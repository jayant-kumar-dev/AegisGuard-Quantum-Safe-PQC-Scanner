"""
AegisGuard — Scan Routes
Core scanning endpoints: single scan, bulk scan, CBOM export, certificate generation.
All scans are saved to the user's history if authenticated.
"""

import io
import asyncio
import time
import logging
import datetime
import concurrent.futures
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Header
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, field_validator

from scanner.pipeline import run_full_scan, build_export_json
from scanner.tls_probe import scan_tls_raw
from scanner.validation import validate_tls_scan
from scanner.pqc_analyzer import analyze_pqc
from scanner.risk_scorer import calculate_risk_score
from scanner.cbom_generator import generate_cbom
from scanner.certificate import generate_pqc_certificate_pdf
from auth.routes import get_current_user
from scan_history.routes import save_scan
from services.report_service import persist_scan_result

logger = logging.getLogger("AegisGuard.Routes")
router = APIRouter(tags=["Scanning"])


# ── Pydantic Models ────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    port: int = 443
    mode: str = "full"

    @field_validator("target")
    @classmethod
    def clean_target(cls, v):
        v = v.strip()
        for pfx in ("https://", "http://"):
            if v.startswith(pfx):
                v = v[len(pfx):]
        v = v.split("/")[0]
        if ":" in v and not v.startswith("["):
            host, mp = v.rsplit(":", 1)
            if mp.isdigit():
                v = host
        if not v:
            raise ValueError("Target cannot be empty")
        return v

    @field_validator("port")
    @classmethod
    def valid_port(cls, v):
        if not 1 <= v <= 65535:
            raise ValueError("Port must be 1-65535")
        return v


class BulkScanRequest(BaseModel):
    targets: List[str]
    port: int = 443
    mode: str = "full"


class CBOMSearchRequest(BaseModel):
    query: str = ""
    targets: List[str] = []


def _scan_bulk_sync(req: BulkScanRequest, authorization: Optional[str]) -> dict:
    results = []
    user = get_current_user(authorization)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exe:
        futures = {
            exe.submit(run_full_scan, t.strip(), req.port, req.mode): t.strip()
            for t in req.targets if t.strip()
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                r = future.result(timeout=30)
                r["target"] = target
                results.append({"target": target, "result": r, **r})
                try:
                    persist_scan_result(target, r, mode=req.mode)
                except Exception as exc:
                    logger.warning("[SCAN] Reporting DB persist failed for %s: %s", target, exc)
                if user:
                    save_scan(user["uid"], r)
            except Exception as e:
                results.append({"target": target, "error": str(e)})

    total = len(results)
    pqc_safe = sum(1 for r in results if not r.get("error") and bool((r.get("result") or r).get("quantum_safe")))
    pqc_vulnerable = max(0, total - pqc_safe)

    return {
        "count": total,
        "total": total,
        "pqc_safe": pqc_safe,
        "pqc_vulnerable": pqc_vulnerable,
        "results": results,
    }


# ── Scan Endpoints ─────────────────────────────────────────────────────────
@router.post("/scan")
async def scan(req: ScanRequest, authorization: Optional[str] = Header(None)):
    """Full PQC scan — saves to history if authenticated."""
    result = await asyncio.to_thread(run_full_scan, req.target, req.port, req.mode)

    try:
        persist_scan_result(req.target, result, mode=req.mode)
    except Exception as exc:
        logger.warning("[SCAN] Reporting DB persist failed for %s: %s", req.target, exc)

    # Save to history if user is logged in
    user = get_current_user(authorization)
    if user:
        save_scan(user["uid"], result)

    return result


@router.post("/export")
async def export_scan(req: ScanRequest, authorization: Optional[str] = Header(None)):
    """Full scan + canonical export JSON."""
    ui = await asyncio.to_thread(run_full_scan, req.target, req.port, req.mode)
    cbom = ui.get("cbom", {})
    export = await asyncio.to_thread(build_export_json, req.target, req.port, ui, cbom)

    user = get_current_user(authorization)
    if user:
        save_scan(user["uid"], ui)

    return export


@router.post("/scan/bulk")
async def scan_bulk(req: BulkScanRequest, authorization: Optional[str] = Header(None)):
    """Concurrent multi-target scan."""
    return await asyncio.to_thread(_scan_bulk_sync, req, authorization)


@router.post("/cbom")
async def export_cbom(req: ScanRequest):
    """Export CBOM as JSON."""
    raw = await asyncio.to_thread(scan_tls_raw, req.target, req.port)
    if raw.get("error") and not raw.get("reachable"):
        raise HTTPException(status_code=502, detail=f"Cannot reach {req.target}:{req.port}")
    validation = await asyncio.to_thread(validate_tls_scan, raw)
    raw = validation["normalized"]
    raw["validation"] = validation
    pqc = await asyncio.to_thread(analyze_pqc, raw)
    risk = await asyncio.to_thread(calculate_risk_score, raw, pqc, validation)
    cbom = await asyncio.to_thread(generate_cbom, req.target, req.port, raw, pqc, risk)
    return cbom


@router.post("/cbom/search")
async def cbom_search(req: CBOMSearchRequest):
    """Search/filter CBOM data across multiple targets."""
    results = []
    for target in (req.targets or []):
        target = target.strip()
        if not target:
            continue
        try:
            raw = await asyncio.to_thread(scan_tls_raw, target, 443, 8)
            if raw.get("reachable"):
                validation = await asyncio.to_thread(validate_tls_scan, raw)
                raw = validation["normalized"]
                raw["validation"] = validation
                pqc = await asyncio.to_thread(analyze_pqc, raw)
                risk = await asyncio.to_thread(calculate_risk_score, raw, pqc, validation)
                cbom = await asyncio.to_thread(generate_cbom, target, 443, raw, pqc, risk)
                if req.query:
                    q = req.query.lower()
                    blob = str(cbom).lower()
                    if q not in blob:
                        continue
                results.append({"target": target, "cbom": cbom, "matched": True})
        except Exception as e:
            results.append({"target": target, "error": str(e)})

    return {"query": req.query, "count": len(results), "results": results}


@router.post("/certificate")
async def generate_certificate(req: ScanRequest):
    """Generate PQC compliance certificate as PDF."""
    raw = await asyncio.to_thread(scan_tls_raw, req.target, req.port)
    if raw.get("error") and not raw.get("reachable"):
        raise HTTPException(status_code=502, detail=f"Cannot reach {req.target}:{req.port}")
    validation = await asyncio.to_thread(validate_tls_scan, raw)
    raw = validation["normalized"]
    raw["validation"] = validation
    pqc = await asyncio.to_thread(analyze_pqc, raw)
    risk = await asyncio.to_thread(calculate_risk_score, raw, pqc, validation)

    pdf_bytes = await asyncio.to_thread(generate_pqc_certificate_pdf, req.target, pqc, risk)
    filename = f"AegisGuard_PQC_Certificate_{req.target}_{datetime.datetime.utcnow().strftime('%Y%m%d')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/scan/test")
async def test_scan():
    """Quick sanity-check — scans example.com."""
    return await asyncio.to_thread(run_full_scan, "example.com", 443, "full")

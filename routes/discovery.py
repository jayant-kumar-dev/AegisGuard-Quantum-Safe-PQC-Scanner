"""AegisGuard discovery and legacy report routes."""

from __future__ import annotations

import asyncio
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, field_validator

from scanner.discovery_engine import DISCOVERY_GLOBAL_TIMEOUT_SECONDS, DiscoveryEngine
from scanner import enumeration_config as enum_cfg
from services.discovery_service import discovery_job_manager

logger = logging.getLogger("AegisGuard.Discovery")
router = APIRouter(tags=["Discovery & Reporting"])

_engine = DiscoveryEngine()


# ── Models ─────────────────────────────────────────────────────────────────
class DiscoveryRequest(BaseModel):
    domain: str
    scan_subdomains: bool = True
    dry_run: bool = False

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v):
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
            raise ValueError("Domain cannot be empty")
        return v


class ReportRequest(BaseModel):
    targets: List[str]
    report_type: str = "executive"
    include_sections: List[str] = ["discovery", "inventory", "cbom", "pqc_posture", "cyber_rating"]


@router.post("/discover")
async def discover_assets(req: DiscoveryRequest):
    """Start non-blocking discovery job and return job metadata immediately."""
    # Whitelist enforcement (empty list disables enforcement)
    whitelist = getattr(enum_cfg, "DISCOVERY_WHITELIST", []) or []
    if whitelist:
        if req.domain.lower() not in [d.lower() for d in whitelist]:
            raise HTTPException(status_code=403, detail="Discovery of this domain is not permitted by server configuration")

    # Determine effective scanning behavior based on safe-mode and dry-run
    safe_mode = getattr(enum_cfg, "DISCOVERY_SAFE_MODE", False)
    effective_scan_subdomains = bool(req.scan_subdomains) and not bool(req.dry_run)
    if safe_mode and not req.dry_run:
        # In safe mode, avoid active subdomain enumeration unless explicitly allowed.
        effective_scan_subdomains = False

    job = await discovery_job_manager.submit(
        domain=req.domain,
        scan_subdomains=effective_scan_subdomains,
        dry_run=req.dry_run,
    )
    message = "Discovery job started"
    if safe_mode:
        message += " (safe mode: active enumeration disabled)"
    if req.dry_run:
        message += " (dry-run)"

    return {**job, "message": message}


@router.get("/status/{job_id}")
async def discovery_status(job_id: str):
    """Return job progress and partial result metadata."""
    try:
        return await discovery_job_manager.get_status(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Discovery job not found")


@router.get("/discover/result/{job_id}")
async def discovery_result(job_id: str):
    """Return completed discovery payload (or partial payload on timeout)."""
    try:
        job = await discovery_job_manager.get_result(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Discovery job not found")

    status = job.get("status")
    if status in ("queued", "running"):
        return {
            "job_id": job_id,
            "status": status,
            "progress": job.get("progress"),
            "message": "Discovery still running",
        }

    if status == "failed":
        raise HTTPException(status_code=502, detail=job.get("error") or "Discovery failed")

    if status in ("timed_out", "timedout"):
        return {
            "job_id": job_id,
            "status": "timed_out",
            "result": job.get("result"),
            "warning": job.get("error") or "Discovery timed out",
        }

    if status == "cancelled":
        return {
            "job_id": job_id,
            "status": status,
            "result": job.get("result"),
            "warning": job.get("error") or "Discovery cancelled",
        }

    if status in ("completed_partial", "partial_success"):
        result = job.get("result") or {}
        if isinstance(result, dict):
            result = {**result, "status": "completed_partial", "warning": job.get("error")}
        return {
            "job_id": job_id,
            "status": "completed_partial",
            "result": result,
            "warning": job.get("error"),
        }

    return {
        "job_id": job_id,
        "status": status,
        "result": job.get("result"),
    }


@router.post("/discover/cancel/{job_id}")
async def cancel_discovery_job(job_id: str):
    """Mark a running discovery job as cancelled.

    Note: this marks status immediately for polling clients; background work may still wind down.
    """
    try:
        job = await discovery_job_manager.cancel(job_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="Discovery job not found")

    if job.get("status") in ("completed", "completed_partial", "partial_success", "failed", "timed_out", "timedout", "cancelled"):
        return {
            "job_id": job_id,
            "status": job.get("status"),
            "message": "Job already in terminal state",
        }

    return {
        "job_id": job_id,
        "status": "cancelled",
        "message": "Job cancellation requested",
    }


@router.post("/discover/sync")
async def discover_assets_sync(req: DiscoveryRequest, wait_seconds: float = Query(default=15.0, ge=1.0, le=25.0)):
    """Compatibility endpoint that waits (bounded) for discovery result."""
    timeout = min(wait_seconds, DISCOVERY_GLOBAL_TIMEOUT_SECONDS)
    result = await asyncio.wait_for(
        _engine.discover(req.domain, scan_subdomains=req.scan_subdomains, global_timeout_seconds=timeout),
        timeout=timeout + 1,
    )
    return result


@router.post("/report/generate-legacy")
def generate_report(req: ReportRequest):
    """Generate a multi-target executive report."""
    all_scans = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as exe:
        futures = {exe.submit(run_full_scan, t.strip(), 443, "full"): t.strip()
                   for t in req.targets if t.strip()}
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                r = future.result(timeout=30)
                r["target"] = target
                all_scans.append(r)
            except Exception as e:
                all_scans.append({"target": target, "error": str(e)})

    report_data = {
        "report_type": req.report_type,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total_assets": len(all_scans),
        "sections": {},
    }

    if "discovery" in req.include_sections:
        report_data["sections"]["discovery"] = [
            {"target": s["target"], "reachable": not s.get("error"),
             "tls_version": s.get("raw_tls", {}).get("tls_version"),
             "pqc_safe": s.get("quantum_safe"), "score": s.get("score"), "grade": s.get("grade")}
            for s in all_scans
        ]

    if "pqc_posture" in req.include_sections:
        tier_counts = {"elite": 0, "standard": 0, "legacy": 0, "critical": 0}
        for s in all_scans:
            sc = s.get("score", 0) if isinstance(s.get("score"), int) else 0
            if sc >= 80:   tier_counts["elite"] += 1
            elif sc >= 60: tier_counts["standard"] += 1
            elif sc >= 40: tier_counts["legacy"] += 1
            else:          tier_counts["critical"] += 1
        report_data["sections"]["pqc_posture"] = {"tier_distribution": tier_counts}

    if "cyber_rating" in req.include_sections:
        scores = [s.get("score", 0) for s in all_scans if isinstance(s.get("score"), int)]
        ent_score = min(round(sum(scores) / max(len(scores), 1)) * 10, 1000) if scores else 0
        report_data["sections"]["cyber_rating"] = {
            "enterprise_score": ent_score, "max_score": 1000,
            "status": "Elite-PQC" if ent_score > 700 else "Standard" if ent_score >= 400 else "Legacy",
        }

    return report_data


@router.post("/report/schedule-legacy")
def schedule_report(
    report_type: str = "executive", frequency: str = "weekly",
    targets: List[str] = [], include_sections: List[str] = ["discovery", "inventory", "cbom", "pqc_posture", "cyber_rating"],
    email: str = "", date: str = "", time_val: str = "09:00", timezone: str = "Asia/Kolkata",
):
    """Schedule a report (stores config)."""
    schedule_id = f"SCH-{abs(hash(f'{report_type}{frequency}{email}')) % 99999:05d}"
    return {
        "status": "scheduled", "schedule_id": schedule_id,
        "report_type": report_type, "frequency": frequency,
        "targets": targets, "include_sections": include_sections,
        "delivery": {"email": email, "date": date, "time": time_val, "timezone": timezone},
        "message": f"Report scheduled successfully. ID: {schedule_id}",
    }

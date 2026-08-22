"""
AegisGuard — Reporting Service
Executive aggregation, score calculation, persistence, and report exports.
"""

from __future__ import annotations

import io
import json
import math
import logging
import datetime
import concurrent.futures
from statistics import mean
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from database import get_db, init_db
from scanner.pipeline import run_full_scan

logger = logging.getLogger("AegisGuard.Reporting")


def _utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _sanitize_floats(obj: Any) -> Any:
    """Recursively replace NaN/Infinity floats with None so the JSON response stays valid."""
    if isinstance(obj, float):
        return None if (math.isnan(obj) or math.isinf(obj)) else obj
    if isinstance(obj, dict):
        return {k: _sanitize_floats(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_floats(v) for v in obj]
    return obj


def _normalize_domains(domains: List[str]) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    for item in domains or []:
        d = (item or "").strip().lower()
        if not d:
            continue
        for pfx in ("https://", "http://"):
            if d.startswith(pfx):
                d = d[len(pfx):]
        d = d.split("/")[0]
        if not d or d in seen:
            continue
        seen.add(d)
        cleaned.append(d)
    return cleaned


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _normalize_scan_result(result: Dict[str, Any], target_fallback: str = "") -> Dict[str, Any]:
    target = (result.get("target") or target_fallback or "").strip().lower()
    score = _safe_int(result.get("score"), 0)
    grade = result.get("grade") or "F"
    quantum_safe = bool(result.get("quantum_safe", result.get("pqc_safe", False)))
    reachable = bool(result.get("reachable", True))
    timestamp = result.get("timestamp") or _utc_now_iso()

    pqc_status_raw = str(result.get("pqc_status") or "").strip().upper()
    pqc_status = pqc_status_raw if pqc_status_raw in ("SAFE", "VULN") else ("SAFE" if quantum_safe else "VULN")

    vuln_pct = _safe_int(result.get("vuln_pct", result.get("vulnerability_pct", 0)), 0)
    pqc_pct = _safe_int(result.get("pqc_pct", result.get("pqc_readiness_pct", 0)), 0)

    normalized = dict(result)
    normalized.update(
        {
            "target": target,
            "score": score,
            "grade": grade,
            "reachable": reachable,
            "timestamp": timestamp,
            "quantum_safe": quantum_safe,
            "pqc_status": pqc_status,
            "vuln_pct": vuln_pct,
            "vulnerability_pct": vuln_pct,
            "pqc_pct": pqc_pct,
            "pqc_readiness_pct": pqc_pct,
        }
    )
    return normalized


def _build_metric_summary(aggregation: Dict[str, Any]) -> Dict[str, Any]:
    asset = aggregation.get("asset_summary") or {}
    tls = aggregation.get("tls_security_metrics") or {}
    pqc = aggregation.get("pqc_readiness") or {}
    return {
        "total_assets": _safe_int(asset.get("total_assets"), 0),
        "reachable": _safe_int(asset.get("reachable_assets"), 0),
        "pqc_safe": _safe_int(pqc.get("ready_count"), 0),
        "pqc_vulnerable": _safe_int(pqc.get("not_ready_count"), 0),
        "avg_score": round(_safe_float(tls.get("avg_score"), 0.0), 2),
        "pqc_coverage": round(_safe_float(pqc.get("coverage_pct"), 0.0), 2),
    }


def _run_domain_scan(domain: str) -> Dict[str, Any]:
    started = datetime.datetime.utcnow()
    try:
        result = _normalize_scan_result(run_full_scan(domain, 443, "full"), target_fallback=domain)
        return {
            "target": domain,
            "ok": True,
            "result": result,
            "subdomains_discovered": 0,
            "scan_duration_ms": int((datetime.datetime.utcnow() - started).total_seconds() * 1000),
        }
    except Exception as exc:
        logger.warning("[REPORT] Scan failed for %s: %s", domain, exc)
        return {
            "target": domain,
            "ok": False,
            "error": str(exc),
            "scan_duration_ms": int((datetime.datetime.utcnow() - started).total_seconds() * 1000),
        }


def aggregate_results(scan_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    successes = [s for s in scan_data if s.get("ok") and isinstance(s.get("result"), dict)]
    failures = [s for s in scan_data if not s.get("ok")]

    if not successes:
        raise HTTPException(status_code=400, detail="Cannot generate report without successful scan data.")

    result_rows = [_normalize_scan_result(s["result"], target_fallback=s.get("target", "")) for s in successes]
    scores = [_safe_int(r.get("score"), 0) for r in result_rows]
    vuln_pcts = [_safe_int(r.get("vuln_pct"), 0) for r in result_rows]
    pqc_pcts = [_safe_int(r.get("pqc_pct"), 0) for r in result_rows]

    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    cert_health = {"healthy": 0, "expiring_30d": 0, "expired": 0, "self_signed": 0}

    for row in result_rows:
        risk_distribution["critical"] += len(row.get("critical_findings") or [])
        risk_distribution["high"] += len(row.get("high_findings") or [])
        risk_distribution["medium"] += len(row.get("medium_findings") or [])
        risk_distribution["low"] += len(row.get("low_findings") or []) + len(row.get("info_findings") or [])

        probe = row.get("probe") or {}
        if probe.get("cert_expired"):
            cert_health["expired"] += 1
        elif _safe_int(probe.get("cert_days_left"), 9999) <= 30:
            cert_health["expiring_30d"] += 1
        else:
            cert_health["healthy"] += 1

        if probe.get("cert_self_signed"):
            cert_health["self_signed"] += 1

    reachable = sum(1 for r in result_rows if bool(r.get("reachable", True)))
    total = len(scan_data)
    pqc_ready = sum(1 for r in result_rows if (r.get("pqc_status") == "SAFE"))
    pqc_not_ready = max(0, total - pqc_ready)

    aggregation = {
        "asset_summary": {
            "total_assets": total,
            "reachable_assets": reachable,
            "unreachable_assets": len(failures),
            "subdomains_discovered": sum(_safe_int(s.get("subdomains_discovered"), 0) for s in scan_data),
            "scan_failures": [{"target": f.get("target"), "error": f.get("error")} for f in failures],
        },
        "tls_security_metrics": {
            "avg_score": round(mean(scores), 2),
            "min_score": min(scores),
            "max_score": max(scores),
            "avg_vulnerability_pct": round(mean(vuln_pcts), 2),
            "avg_vuln_pct": round(mean(vuln_pcts), 2),
            "vulnerability_pct": round(mean(vuln_pcts), 2),
            "vuln_pct": round(mean(vuln_pcts), 2),
        },
        "pqc_readiness": {
            "coverage_pct": round((pqc_ready / max(total, 1)) * 100, 2),
            "avg_readiness_pct": round(mean(pqc_pcts), 2),
            "avg_pqc_pct": round(mean(pqc_pcts), 2),
            "ready_count": pqc_ready,
            "not_ready_count": pqc_not_ready,
        },
        "certificate_health": cert_health,
        "risk_distribution": risk_distribution,
        "raw_scan_results": scan_data,
    }

    return aggregation


def calculate_scores(aggregation: Dict[str, Any]) -> Dict[str, Any]:
    tls = aggregation.get("tls_security_metrics", {})
    pqc = aggregation.get("pqc_readiness", {})
    cert = aggregation.get("certificate_health", {})
    risk = aggregation.get("risk_distribution", {})

    avg_score = float(tls.get("avg_score", 0))
    pqc_cov = float(pqc.get("coverage_pct", 0))
    vuln_pct = float(tls.get("avg_vulnerability_pct", tls.get("vulnerability_pct", 0)))

    cert_penalty = (cert.get("expired", 0) * 40) + (cert.get("expiring_30d", 0) * 15) + (cert.get("self_signed", 0) * 10)
    risk_penalty = (risk.get("critical", 0) * 8) + (risk.get("high", 0) * 4) + (risk.get("medium", 0) * 2)

    normalized = max(0.0, min(100.0, (avg_score * 0.55) + (pqc_cov * 0.25) + ((100 - vuln_pct) * 0.20)))
    normalized = max(0.0, normalized - min(40.0, (cert_penalty * 0.1 + risk_penalty * 0.05)))

    final_score_1000 = int(round(normalized * 10))
    if final_score_1000 >= 900:
        grade = "A+"
    elif final_score_1000 >= 800:
        grade = "A"
    elif final_score_1000 >= 700:
        grade = "B"
    elif final_score_1000 >= 600:
        grade = "C"
    elif final_score_1000 >= 400:
        grade = "D"
    else:
        grade = "F"

    return {
        "normalized_score_100": round(normalized, 2),
        "final_score": final_score_1000,
        "grade": grade,
        "scoring_formula": {
            "base": "normalized = (avg_score*0.55) + (pqc_coverage*0.25) + ((100-vulnerability_pct)*0.20)",
            "penalty": "normalized -= min(40, cert_penalty*0.1 + risk_penalty*0.05)",
            "final": "final_score = round(normalized * 10)",
        },
    }


def _ai_summary(aggregation: Dict[str, Any], scoring: Dict[str, Any]) -> Dict[str, Any]:
    tls = aggregation.get("tls_security_metrics", {})
    pqc = aggregation.get("pqc_readiness", {})
    risk = aggregation.get("risk_distribution", {})
    cert = aggregation.get("certificate_health", {})

    grade = scoring.get("grade", "F")
    avg = tls.get("avg_score", 0)
    pqc_cov = pqc.get("coverage_pct", 0)

    reasons: List[str] = []
    if avg < 70:
        reasons.append("weak average TLS posture")
    if pqc_cov < 50:
        reasons.append("limited PQC readiness")
    if risk.get("critical", 0) > 0:
        reasons.append("critical findings present")
    if cert.get("expired", 0) > 0:
        reasons.append("expired certificates detected")

    if not reasons:
        reasons.append("strong security baseline with no major blockers")

    severity = "Critical" if grade in ("F", "D") else "High" if grade == "C" else "Medium" if grade == "B" else "Low"

    summary = (
        f"Portfolio security posture is {severity.lower()} with grade {grade}. "
        f"Key drivers: {', '.join(reasons)}."
    )

    recommendations = []
    if pqc_cov < 70:
        recommendations.append("Prioritize ML-KEM/ML-DSA deployment for non-PQC assets.")
    if tls.get("avg_vulnerability_pct", 0) > 30:
        recommendations.append("Harden TLS policies and remove legacy protocol/cipher support.")
    if cert.get("expiring_30d", 0) > 0 or cert.get("expired", 0) > 0:
        recommendations.append("Enforce automated certificate lifecycle management.")
    if risk.get("critical", 0) > 0:
        recommendations.append("Triage and remediate critical findings immediately.")

    if not recommendations:
        recommendations.append("Maintain current controls and schedule continuous monitoring.")

    return {
        "summary": summary,
        "severity": severity,
        "risk_prediction": {
            "next_30_days": "high" if severity in ("Critical", "High") else "moderate" if severity == "Medium" else "low"
        },
        "priority_recommendations": recommendations[:5],
    }


def _persist_scan_records(scan_data: List[Dict[str, Any]]) -> None:
    init_db()
    conn = get_db()
    inserted = 0
    try:
        for item in scan_data:
            if not item.get("ok"):
                continue
            res = _normalize_scan_result(item.get("result") or {}, target_fallback=item.get("target", ""))
            conn.execute(
                """
                INSERT INTO scans
                (target, port, mode, score, grade, pqc_safe, vulnerability_pct, pqc_readiness_pct, confidence, scan_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    res.get("target") or item.get("target", ""),
                    _safe_int((res.get("raw_tls") or {}).get("port"), 443),
                    "full",
                    _safe_int(res.get("score"), 0),
                    res.get("grade", ""),
                    1 if res.get("pqc_status") == "SAFE" else 0,
                    _safe_int(res.get("vuln_pct"), 0),
                    _safe_int(res.get("pqc_pct"), 0),
                    float(res.get("confidence", 0.0) or 0.0),
                    json.dumps(res, default=str),
                ),
            )
            inserted += 1
        conn.commit()
        logger.info("[REPORT][DB] Persisted %s scan record(s) into scans table", inserted)
    except Exception:
        conn.rollback()
        logger.exception("[REPORT][DB] Failed to persist scan records; transaction rolled back")
        raise
    finally:
        conn.close()


def persist_scan_result(target: str, result: Dict[str, Any], mode: str = "full") -> None:
    """Persist a single scan result into reporting scan history without interrupting scan API flow."""
    normalized = _normalize_scan_result(result or {}, target_fallback=target)
    _persist_scan_records(
        [
            {
                "target": target,
                "ok": bool(normalized.get("reachable", True)),
                "result": normalized,
                "mode": mode,
            }
        ]
    )


def _persist_report(report_type: str, domains: List[str], payload: Dict[str, Any], generated_by: str = "system") -> int:
    init_db()
    conn = get_db()
    try:
        cur = conn.execute(
            """
            INSERT INTO reports (report_type, generated_by, domains_json, final_score, grade, report_data)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                report_type,
                generated_by,
                json.dumps(domains),
                _safe_int((payload.get("final_score") or {}).get("final_score"), 0),
                (payload.get("final_score") or {}).get("grade", "F"),
                json.dumps(payload, default=str),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_report_history(limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    init_db()
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT id, report_type, generated_by, domains_json, final_score, grade, created_at
            FROM reports
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS cnt FROM reports").fetchone()["cnt"]
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "reports": [
                {
                    "id": r["id"],
                    "report_type": r["report_type"],
                    "generated_by": r["generated_by"],
                    "domains": json.loads(r["domains_json"] or "[]"),
                    "final_score": r["final_score"],
                    "grade": r["grade"],
                    "created_at": r["created_at"],
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def get_scan_history(limit: int = 100, offset: int = 0) -> Dict[str, Any]:
    init_db()
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT id, target, port, score, grade, pqc_safe, vulnerability_pct, pqc_readiness_pct, confidence, created_at
            FROM scans
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
        total = conn.execute("SELECT COUNT(*) AS cnt FROM scans").fetchone()["cnt"]
        logger.info("[REPORT][DB] Loaded %s scan record(s) (limit=%s, offset=%s, total=%s)", len(rows), limit, offset, total)
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "scans": [
                {
                    "id": r["id"],
                    "target": r["target"],
                    "port": r["port"],
                    "score": r["score"],
                    "grade": r["grade"],
                    "pqc_safe": bool(r["pqc_safe"]),
                    "pqc_status": "SAFE" if bool(r["pqc_safe"]) else "VULN",
                    "reachable": True,
                    "vulnerability_pct": r["vulnerability_pct"],
                    "vuln_pct": r["vulnerability_pct"],
                    "pqc_readiness_pct": r["pqc_readiness_pct"],
                    "pqc_pct": r["pqc_readiness_pct"],
                    "confidence": r["confidence"],
                    "created_at": r["created_at"],
                    "timestamp": r["created_at"],
                }
                for r in rows
            ],
        }
    finally:
        conn.close()


def get_report_by_id(report_id: int) -> Dict[str, Any]:
    init_db()
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        return {
            "id": row["id"],
            "report_type": row["report_type"],
            "generated_by": row["generated_by"],
            "domains": json.loads(row["domains_json"] or "[]"),
            "final_score": row["final_score"],
            "grade": row["grade"],
            "created_at": row["created_at"],
            "report": json.loads(row["report_data"] or "{}"),
        }
    finally:
        conn.close()


def generate_executive_report(domains: List[str], generated_by: str = "system") -> Dict[str, Any]:
    targets = _normalize_domains(domains)
    if not targets:
        raise HTTPException(status_code=400, detail="At least one domain is required")

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(2, len(targets)))) as exe:
        futures = [exe.submit(_run_domain_scan, d) for d in targets]
        scan_data = [f.result() for f in concurrent.futures.as_completed(futures)]

    aggregation = aggregate_results(scan_data)
    scoring = calculate_scores(aggregation)
    ai = _ai_summary(aggregation, scoring)
    metrics = _build_metric_summary(aggregation)

    report = {
        "report_type": "executive",
        "generated_at": _utc_now_iso(),
        "domains": targets,
        "asset_summary": aggregation["asset_summary"],
        "tls_security_metrics": aggregation["tls_security_metrics"],
        "pqc_readiness": aggregation["pqc_readiness"],
        "certificate_health": aggregation["certificate_health"],
        "risk_distribution": aggregation["risk_distribution"],
        "final_score": scoring,
        "ai_summary": ai,
        "dashboard": {
            "cards": {
                "total_assets": metrics["total_assets"],
                "reachable_assets": metrics["reachable"],
                "pqc_safe": metrics["pqc_safe"],
                "pqc_vulnerable": metrics["pqc_vulnerable"],
                "avg_score": metrics["avg_score"],
                "pqc_coverage_pct": metrics["pqc_coverage"],
                "vulnerability_pct": aggregation["tls_security_metrics"]["vulnerability_pct"],
                "final_score": scoring["final_score"],
                "grade": scoring["grade"],
            },
            "charts": {
                "risk_distribution": aggregation["risk_distribution"],
                "pqc_ready_split": {
                    "ready": aggregation["pqc_readiness"]["ready_count"],
                    "not_ready": aggregation["pqc_readiness"]["not_ready_count"],
                },
                "score_range": {
                    "min": aggregation["tls_security_metrics"]["min_score"],
                    "avg": aggregation["tls_security_metrics"]["avg_score"],
                    "max": aggregation["tls_security_metrics"]["max_score"],
                },
            },
        },
        "scans": scan_data,
        "metrics": metrics,
        # Legacy-friendly top-level metric aliases for /report/generate compatibility.
        "total_assets": metrics["total_assets"],
        "reachable": metrics["reachable"],
        "pqc_safe": metrics["pqc_safe"],
        "pqc_vulnerable": metrics["pqc_vulnerable"],
        "avg_score": metrics["avg_score"],
        "pqc_coverage": metrics["pqc_coverage"],
        "consistency_checks": {
            "pqc_pct_matches_counts": round((aggregation["pqc_readiness"]["ready_count"] / max(aggregation["asset_summary"]["total_assets"], 1)) * 100, 2) == aggregation["pqc_readiness"]["coverage_pct"],
            "vulnerability_pct_source": "mean(scan.vuln_pct)",
            "score_source": "weighted aggregation formula",
            "confidence_score": round(
                max(
                    0.0,
                    min(
                        1.0,
                        0.6
                        + (0.2 if metrics["total_assets"] > 0 else -0.2)
                        + (0.2 if metrics["reachable"] > 0 else -0.2)
                        - (0.15 if aggregation["asset_summary"]["scan_failures"] else 0.0),
                    ),
                ),
                2,
            ),
        },
    }

    report = _sanitize_floats(report)
    _persist_scan_records(scan_data)
    report_id = _persist_report("executive", targets, report, generated_by=generated_by)
    report["report_id"] = report_id
    return report


def generate_on_demand_report(domains: List[str], scan_ids: Optional[List[int]] = None, generated_by: str = "system") -> Dict[str, Any]:
    scan_ids = scan_ids or []
    selected_rows: List[Dict[str, Any]] = []

    if scan_ids:
        conn = get_db()
        try:
            q_marks = ",".join(["?"] * len(scan_ids))
            rows = conn.execute(f"SELECT id, target, scan_data, created_at FROM scans WHERE id IN ({q_marks})", tuple(scan_ids)).fetchall()
            for row in rows:
                selected_rows.append(
                    {
                        "scan_id": row["id"],
                        "target": row["target"],
                        "created_at": row["created_at"],
                        "result": json.loads(row["scan_data"] or "{}"),
                    }
                )
        finally:
            conn.close()

    generated: List[Dict[str, Any]] = []
    if domains:
        targets = _normalize_domains(domains)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, max(2, len(targets)))) as exe:
            futures = [exe.submit(_run_domain_scan, d) for d in targets]
            generated = [f.result() for f in concurrent.futures.as_completed(futures)]

    normalized_existing = [
        {"target": row["target"], "ok": True, "result": row["result"], "scan_id": row["scan_id"], "created_at": row["created_at"]}
        for row in selected_rows
        if row.get("result")
    ]

    combined = normalized_existing + generated
    if not combined:
        raise HTTPException(status_code=400, detail="No scan data selected for on-demand report")

    aggregation = aggregate_results(combined)
    scoring = calculate_scores(aggregation)
    ai = _ai_summary(aggregation, scoring)
    metrics = _build_metric_summary(aggregation)

    report = {
        "report_type": "on_demand",
        "generated_at": _utc_now_iso(),
        "domains": _normalize_domains(domains),
        "selected_scan_ids": scan_ids,
        "comparison": {
            "scan_count": len(combined),
            "targets": [c.get("target") for c in combined],
            "score_series": [
                {
                    "target": c.get("target"),
                    "score": _safe_int((c.get("result") or {}).get("score"), 0),
                    "grade": (c.get("result") or {}).get("grade", "F"),
                    "created_at": c.get("created_at"),
                }
                for c in combined
            ],
        },
        "asset_summary": aggregation["asset_summary"],
        "tls_security_metrics": aggregation["tls_security_metrics"],
        "pqc_readiness": aggregation["pqc_readiness"],
        "certificate_health": aggregation["certificate_health"],
        "risk_distribution": aggregation["risk_distribution"],
        "final_score": scoring,
        "ai_summary": ai,
        "scans": combined,
        "metrics": metrics,
        "total_assets": metrics["total_assets"],
        "reachable": metrics["reachable"],
        "pqc_safe": metrics["pqc_safe"],
        "pqc_vulnerable": metrics["pqc_vulnerable"],
        "avg_score": metrics["avg_score"],
        "pqc_coverage": metrics["pqc_coverage"],
    }

    report = _sanitize_floats(report)
    report_id = _persist_report("on_demand", report.get("domains") or [], report, generated_by=generated_by)
    report["report_id"] = report_id
    if generated:
        _persist_scan_records(generated)
    return report


def generate_report_pdf_bytes(report: Dict[str, Any]) -> bytes:
    try:
        from fpdf import FPDF  # type: ignore
    except Exception as exc:
        raise HTTPException(status_code=500, detail="PDF dependency unavailable. Install fpdf2.") from exc

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=12)
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "AegisGuard Executive Report", ln=1)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Generated: {report.get('generated_at', _utc_now_iso())}", ln=1)
    pdf.cell(0, 6, f"Type: {report.get('report_type', 'executive')}", ln=1)
    pdf.ln(2)

    final_score = report.get("final_score") or {}
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 7, f"Final Score: {final_score.get('final_score', 0)}/1000 ({final_score.get('grade', 'F')})", ln=1)

    asset = report.get("asset_summary") or {}
    tls = report.get("tls_security_metrics") or {}
    pqc = report.get("pqc_readiness") or {}

    pdf.set_font("Helvetica", "", 10)
    lines = [
        f"Assets: total={asset.get('total_assets', 0)}, reachable={asset.get('reachable_assets', 0)}, subdomains={asset.get('subdomains_discovered', 0)}",
        f"TLS: avg={tls.get('avg_score', 0)}, min={tls.get('min_score', 0)}, max={tls.get('max_score', 0)}, vuln%={tls.get('vulnerability_pct', 0)}",
        f"PQC: coverage={pqc.get('coverage_pct', 0)}%, ready={pqc.get('ready_count', 0)}, not_ready={pqc.get('not_ready_count', 0)}",
        "",
        f"AI Summary: {(report.get('ai_summary') or {}).get('summary', 'N/A')}",
    ]
    for line in lines:
        safe_line = (line or "").encode("ascii", errors="replace").decode("ascii")
        if not safe_line:
            pdf.ln(4)
            continue
        try:
            pdf.multi_cell(0, 6, safe_line)
        except Exception:
            # Fallback wrapping for rare long-token edge cases.
            chunks = [safe_line[i:i + 90] for i in range(0, len(safe_line), 90)]
            for chunk in chunks:
                pdf.cell(0, 6, chunk, ln=1)

    out = pdf.output(dest="S")
    if isinstance(out, (bytes, bytearray)):
        return bytes(out)
    return out.encode("latin1")

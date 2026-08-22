"""
AegisGuard — Research Exporters
Assembles a flattened, research-grade audit record for a single scanned
endpoint and exports a batch of them to a strict-schema CSV, plus a
CycloneDX 1.6 CBOM. Built for the ~100 legitimate enterprise banking HTTPS
endpoint study.

Does not replace scanner/pipeline.py's rich UI response — it consumes the
same raw/pqc/risk objects the pipeline already produces and reshapes them
into the flat, reproducible schema needed for academic export.
"""

from __future__ import annotations

import csv
import datetime
from typing import Iterable, List, Optional

try:
    from .pqc_analyzer import analyze_pqc
    from .risk_scorer import calculate_risk_score
    from .cbom_generator import generate_cbom
except Exception:
    from scanner.pqc_analyzer import analyze_pqc
    from scanner.risk_scorer import calculate_risk_score
    from scanner.cbom_generator import generate_cbom

# Exact column order — REQUIREMENT 8. Do not add/reorder columns here.
CSV_COLUMNS = [
    "id", "bank_name", "country", "domain", "port", "ip", "reachable",
    "tls_version", "cipher_suite", "key_exchange_group", "key_exchange_class",
    "pqc_status", "pqc_key_exchange", "pqc_signature", "is_hybrid",
    "pqc_confidence", "certificate_subject", "certificate_issuer",
    "certificate_signature_algorithm", "certificate_public_key_algorithm",
    "certificate_public_key_size", "certificate_not_after",
    "certificate_days_remaining", "certificate_expired",
    "certificate_self_signed", "certificate_sha256", "hsts", "risk_score",
    "risk_grade", "findings", "recommendation", "scan_timestamp",
]


def build_audit_record(
    target: str,
    port: int,
    raw: dict,
    record_id: Optional[int] = None,
    bank_name: str = "",
    country: str = "",
) -> dict:
    """Assemble one flat, 32-column-ready audit record for a scanned target.

    Args:
        target: hostname/domain scanned.
        port: TCP port scanned.
        raw: the dict returned by scanner.tls_probe.scan_tls_raw() (ideally
            after scanner.validation.validate_tls_scan() cross-checking).
        record_id: optional sequential id for the batch (1..100).
        bank_name: optional institution label for the research dataset.
        country: optional country label for the research dataset.

    Returns:
        A dict with internal fields plus the exact 32 research fields.
        Extra internal fields (e.g. nested cbom) may be present but
        export_audit_csv() only ever emits CSV_COLUMNS.
    """
    reachable = bool(raw.get("reachable", False))

    if not reachable:
        # REQUIREMENT 11: never crash or fabricate values for a failed scan.
        pqc = {
            "pqc_status": "NOT_VERIFIED", "pqc_safe": False, "is_hybrid": False,
            "pqc_confidence": "UNKNOWN", "pqc_key_exchange": "Unknown",
            "pqc_signature": "Unknown", "evidence": raw.get("error") or "Target unreachable.",
            "safe_components": [], "vulnerable_components": [],
        }
        risk = {"score": 0, "grade": "F", "penalties": [
            f"🔴 CRITICAL — Endpoint unreachable: {raw.get('error') or 'unknown error'}"
        ]}
    else:
        pqc = analyze_pqc(raw)
        risk = calculate_risk_score(raw, pqc)

    findings = "; ".join(risk.get("penalties", [])) or "None"
    recommendation = _build_recommendation(pqc, raw)

    return {
        "id": record_id if record_id is not None else "",
        "bank_name": bank_name,
        "country": country,
        "domain": target,
        "port": port,
        "ip": raw.get("ip") or "",
        "reachable": reachable,
        "tls_version": raw.get("tls_version") or "Unknown",
        "cipher_suite": raw.get("cipher_suite") or "",
        "key_exchange_group": raw.get("kex_algorithm") or "Unknown",
        "key_exchange_class": pqc.get("pqc_status", "NOT_VERIFIED"),
        "pqc_status": pqc.get("pqc_status", "NOT_VERIFIED"),
        "pqc_key_exchange": pqc.get("pqc_key_exchange", "Unknown"),
        "pqc_signature": pqc.get("pqc_signature", "Unknown"),
        "is_hybrid": bool(pqc.get("is_hybrid", False)),
        "pqc_confidence": pqc.get("pqc_confidence", "UNKNOWN"),
        "certificate_subject": raw.get("cert_subject") or "",
        "certificate_issuer": raw.get("cert_issuer") or "",
        "certificate_signature_algorithm": raw.get("cert_sig_alg") or "",
        "certificate_public_key_algorithm": raw.get("cert_pubkey_alg") or "",
        "certificate_public_key_size": raw.get("cert_pubkey_bits") or "",
        "certificate_not_after": raw.get("cert_not_after") or "",
        "certificate_days_remaining": raw.get("cert_days_left") if raw.get("cert_days_left") is not None else "",
        "certificate_expired": bool(raw.get("cert_expired", False)),
        "certificate_self_signed": bool(raw.get("cert_self_signed", False)),
        "certificate_sha256": raw.get("cert_sha256") or "",
        "hsts": bool(raw.get("hsts", False)),
        "risk_score": risk.get("score", 0),
        "risk_grade": risk.get("grade", "F"),
        "findings": findings,
        "recommendation": recommendation,
        "scan_timestamp": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        # Internal-only, not exported to CSV (REQUIREMENT 8's "extra fields
        # may exist internally but must not appear in the CSV"):
        "_pqc_evidence": pqc.get("evidence", ""),
        "_raw": raw,
        "_pqc": pqc,
        "_risk": risk,
    }


def _build_recommendation(pqc: dict, raw: dict) -> str:
    status = pqc.get("pqc_status", "NOT_VERIFIED")
    if status == "NOT_VERIFIED":
        return "Re-run verification with OpenSSL CLI available; PQC posture cannot be assessed from this scan alone."
    if status == "CLASSICAL":
        return f"Migrate key exchange to a hybrid or pure PQC KEM (e.g. X25519MLKEM768 or ML-KEM-768); currently using {pqc.get('pqc_key_exchange')}."
    if status == "HYBRID_PQC":
        return "Hybrid PQC in place; monitor for full PQC KEM rollout once ecosystem support matures."
    return "PQC key exchange verified; no key-exchange migration action required."


def export_audit_csv(records: Iterable[dict], filename: str) -> str:
    """Write a batch of audit records to a strict 32-column research CSV.

    Args:
        records: iterable of dicts, each produced by build_audit_record()
            (or any dict containing at least the CSV_COLUMNS keys).
        filename: output path.

    Returns:
        The filename written to.

    Missing values are written as an empty string, except fields whose
    research schema requires an explicit "Unknown" (key_exchange_group,
    key_exchange_class, pqc_status, pqc_key_exchange, pqc_signature,
    pqc_confidence), which default to "Unknown" / "NOT_VERIFIED" /
    "UNKNOWN" respectively rather than being left blank.
    """
    explicit_unknown_defaults = {
        "key_exchange_group": "Unknown",
        "key_exchange_class": "NOT_VERIFIED",
        "pqc_status": "NOT_VERIFIED",
        "pqc_key_exchange": "Unknown",
        "pqc_signature": "Unknown",
        "pqc_confidence": "UNKNOWN",
    }

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = {}
            for col in CSV_COLUMNS:
                val = rec.get(col, "")
                if val in (None, "") and col in explicit_unknown_defaults:
                    val = explicit_unknown_defaults[col]
                elif isinstance(val, bool):
                    val = str(val)
                row[col] = val
            writer.writerow(row)
    return filename


def run_batch_scan_and_export(
    targets: List[dict],
    csv_filename: str,
    scan_fn=None,
    timeout: int = 10,
) -> List[dict]:
    """Scan a list of {"domain", "port", "bank_name", "country"} targets and
    export the results to CSV. One failing endpoint never aborts the batch
    (REQUIREMENT 11).

    Args:
        targets: list of dicts with keys domain (required), port (default
            443), bank_name (optional), country (optional).
        csv_filename: output CSV path.
        scan_fn: injectable scan function with signature
            (host, port, timeout) -> raw dict; defaults to
            scanner.tls_probe.scan_tls_raw.
        timeout: per-target timeout in seconds.

    Returns:
        List of assembled audit records (including internal-only fields;
        the CSV export itself only writes the 32 public columns).
    """
    if scan_fn is None:
        try:
            from .tls_probe import scan_tls_raw as scan_fn
        except Exception:
            from scanner.tls_probe import scan_tls_raw as scan_fn

    records = []
    for idx, t in enumerate(targets, start=1):
        domain = t.get("domain", "")
        port = int(t.get("port", 443) or 443)
        try:
            raw = scan_fn(domain, port, timeout)
        except Exception as e:
            raw = {"host": domain, "port": port, "reachable": False, "error": str(e), "ip": None}
        rec = build_audit_record(
            domain, port, raw,
            record_id=idx, bank_name=t.get("bank_name", ""), country=t.get("country", ""),
        )
        records.append(rec)

    export_audit_csv(records, csv_filename)
    return records

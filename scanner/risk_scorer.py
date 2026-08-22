"""
AegisGuard — Risk Scorer
Weighted risk scoring with validation-aware confidence, factor breakdowns,
and direct backend metrics for the dashboard.
"""

from __future__ import annotations

from typing import List, Optional

from config import DEPRECATED_CIPHERS
from .intelligence import detect_cves
from .pqc_analyzer import is_pqc_sig


SCORING_WEIGHTS = {
    "tls_version": {"TLSv1": 24, "TLSv1.1": 18, "TLSv1.2": 8, "TLSv1.3": 0},
    "cipher_strength": {"deprecated": 20, "cbc": 8, "aead": 0},
    "key_exchange": {"RSA": 18, "DH": 14, "DHE": 12, "ECDH": 9, "ECDHE": 6, "PQC": 0, "HYBRID": 0},
    "certificate": {"expired": 20, "expiring_soon": 12, "self_signed": 8, "sha1": 15, "md5": 25, "weak_bits": 12},
    "hsts_missing": 5,
    "vulnerability_severity": {"CRITICAL": 18, "HIGH": 12, "MEDIUM": 7, "LOW": 3},
    "pqc_readiness": {"safe_kex": 40, "hybrid_kex": 28, "pqc_sig": 18, "pqc_cert": 12, "tls13": 8, "aead": 6, "hsts": 4, "validation": 4},
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

PENALTY_CATEGORY_LABELS = {
    "tls": "TLS",
    "cipher": "Cipher",
    "certificate": "Certificate",
    "hsts": "HSTS",
    "pqc": "PQC",
}


def _confidence_multiplier(validation_confidence: float) -> float:
    return max(0.5, min(1.0, 0.55 + (validation_confidence * 0.45)))


def _push_finding(findings: List[dict], severity: str, factor: str, message: str, weight: int, confidence: float, category: str, evidence: str) -> None:
    findings.append({
        "severity": severity,
        "factor": factor,
        "message": message,
        "weight": weight,
        "impact": round(weight * confidence, 2),
        "confidence": round(max(0.0, min(1.0, confidence)), 2),
        "category": category,
        "evidence": evidence,
    })


def _label(severity: str, message: str) -> str:
    prefix = {
        "Critical": "🔴 CRITICAL",
        "High": "🔴 HIGH",
        "Medium": "🟡 MEDIUM",
        "Low": "🟢 INFO",
        "Info": "🟢 INFO",
    }[severity]
    return f"{prefix} — {message}"


def _penalty_category(finding: dict) -> str:
    category = str(finding.get("category") or "").lower()
    if category in ("tls_version", "cve"):
        return "tls"
    if category == "cipher_strength":
        return "cipher"
    if category == "certificate":
        return "certificate"
    if category == "hsts":
        return "hsts"
    if category in ("key_exchange", "pqc"):
        return "pqc"
    return "tls"


def _severity_upper(severity: str) -> str:
    mapping = {
        "Critical": "CRITICAL",
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "INFO",
        "Info": "INFO",
    }
    return mapping.get(severity, "INFO")


def _classify_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _tls_version_label(raw: dict) -> str:
    return (raw.get("tls_version") or "").strip()


def _cipher_name(raw: dict) -> str:
    return (raw.get("cipher_suite") or "").upper()


def calculate_risk_score(raw: dict, pqc: dict, validation: Optional[dict] = None, cves: Optional[list] = None) -> dict:
    """Calculate a weighted security score from TLS, PQC, and validation evidence."""
    validation = validation or raw.get("validation", {}) or {}
    validation_confidence = float(validation.get("confidence", raw.get("validation_confidence", 1.0)) or 1.0)
    confidence_multiplier = _confidence_multiplier(validation_confidence)

    tls_ver = _tls_version_label(raw)
    cipher_name = _cipher_name(raw)
    cert_days = raw.get("cert_days_left", 999) or 999
    sig_algo = (raw.get("cert_sig_alg") or "").lower()
    cert_bits = raw.get("cert_pubkey_bits", 2048) or 2048
    cert_alg = (raw.get("cert_pubkey_alg") or "").upper()

    score = 100.0
    vulnerability_total = 0.0
    readiness_total = 0.0
    findings: List[dict] = []
    penalties: List[str] = []

    # TLS version
    tls_weight = SCORING_WEIGHTS["tls_version"].get(tls_ver, 0)
    if tls_weight:
        impact = tls_weight * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        sev = "Critical" if tls_ver == "TLSv1" else "High" if tls_ver == "TLSv1.1" else "Medium"
        msg = "TLS 1.0 detected; deprecated and unsafe" if tls_ver == "TLSv1" else (
            "TLS 1.1 detected; deprecated and unsafe" if tls_ver == "TLSv1.1" else "TLS 1.2 detected; acceptable but not PQC-ready"
        )
        _push_finding(findings, sev, "TLS Version", msg, tls_weight, confidence_multiplier, "tls_version", tls_ver)
        penalties.append(_label(sev, msg))
    elif tls_ver == "TLSv1.3":
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["tls13"]
        penalties.append(_label("Info", "TLS 1.3 confirmed; modern protocol baseline observed"))

    # Cipher strength
    cipher_impact = 0.0
    if any(dep in cipher_name for dep in DEPRECATED_CIPHERS):
        cipher_impact = SCORING_WEIGHTS["cipher_strength"]["deprecated"]
        msg = f"Deprecated cipher detected: {next(dep for dep in DEPRECATED_CIPHERS if dep in cipher_name)}"
        severity = "Critical"
    elif "CBC" in cipher_name:
        cipher_impact = SCORING_WEIGHTS["cipher_strength"]["cbc"]
        msg = "CBC-mode cipher detected; vulnerable to legacy oracle attacks"
        severity = "Medium"
    else:
        msg = "AEAD cipher suite observed"
        severity = "Info"
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["aead"]

    if cipher_impact:
        impact = cipher_impact * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        _push_finding(findings, severity, "Cipher Strength", msg, int(cipher_impact), confidence_multiplier, "cipher_strength", cipher_name)
        penalties.append(_label(severity, msg))
    elif severity == "Info":
        penalties.append(_label("Info", msg))

    # Key exchange
    # pqc_status is the strict, evidence-based verdict from pqc_analyzer:
    # "NOT_VERIFIED" | "CLASSICAL" | "HYBRID_PQC" | "PQC". Unknown/NOT_VERIFIED
    # must NEVER be scored or worded as if it were a verified classical KEX
    # (REQUIREMENT 5 / 12) — it gets a neutral "verification required" note
    # and zero penalty instead.
    pqc_status = pqc.get("pqc_status", "NOT_VERIFIED" if not pqc.get("pqc_safe") else ("HYBRID_PQC" if pqc.get("is_hybrid") else "PQC"))
    kex_verified_label = pqc.get("pqc_key_exchange") or (raw.get("kex_algorithm") or "Unknown")

    if pqc_status == "PQC":
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["safe_kex"]
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["pqc_sig"] if is_pqc_sig(raw.get("cert_sig_alg", "")) else 0
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["pqc_cert"] if is_pqc_sig(raw.get("cert_sig_alg", "")) else 0
        penalties.append(_label("Info", f"Verified PQC key exchange: {kex_verified_label}"))
    elif pqc_status == "HYBRID_PQC":
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["hybrid_kex"]
        penalties.append(_label("Info", f"Verified hybrid PQC key exchange: {kex_verified_label}"))
    elif pqc_status == "CLASSICAL":
        kex_weight = SCORING_WEIGHTS["key_exchange"].get(kex_verified_label.upper(), 10)
        impact = kex_weight * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        severity = "Critical" if kex_verified_label.upper() == "RSA" else "High"
        msg = f"PQC migration gap — verified classical key exchange: {kex_verified_label}"
        _push_finding(findings, severity, "Key Exchange", msg, int(kex_weight), confidence_multiplier, "key_exchange", kex_verified_label)
        penalties.append(_label(severity, msg))
    else:  # NOT_VERIFIED
        msg = "TLS key-exchange group could not be independently verified; PQC assessment requires verification."
        _push_finding(findings, "Medium", "Key Exchange", msg, 0, confidence_multiplier, "key_exchange", "UNKNOWN")
        penalties.append(_label("Medium", msg))

    if pqc_status == "CLASSICAL" or pqc_status == "HYBRID_PQC":
        pqc_impact = (12 if pqc_status == "CLASSICAL" else 6) * confidence_multiplier
        score -= pqc_impact
        vulnerability_total += pqc_impact
        msg = ("No PQC key exchange detected (classical KEX verified)" if pqc_status == "CLASSICAL"
               else "Hybrid PQC transition still depends on classical key exchange")
        severity = "High" if pqc_status == "CLASSICAL" else "Medium"
        _push_finding(findings, severity, "PQC Readiness", msg, 12 if pqc_status == "CLASSICAL" else 6, confidence_multiplier, "pqc", "pqc_missing" if pqc_status == "CLASSICAL" else "hybrid")
        penalties.append(_label(severity, msg))
    elif pqc_status == "NOT_VERIFIED":
        # No PQC-vulnerability penalty for unverified KEX — verification gap only.
        penalties.append(_label("Info", "PQC readiness cannot be scored until the key-exchange group is verified"))

    # Certificate validity and trust chain
    if raw.get("cert_expired"):
        impact = SCORING_WEIGHTS["certificate"]["expired"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = "Certificate expired"
        _push_finding(findings, "Critical", "Certificate Validity", msg, SCORING_WEIGHTS["certificate"]["expired"], confidence_multiplier, "certificate", "expired")
        penalties.append(_label("Critical", msg))
    elif 0 < cert_days <= 14:
        impact = SCORING_WEIGHTS["certificate"]["expiring_soon"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = f"Certificate expires in {cert_days} days"
        _push_finding(findings, "High", "Certificate Validity", msg, SCORING_WEIGHTS["certificate"]["expiring_soon"], confidence_multiplier, "certificate", "expiring_soon")
        penalties.append(_label("High", msg))
    elif 14 < cert_days <= 30:
        impact = 8 * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = f"Certificate expires in {cert_days} days"
        _push_finding(findings, "Medium", "Certificate Validity", msg, 8, confidence_multiplier, "certificate", "expiring_soon")
        penalties.append(_label("Medium", msg))

    if raw.get("cert_self_signed"):
        impact = SCORING_WEIGHTS["certificate"]["self_signed"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = "Self-signed certificate detected"
        _push_finding(findings, "Medium", "Trust Chain", msg, SCORING_WEIGHTS["certificate"]["self_signed"], confidence_multiplier, "certificate", "self_signed")
        penalties.append(_label("Medium", msg))

    if "sha1" in sig_algo:
        impact = SCORING_WEIGHTS["certificate"]["sha1"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = "SHA-1 certificate signature detected"
        _push_finding(findings, "High", "Certificate Signature", msg, SCORING_WEIGHTS["certificate"]["sha1"], confidence_multiplier, "certificate", sig_algo)
        penalties.append(_label("High", msg))
    if "md5" in sig_algo:
        impact = SCORING_WEIGHTS["certificate"]["md5"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = "MD5 certificate signature detected"
        _push_finding(findings, "Critical", "Certificate Signature", msg, SCORING_WEIGHTS["certificate"]["md5"], confidence_multiplier, "certificate", sig_algo)
        penalties.append(_label("Critical", msg))

    if cert_alg == "RSA" and cert_bits < 2048:
        impact = SCORING_WEIGHTS["certificate"]["weak_bits"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = f"Weak RSA key size: {cert_bits} bits"
        _push_finding(findings, "High", "Key Size", msg, SCORING_WEIGHTS["certificate"]["weak_bits"], confidence_multiplier, "certificate", f"{cert_alg}:{cert_bits}")
        penalties.append(_label("High", msg))

    # HSTS
    if not raw.get("hsts", False):
        impact = SCORING_WEIGHTS["hsts_missing"] * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = "HSTS header missing"
        _push_finding(findings, "Medium", "Transport Policy", msg, SCORING_WEIGHTS["hsts_missing"], confidence_multiplier, "hsts", "missing")
        penalties.append(_label("Medium", msg))
    else:
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["hsts"]

    # Known vulnerabilities
    detected_cves = cves if cves is not None else detect_cves(raw, pqc)
    for cve in detected_cves:
        severity = cve.get("severity", "MEDIUM").upper()
        weight = SCORING_WEIGHTS["vulnerability_severity"].get(severity, 7)
        impact = weight * confidence_multiplier
        score -= impact
        vulnerability_total += impact
        msg = f"{cve.get('name', cve.get('cve_id', 'Vulnerability'))} detected ({cve.get('cve_id')})"
        _push_finding(findings, "Critical" if severity == "CRITICAL" else "High" if severity == "HIGH" else "Medium", "Known Vulnerability", msg, weight, confidence_multiplier, "cve", cve.get("cve_id", ""))
        penalties.append(_label("Critical" if severity == "CRITICAL" else "High" if severity == "HIGH" else "Medium", msg))

    # PQC readiness and certificate signatures
    if is_pqc_sig(raw.get("cert_sig_alg", "")):
        readiness_total += SCORING_WEIGHTS["pqc_readiness"]["pqc_sig"]
        penalties.append(_label("Info", "Post-quantum certificate signature detected"))
    else:
        msg = f"Classical certificate signature detected: {raw.get('cert_sig_alg') or 'unknown'}"
        _push_finding(findings, "Medium", "Certificate Signature", msg, 4, confidence_multiplier, "pqc", raw.get("cert_sig_alg", ""))
        penalties.append(_label("Medium", msg))

    readiness_total += SCORING_WEIGHTS["pqc_readiness"]["validation"] * validation_confidence

    score = max(0, min(100, round(score)))
    vulnerability_pct = max(0, min(100, round(vulnerability_total)))
    pqc_readiness_pct = max(0, min(100, round(readiness_total)))

    grade = _classify_grade(score)

    findings.sort(key=lambda item: (SEVERITY_ORDER[item["severity"]], -item["impact"], item["factor"]))
    penalties = [_label(item["severity"], item["message"]) for item in findings]

    risk_penalties = []
    category_totals = {key: 0.0 for key in PENALTY_CATEGORY_LABELS}
    for idx, finding in enumerate(findings, start=1):
        deduction = round(float(finding.get("impact") or 0.0), 2)
        bucket = _penalty_category(finding)
        category_totals[bucket] += deduction
        risk_penalties.append({
            "id": idx,
            "severity": _severity_upper(finding.get("severity", "Info")),
            "category": bucket,
            "category_label": PENALTY_CATEGORY_LABELS[bucket],
            "reason": finding.get("message", ""),
            "deduction": deduction,
            "confidence": round(float(finding.get("confidence") or 0.0), 2),
            "evidence": finding.get("evidence", ""),
        })

    category_totals = {k: round(v, 2) for k, v in category_totals.items()}

    if score >= 90 and pqc.get("pqc_safe"):
        grade = "A+"
    elif score >= 80 and pqc_readiness_pct >= 50:
        grade = "A"

    if validation.get("low_confidence") and grade in ("A+", "A"):
        grade = "B"
        penalties.append(_label("Medium", "Grade downgraded because validation confidence is low"))

    score_formula = "security_score = max(0, 100 - min(100, weighted_risk))"
    vulnerability_formula = "vulnerability_pct = min(100, weighted_risk)"
    pqc_formula = "pqc_readiness_pct = min(100, weighted_readiness)"

    return {
        "score": score,
        "grade": grade,
        "vulnerability_pct": vulnerability_pct,
        "pqc_readiness_pct": pqc_readiness_pct,
        "penalties": penalties,
        "finding_details": findings,
        "pqc_safe": pqc.get("pqc_safe", False),
        "validation_confidence": round(validation_confidence, 2),
        "confidence": round(validation_confidence, 2),
        "details": {
            "tls_version": tls_ver,
            "validation": validation,
            "validation_confidence": round(validation_confidence, 2),
            "confidence_multiplier": round(confidence_multiplier, 2),
            "risk_total": vulnerability_total,
            "readiness_total": readiness_total,
            "score_formula": score_formula,
            "vulnerability_formula": vulnerability_formula,
            "pqc_formula": pqc_formula,
            "weights": SCORING_WEIGHTS,
            "total_deducted": vulnerability_total,
            "finding_count": len(findings),
            "category_totals": category_totals,
        },
        "risk_penalties": risk_penalties,
        "explanation": {
            "summary": f"Security score {score}/100 is derived from weighted TLS, certificate, HSTS, CVE, and PQC factors.",
            "risk_drivers": [item["message"] for item in findings[:5]],
            "pqc_readiness_drivers": [
                "PQC key exchange detected" if pqc.get("pqc_safe") else "Classical key exchange still present",
                "PQC certificate signature detected" if is_pqc_sig(raw.get("cert_sig_alg", "")) else "Classical certificate signature detected",
                "Validation confidence included in readiness score",
            ],
        },
    }

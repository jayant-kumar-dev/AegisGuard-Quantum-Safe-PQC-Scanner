"""
AegisGuard — AI Insights Engine
Deterministic anomaly detection and remediation guidance for scan results.

The module is intentionally model-agnostic: it works without external ML
dependencies, but it exposes stable hooks for future statistical or LLM-based
classifiers.
"""

from __future__ import annotations

from typing import List, Optional


def _severity_from_score(score: int, confidence: float) -> str:
    if score >= 85 and confidence >= 0.85:
        return "Low"
    if score >= 70 and confidence >= 0.7:
        return "Medium"
    if score >= 50 or confidence < 0.7:
        return "High"
    return "Critical"


def _asset_priority(score: int, pqc_pct: int, confidence: float) -> int:
    if score < 40 or pqc_pct < 30:
        return 1
    if score < 60 or pqc_pct < 50:
        return 2
    if score < 75 or pqc_pct < 70:
        return 3
    if confidence < 0.7:
        return 3
    return 4


def _trend_direction(history: List[dict], current_score: int) -> dict:
    scores = [int(item.get("score", 0)) for item in history if isinstance(item, dict) and item.get("score") is not None]
    if not scores:
        return {"direction": "unknown", "delta": 0, "message": "No historical scans available for trend analysis."}

    previous_avg = sum(scores) / len(scores)
    delta = round(current_score - previous_avg, 1)
    if delta >= 8:
        direction = "improving"
    elif delta <= -8:
        direction = "degrading"
    else:
        direction = "stable"

    return {
        "direction": direction,
        "delta": delta,
        "previous_average": round(previous_avg, 1),
        "message": f"Current score is {delta:+.1f} points versus historical average.",
    }


def _top_risk_drivers(risk_details: dict) -> List[str]:
    drivers: List[str] = []
    for item in risk_details.get("finding_details", []):
        if item.get("severity") in ("Critical", "High"):
            drivers.append(item.get("message", item.get("factor", "")))
    return drivers[:4]


def build_ai_insights(raw: dict, pqc: dict, risk: dict, validation: Optional[dict] = None, history: Optional[List[dict]] = None) -> dict:
    """Return deterministic AI-like insights for anomaly detection and prioritization."""
    validation = validation or raw.get("validation", {}) or {}
    confidence = float(validation.get("confidence", raw.get("validation_confidence", 1.0)) or 1.0)
    score = int(risk.get("score", 0) or 0)
    pqc_pct = int(risk.get("pqc_readiness_pct", 0) or 0)

    anomaly_signals: List[str] = []
    signal_weights: List[int] = []

    if validation.get("low_confidence"):
        anomaly_signals.append("Validation conflicts detected across TLS probes")
        signal_weights.append(30)
    if raw.get("tls_version") in ("TLSv1", "TLSv1.1"):
        anomaly_signals.append("Legacy TLS protocol observed")
        signal_weights.append(18)
    if "CBC" in (raw.get("cipher_suite") or "").upper():
        anomaly_signals.append("CBC cipher detected")
        signal_weights.append(12)
    if not raw.get("hsts", False):
        anomaly_signals.append("Missing HSTS header")
        signal_weights.append(8)
    if not pqc.get("pqc_safe"):
        anomaly_signals.append("No PQC key exchange detected")
        signal_weights.append(15)

    anomaly_score = min(100, sum(signal_weights))
    severity = _severity_from_score(score, confidence)
    priority = _asset_priority(score, pqc_pct, confidence)
    trend = _trend_direction(history or [], score)

    remediation: List[str] = []
    if raw.get("tls_version") in ("TLSv1", "TLSv1.1", "TLSv1.2"):
        remediation.append("Prefer TLS 1.3 and remove legacy protocol support.")
    if "CBC" in (raw.get("cipher_suite") or "").upper():
        remediation.append("Move to AEAD ciphers such as AES-GCM or ChaCha20-Poly1305.")
    if not pqc.get("pqc_safe"):
        remediation.append("Deploy ML-KEM for key exchange and ML-DSA for signatures.")
    if not raw.get("hsts", False):
        remediation.append("Enable HSTS with a long max-age and preload when appropriate.")
    if confidence < 0.7:
        remediation.append("Re-run the scan with validation enabled to resolve conflicting evidence.")

    top_drivers = _top_risk_drivers(risk)
    if top_drivers:
        remediation.extend(top_drivers[:2])

    feature_vector = {
        "security_score": score,
        "pqc_readiness_pct": pqc_pct,
        "validation_confidence": round(confidence, 2),
        "anomaly_score": anomaly_score,
        "legacy_tls": raw.get("tls_version") in ("TLSv1", "TLSv1.1"),
        "weak_cipher": "CBC" in (raw.get("cipher_suite") or "").upper(),
        "pqc_missing": not pqc.get("pqc_safe"),
        "hsts_missing": not raw.get("hsts", False),
    }

    return {
        "model": "deterministic-rules-v1",
        "severity": severity,
        "priority": priority,
        "anomaly_score": anomaly_score,
        "confidence_adjustment": round(max(0.5, confidence), 2),
        "signal_count": len(anomaly_signals),
        "signals": anomaly_signals,
        "remediation": remediation[:5],
        "priority_reason": "High-risk crypto posture" if priority <= 2 else "Monitor and re-scan" if priority == 3 else "Stable posture",
        "trend": trend,
        "feature_vector": feature_vector,
    }

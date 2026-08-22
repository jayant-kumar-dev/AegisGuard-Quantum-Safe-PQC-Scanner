"""
AegisGuard — PQC Analyzer
Strict, evidence-based post-quantum readiness classification.

Design rule (non-negotiable, see REQUIREMENT 12 in the research spec):
    TLS 1.3 != PQC.  AES-GCM != KEX.  RSA certificate != classical TLS KEX.
    Unknown KEX != classical.  Unknown KEX != PQC vulnerability.
    Unknown KEX != Harvest Now Decrypt Later.

Only an explicitly observed, independently verified KEX NamedGroup (see
scanner.tls_probe.get_actual_tls13_kex) may ever drive classification here.
"""

from __future__ import annotations

from typing import Optional

from config import KEX_GROUP_CLASSIFICATION, PQC_CONFIDENCE_BY_STATUS, PQC_SIG_NAMES


def is_pqc_sig(sig_alg: str) -> bool:
    """True if sig_alg is a recognised post-quantum signature algorithm."""
    s = (sig_alg or "").upper()
    return any(name in s for name in PQC_SIG_NAMES)


def classify_pqc_signature(cert_sig_alg: Optional[str]) -> str:
    """Classify the certificate's signature algorithm independently of KEX.

    A KEM/key-exchange result must never be inferred from this, and vice
    versa (REQUIREMENT 6) — these are reported as two separate fields.
    """
    s = (cert_sig_alg or "").upper()
    if not s:
        return "Unknown"
    if any(name in s for name in ("ML-DSA", "MLDSA", "DILITHIUM")):
        return "ML-DSA"
    if any(name in s for name in ("SLH-DSA", "SLHDSA", "SPHINCS")):
        return "ML-DSA"  # PQC hash-based signature family; reported under the
        # same high-level "PQC signature" bucket as ML-DSA for the CSV schema.
    if "ED25519" in s:
        return "Ed25519"
    if "ECDSA" in s:
        return "ECDSA"
    if "RSASSA-PSS" in s or "RSA-PSS" in s or "PSS" in s:
        return "RSA-PSS"
    if "RSA" in s:
        return "RSA"
    return "Unknown"


def classify_pqc_status(kex_group: Optional[str]) -> dict:
    """Classify a TLS key-exchange NamedGroup using ONLY explicit evidence.

    Args:
        kex_group: The exact NamedGroup string as returned by
            scanner.tls_probe.get_actual_tls13_kex()['kex_group']. Must be
            "Unknown" (not a guess) if it could not be independently
            verified.

    Returns:
        dict with keys: pqc_status, is_hybrid, pqc_confidence,
        pqc_key_exchange, evidence.
    """
    group_raw = (kex_group or "Unknown").strip()
    lookup_key = group_raw.upper().replace(" ", "").replace("-", "")

    if not group_raw or group_raw.lower() == "unknown" or lookup_key not in KEX_GROUP_CLASSIFICATION:
        return {
            "pqc_status": "NOT_VERIFIED",
            "is_hybrid": False,
            "pqc_confidence": PQC_CONFIDENCE_BY_STATUS["NOT_VERIFIED"],
            "pqc_key_exchange": "Unknown",
            "evidence": "TLS key-exchange group could not be independently verified.",
        }

    status = KEX_GROUP_CLASSIFICATION[lookup_key]  # CLASSICAL | HYBRID_PQC | PQC
    return {
        "pqc_status": status,
        "is_hybrid": status == "HYBRID_PQC",
        "pqc_confidence": PQC_CONFIDENCE_BY_STATUS[status],
        "pqc_key_exchange": group_raw,
        "evidence": f"Verified negotiated TLS key-exchange group: {group_raw}",
    }


# ── Legacy-shaped wrapper ────────────────────────────────────────────────────
# The rest of AegisGuard (risk_scorer, cbom_generator, pipeline, intelligence)
# consumes analyze_pqc(raw) -> dict with keys pqc_safe/is_hybrid/status/reason.
# This wrapper is kept so those modules do not need to be rewritten; it is
# built strictly on top of classify_pqc_status(), so the underlying
# no-false-positive guarantees flow through unchanged.
def analyze_pqc(raw: dict) -> dict:
    """Analyze TLS scan results for PQC readiness (legacy-compatible shape)."""
    kex_group = raw.get("kex_algorithm") or "Unknown"
    verdict = classify_pqc_status(kex_group)
    pqc_status = verdict["pqc_status"]
    pqc_sig = classify_pqc_signature(raw.get("cert_sig_alg"))

    if pqc_status == "NOT_VERIFIED":
        status_label = "Verification Required"
        reason = ("TLS key-exchange group could not be independently verified; "
                  "PQC assessment requires verification.")
        pqc_safe = False
    elif pqc_status == "CLASSICAL":
        status_label = "PQC Migration Gap"
        reason = f"Classical key exchange verified: {verdict['pqc_key_exchange']}"
        pqc_safe = False
    elif pqc_status == "HYBRID_PQC":
        status_label = "Hybrid PQC"
        reason = f"Protected by verified hybrid scheme: {verdict['pqc_key_exchange']}"
        pqc_safe = True
    else:  # PQC
        status_label = "PQC"
        reason = f"Protected by verified PQC key exchange: {verdict['pqc_key_exchange']}"
        pqc_safe = True

    safe_components = [verdict["pqc_key_exchange"]] if pqc_safe else []
    vulnerable_components = [verdict["pqc_key_exchange"]] if pqc_status == "CLASSICAL" else []

    return {
        # Legacy fields (consumed by risk_scorer / cbom_generator / pipeline)
        "status": status_label,
        "pqc_safe": pqc_safe,
        "is_hybrid": verdict["is_hybrid"],
        "reason": reason,
        "vulnerable_components": vulnerable_components,
        "safe_components": safe_components,
        # Strict research-grade fields (REQUIREMENT 2 / 9)
        "pqc_status": pqc_status,
        "pqc_confidence": verdict["pqc_confidence"],
        "pqc_key_exchange": verdict["pqc_key_exchange"],
        "pqc_signature": pqc_sig,
        "evidence": verdict["evidence"],
    }

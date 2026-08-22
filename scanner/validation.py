"""
AegisGuard — TLS Validation Pipeline
Cross-verifies probe results using multiple TLS checks before scoring.
"""

from __future__ import annotations

import datetime
import logging
import socket
import ssl
from typing import Any, Dict, List, Tuple

try:
    from .tls_probe import _extract_kex, _parse_cert_fields
except Exception:
    from scanner.tls_probe import _extract_kex, _parse_cert_fields

logger = logging.getLogger("AegisGuard.Validation")


_FIELD_WEIGHTS = {
    "tls_version": 0.25,
    "cipher_suite": 0.25,
    "kex_algorithm": 0.15,
    "cert_sha256": 0.20,
    "cert_subject": 0.10,
    "cert_issuer": 0.10,
    "cert_not_after": 0.05,
    "hsts": 0.05,
}


def _normalize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip().lower()


def _score_field(primary: Any, secondary: Any, weight: float) -> Tuple[float, str, str | None]:
    p = _normalize_value(primary)
    s = _normalize_value(secondary)

    if not p and not s:
        return weight * 0.55, "missing", None
    if p and s and p == s:
        return weight, "match", None
    if p and s and p != s:
        return weight * 0.20, "conflict", f"primary={primary!r}, secondary={secondary!r}"
    if p or s:
        return weight * 0.72, "partial", f"primary={primary!r}, secondary={secondary!r}"
    return weight * 0.55, "missing", None


def _probe_tls(host: str, port: int, timeout: int, verify: bool) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "reachable": False,
        "verified": verify,
        "tls_version": None,
        "cipher_suite": None,
        "kex_algorithm": None,
        "cert_subject": None,
        "cert_issuer": None,
        "cert_pubkey_alg": None,
        "cert_pubkey_bits": None,
        "cert_sig_alg": None,
        "cert_not_after": None,
        "cert_days_left": None,
        "cert_expired": False,
        "cert_self_signed": False,
        "cert_sha256": None,
        "verification_error": None,
        "error": None,
    }

    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    ctx.check_hostname = verify
    ctx.verify_mode = ssl.CERT_REQUIRED if verify else ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["tls_version"] = ssock.version() or "Unknown"
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = cipher[0]
                    result["kex_algorithm"] = _extract_kex(cipher[0], host, port)
                der = ssock.getpeercert(binary_form=True)
                dct = ssock.getpeercert()
                if der and dct:
                    _parse_cert_fields(result, der, dct)
    except ssl.SSLCertVerificationError as exc:
        result["verification_error"] = str(exc)
        result["error"] = str(exc)
    except ssl.SSLError as exc:
        result["error"] = f"TLS error: {exc.reason}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except OSError as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)

    return result


def validate_tls_scan(raw: dict, timeout: int = 8) -> dict:
    """Validate a raw TLS probe with independent re-checks and confidence scoring."""
    host = raw.get("host") or ""
    port = int(raw.get("port", 443) or 443)

    primary = dict(raw)
    verified = _probe_tls(host, port, timeout, verify=True) if host else {}
    fallback = _probe_tls(host, port, timeout, verify=False) if host and not verified.get("reachable") else {}

    if not verified.get("reachable") and fallback:
        secondary = fallback
    else:
        secondary = verified or fallback or {}

    checks: List[dict] = []
    conflicts: List[dict] = []
    confidence_total = 0.0
    confidence_weight = 0.0

    comparison_map = [
        ("tls_version", "TLS version"),
        ("cipher_suite", "Cipher suite"),
        ("kex_algorithm", "Key exchange"),
        ("cert_subject", "Certificate subject"),
        ("cert_issuer", "Certificate issuer"),
        ("cert_sha256", "Certificate fingerprint"),
        ("cert_not_after", "Certificate expiry"),
        ("hsts", "HSTS header"),
    ]

    for field, label in comparison_map:
        weight = _FIELD_WEIGHTS[field]
        contribution, status, evidence = _score_field(primary.get(field), secondary.get(field), weight)
        confidence_total += contribution
        confidence_weight += weight
        check = {
            "field": field,
            "label": label,
            "status": status,
            "confidence": round(min(1.0, contribution / max(weight, 1e-9)), 2),
            "primary": primary.get(field),
            "secondary": secondary.get(field),
        }
        if evidence:
            check["evidence"] = evidence
        if status == "conflict":
            conflicts.append(check)
        checks.append(check)

    verification_bonus = 0.1 if verified.get("reachable") and not verified.get("verification_error") else 0.0
    verification_penalty = 0.12 if verified.get("verification_error") else 0.0

    raw_confidence = confidence_total / max(confidence_weight, 1e-9)
    confidence = max(0.0, min(1.0, raw_confidence + verification_bonus - verification_penalty))
    low_confidence = confidence < 0.7 or bool(conflicts)

    normalized = dict(primary)
    for field in ("tls_version", "cipher_suite", "kex_algorithm", "cert_subject", "cert_issuer", "cert_pubkey_alg", "cert_pubkey_bits", "cert_sig_alg", "cert_not_after", "cert_days_left", "cert_expired", "cert_self_signed", "cert_sha256"):
        if normalized.get(field) in (None, "", [], {}):
            if secondary.get(field) not in (None, "", [], {}):
                normalized[field] = secondary.get(field)

    if secondary.get("hsts") is not None:
        normalized["hsts"] = bool(primary.get("hsts") or secondary.get("hsts"))

    if secondary.get("tls_version") and not normalized.get("tls_version"):
        normalized["tls_version"] = secondary.get("tls_version")

    normalized["validation_confidence"] = round(confidence, 2)
    normalized["validation_status"] = "low_confidence" if low_confidence else "validated"
    normalized["validation_checked_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    return {
        "host": host,
        "port": port,
        "confidence": round(confidence, 2),
        "low_confidence": low_confidence,
        "validation_status": normalized["validation_status"],
        "checked_at": normalized["validation_checked_at"],
        "primary_probe": primary,
        "secondary_probe": secondary,
        "checks": checks,
        "conflicts": conflicts,
        "normalized": normalized,
    }

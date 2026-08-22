"""
AegisGuard — CBOM Generator
Generates CycloneDX 1.6 Cryptographic Bill of Materials.
"""

import datetime
import hashlib
from config import PORT_ASSET_MAP, CLASSICAL_KEX, PROJECT_NAME, VERSION
try:
    from .pqc_analyzer import is_pqc_sig
except Exception:
    from scanner.pqc_analyzer import is_pqc_sig


def generate_cbom(target: str, port: int, raw: dict, pqc: dict, risk: dict) -> dict:
    """Generate a full CBOM document for a scanned target."""
    asset_type = PORT_ASSET_MAP.get(port, f"Network Service (Port {port})")
    cipher = raw.get("cipher_suite") or ""
    tls_ver = raw.get("tls_version") or ""
    is_pqc_safe = pqc.get("pqc_safe", False)
    is_hybrid = pqc.get("is_hybrid", False)
    has_pqc_sig = is_pqc_sig(raw.get("cert_sig_alg", ""))

    cert = {
        "subject": raw.get("cert_subject"), "issuer": raw.get("cert_issuer"),
        "signatureAlgorithm": raw.get("cert_sig_alg"),
        "publicKeyAlgorithm": raw.get("cert_pubkey_alg"),
        "publicKeyBits": raw.get("cert_pubkey_bits"),
        "notAfter": raw.get("cert_not_after"),
        "daysToExpiry": raw.get("cert_days_left"),
        "expired": raw.get("cert_expired"),
        "selfSigned": raw.get("cert_self_signed"),
        "sha256Fingerprint": raw.get("cert_sha256"),
    }

    pqc_label = "Fully Quantum Safe" if is_pqc_safe and not is_hybrid else \
                "Hybrid PQC (Partial)" if is_pqc_safe else "Not Quantum Safe"

    nist_standards = []
    if is_pqc_safe:
        nist_standards.append("FIPS 203 (ML-KEM)")
    if has_pqc_sig:
        nist_standards.extend(["FIPS 204 (ML-DSA)", "FIPS 205 (SLH-DSA)"])

    metadata_standard = ("NIST " + "/".join(s.split("(")[0].strip() for s in nist_standards) + ", CycloneDX 1.6") if nist_standards else "CycloneDX 1.6 (No NIST PQC standards satisfied)"

    cert_eligible = is_pqc_safe and not is_hybrid and has_pqc_sig

    # Remediation plan
    remediation = []
    if not is_pqc_safe:
        remediation.append({"action": "Migrate Key Exchange", "target": "ML-KEM-768 (NIST FIPS 203)", "priority": "CRITICAL"})
        remediation.append({"action": "Migrate Digital Signatures", "target": "ML-DSA-65 (NIST FIPS 204)", "priority": "HIGH"})
        if tls_ver != "TLSv1.3":
            remediation.append({"action": "Enable TLS 1.3", "target": "RFC 8446", "priority": "HIGH"})
    if not has_pqc_sig and is_pqc_safe:
        remediation.append({"action": "Migrate Certificate Signature", "target": "ML-DSA-65 (NIST FIPS 204)", "priority": "MEDIUM"})
    if not raw.get("hsts", False):
        remediation.append({"action": "Enable HSTS", "target": "RFC 6797", "priority": "MEDIUM"})

    # KEX analysis — kex_name is either an explicitly OpenSSL-verified
    # NamedGroup or the literal string "Unknown"; it is never fabricated.
    kex_name = raw.get("kex_algorithm") or "Unknown"
    kex_upper = kex_name.upper()
    kex_info = CLASSICAL_KEX.get(kex_upper, {})
    pqc_status = pqc.get("pqc_status", "NOT_VERIFIED")

    # CycloneDX 1.6 cryptographic-asset representation. The negotiated
    # NamedGroup is surfaced as parameterSetIdentifier — set to "Unknown"
    # whenever it was not independently verified, never invented.
    crypto_properties = {
        "assetType": "protocol",
        "protocolProperties": {
            "type": "tls",
            "version": tls_ver or "unknown",
            "cipherSuite": [{"name": cipher}] if cipher else [],
        },
        "relatedCryptoMaterialProperties": {
            "type": "key-exchange",
            "parameterSetIdentifier": kex_name,
        },
        "oid": None,
    }

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    serial = hashlib.sha256(f"{target}:{port}:{ts}".encode()).hexdigest()[:16].upper()

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:aegis-cbom-{serial}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{"vendor": "AegisGuard", "name": PROJECT_NAME, "version": VERSION}],
            "standard": metadata_standard,
        },
        "asset": {"host": target, "port": port, "type": asset_type, "ip": raw.get("ip")},
        "tlsProfile": {"version": tls_ver, "cipherSuite": cipher, "keyExchange": kex_name},
        "certificate": cert,
        "components": [{
            "type": "cryptographic-asset",
            "name": f"{target}:{port} TLS key-exchange",
            "cryptoProperties": crypto_properties,
            "properties": [
                {"name": "aegisguard:pqcStatus", "value": pqc_status},
                {"name": "aegisguard:pqcConfidence", "value": pqc.get("pqc_confidence", "UNKNOWN")},
                {"name": "aegisguard:evidence", "value": pqc.get("evidence", "")},
            ],
        }],
        "pqcAssessment": {
            "status": pqc_label, "pqcSafe": is_pqc_safe, "isHybrid": is_hybrid,
            "pqcStatus": pqc_status,
            "pqcConfidence": pqc.get("pqc_confidence", "UNKNOWN"),
            "pqcKeyExchange": pqc.get("pqc_key_exchange", kex_name),
            "pqcSignature": pqc.get("pqc_signature", "Unknown"),
            "evidence": pqc.get("evidence", ""),
            "safeComponents": pqc.get("safe_components", []),
            "vulnerableComponents": pqc.get("vulnerable_components", []),
            "nistStandards": nist_standards,
            "certificationEligible": cert_eligible,
        },
        "riskScore": {"score": risk.get("score"), "grade": risk.get("grade")},
        "keyExchangeAnalysis": {
            "algorithm": kex_name,
            "verified": pqc_status != "NOT_VERIFIED",
            "standard": kex_info.get("std", "N/A") if pqc_status == "CLASSICAL" else "N/A",
            "keySize": kex_info.get("ks", "N/A") if pqc_status == "CLASSICAL" else "N/A",
            "recommendation": (kex_info.get("rec", "No change needed") if pqc_status == "CLASSICAL"
                                else "Already PQC protected" if is_pqc_safe
                                else "Verify negotiated NamedGroup before drawing conclusions"),
        },
        "remediationPlan": remediation,
    }


def generate_cyclonedx_1_6_cbom(audit_record: dict) -> dict:
    """Spec-named entry point (REQUIREMENT 7): build a CycloneDX 1.6 CBOM
    directly from an assembled audit record (see scanner/exporters.py).

    Thin adapter over generate_cbom() so both the pipeline's raw/pqc/risk
    shape and a flattened audit-record shape can produce the same CBOM
    structure without duplicating the CycloneDX-building logic.
    """
    raw = {
        "host": audit_record.get("domain"), "port": audit_record.get("port"),
        "ip": audit_record.get("ip"), "tls_version": audit_record.get("tls_version"),
        "cipher_suite": audit_record.get("cipher_suite"),
        "kex_algorithm": audit_record.get("key_exchange_group", "Unknown"),
        "cert_subject": audit_record.get("certificate_subject"),
        "cert_issuer": audit_record.get("certificate_issuer"),
        "cert_sig_alg": audit_record.get("certificate_signature_algorithm"),
        "cert_pubkey_alg": audit_record.get("certificate_public_key_algorithm"),
        "cert_pubkey_bits": audit_record.get("certificate_public_key_size"),
        "cert_not_after": audit_record.get("certificate_not_after"),
        "cert_days_left": audit_record.get("certificate_days_remaining"),
        "cert_expired": audit_record.get("certificate_expired"),
        "cert_self_signed": audit_record.get("certificate_self_signed"),
        "cert_sha256": audit_record.get("certificate_sha256"),
        "hsts": audit_record.get("hsts"),
    }
    pqc = {
        "pqc_status": audit_record.get("pqc_status", "NOT_VERIFIED"),
        "pqc_safe": audit_record.get("pqc_status") in ("HYBRID_PQC", "PQC"),
        "is_hybrid": bool(audit_record.get("is_hybrid")),
        "pqc_confidence": audit_record.get("pqc_confidence", "UNKNOWN"),
        "pqc_key_exchange": audit_record.get("pqc_key_exchange", "Unknown"),
        "pqc_signature": audit_record.get("pqc_signature", "Unknown"),
        "evidence": audit_record.get("pqc_evidence", ""),
        "safe_components": [], "vulnerable_components": [],
    }
    risk = {"score": audit_record.get("risk_score"), "grade": audit_record.get("risk_grade")}
    return generate_cbom(audit_record.get("domain", ""), int(audit_record.get("port") or 443), raw, pqc, risk)

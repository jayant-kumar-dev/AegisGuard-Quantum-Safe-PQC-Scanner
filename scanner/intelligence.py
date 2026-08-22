"""
AegisGuard — Intelligence Module
Security headers audit, CVE detection, HNDL timeline, compliance evaluation,
crypto agility scoring, DNS security scanning.
"""

import ssl
import socket
import logging
from config import (
    SECURITY_HEADERS, CVE_DATABASE, QUANTUM_THREAT_TIMELINE,
    COMPLIANCE_FRAMEWORKS, DEPRECATED_CIPHERS,
)

logger = logging.getLogger("AegisGuard.Intel")


# ── Security Headers Audit ─────────────────────────────────────────────────
def scan_security_headers(host: str, port: int, timeout: int = 8) -> dict:
    headers_found = {}
    try:
        import http.client
        conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                           context=ssl._create_unverified_context())
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        for hdr_name in SECURITY_HEADERS:
            headers_found[hdr_name] = resp.getheader(hdr_name)
        headers_found["_server"] = resp.getheader("Server")
        headers_found["_powered_by"] = resp.getheader("X-Powered-By")
        headers_found["_status_code"] = resp.status
        conn.close()
    except Exception as e:
        headers_found["_error"] = str(e)

    results = []
    score = 0
    max_score = len(SECURITY_HEADERS)
    for hdr_name, meta in SECURITY_HEADERS.items():
        present = headers_found.get(hdr_name) is not None
        val = headers_found.get(hdr_name, "")
        if present:
            score += 1
        results.append({
            "header": hdr_name, "present": present, "value": val or "",
            "priority": meta["priority"], "description": meta["description"],
            "recommended": meta["recommended"],
        })

    grade = "A" if score >= 8 else "B" if score >= 6 else "C" if score >= 4 else "D" if score >= 2 else "F"
    return {
        "score": score, "max_score": max_score, "grade": grade,
        "percentage": round((score / max(max_score, 1)) * 100),
        "headers": results,
        "server_fingerprint": headers_found.get("_server"),
        "powered_by": headers_found.get("_powered_by"),
    }


# ── CVE Detection ──────────────────────────────────────────────────────────
def detect_cves(raw: dict, pqc: dict) -> list:
    tls_ver = (raw.get("tls_version") or "").upper()
    cipher = (raw.get("cipher_suite") or "").upper()
    kex = (raw.get("kex_algorithm") or "").upper()
    is_pqc = pqc.get("pqc_safe", False)
    # Strict verdict from pqc_analyzer.classify_pqc_status. HNDL and other
    # KEX-based CVEs may only fire when a classical KEX was EXPLICITLY
    # VERIFIED — never for NOT_VERIFIED/Unknown (REQUIREMENT 12).
    pqc_status = pqc.get("pqc_status", "NOT_VERIFIED" if not is_pqc else "PQC")
    kex_verified_classical = pqc_status == "CLASSICAL"
    detected = []

    for cve in CVE_DATABASE:
        triggered = False
        for t in cve["affects"]:
            if t == "SSLv3" and "SSLV3" in tls_ver:
                triggered = True
            elif t == "SSLv2" and "SSLV2" in tls_ver:
                triggered = True
            elif t == "TLSv1.0" and tls_ver == "TLSV1":
                triggered = True
            elif t == "TLS_CBC" and "CBC" in cipher:
                triggered = True
            elif t == "AES_CBC" and "AES" in cipher and "CBC" in cipher:
                triggered = True
            elif t == "RSA_KEX" and kex_verified_classical and kex == "RSA":
                triggered = True
            elif t == "EXPORT" and "EXPORT" in cipher:
                triggered = True
            elif t == "DHE_WEAK" and kex_verified_classical and kex == "DHE":
                triggered = True
            elif t == "NO_PQC" and kex_verified_classical:
                # Harvest-Now-Decrypt-Later only fires on a VERIFIED classical
                # KEX. An Unknown/NOT_VERIFIED KEX must never be scored as
                # "vulnerable" — that would be exactly the false positive
                # this research tool is designed to avoid.
                triggered = True
            elif t == "ECDHE" and kex_verified_classical and kex == "ECDHE":
                triggered = True
            elif t == "DHE" and kex_verified_classical and kex == "DHE":
                triggered = True
            elif t == "DH" and kex_verified_classical and kex == "DH":
                triggered = True
            elif t == "ECDH" and kex_verified_classical and kex == "ECDH":
                triggered = True
        if triggered:
            detected.append({
                "cve_id": cve["id"], "name": cve["name"],
                "severity": cve["severity"], "cvss": cve["cvss"],
                "description": cve["description"], "remediation": cve["remediation"],
                "year": cve["year"], "cwe": cve["cwe"],
            })
    return detected


# ── HNDL Timeline ──────────────────────────────────────────────────────────
def calculate_hndl_timeline(raw: dict, pqc: dict) -> dict:
    kex = (raw.get("kex_algorithm") or "").upper()
    cert_alg = (raw.get("cert_pubkey_alg") or "").upper()
    cert_bits = raw.get("cert_pubkey_bits") or 2048
    sig = (raw.get("cert_sig_alg") or "").lower()
    cipher = (raw.get("cipher_suite") or "").upper()
    is_pqc = pqc.get("pqc_safe", False)

    timeline_entries = []
    pqc_status = pqc.get("pqc_status", "NOT_VERIFIED" if not is_pqc else "PQC")

    # KEX — only build a threat-timeline entry when the group was actually
    # verified. An Unknown/NOT_VERIFIED KEX must not be silently treated as
    # ECDHE (or anything else); that would fabricate a threat timeline out of
    # missing evidence (REQUIREMENT 12).
    kex_key = None
    if pqc_status in ("PQC", "HYBRID_PQC"):
        kex_key = "ML-KEM"
    elif pqc_status == "CLASSICAL":
        if kex in ("X25519", "SECP256R1", "SECP384R1", "SECP521R1"):
            kex_key = "ECDHE"
        elif kex == "RSA":
            kex_key = f"RSA-{cert_bits}"

    if kex_key and kex_key in QUANTUM_THREAT_TIMELINE:
        e = QUANTUM_THREAT_TIMELINE[kex_key]
        timeline_entries.append({"component": f"Key Exchange ({kex or kex_key})", "algorithm": kex_key, **e})
    elif pqc_status == "NOT_VERIFIED":
        timeline_entries.append({
            "component": "Key Exchange (Unknown)", "algorithm": "Unverified",
            "years_to_break": "N/A", "threat_level": "VERIFICATION REQUIRED",
            "nist_deadline": "N/A", "qubits_needed": "N/A",
        })

    # Cert signature
    sig_key = "SHA-1" if "sha1" in sig else "SHA-256"
    if sig_key in QUANTUM_THREAT_TIMELINE:
        e = QUANTUM_THREAT_TIMELINE[sig_key]
        timeline_entries.append({"component": f"Certificate Signature ({sig_key})", "algorithm": sig_key, **e})

    # Cert key
    pk_key = f"RSA-{cert_bits}" if cert_alg == "RSA" else "ECDH-P256" if cert_alg in ("EC", "ECDSA") else "RSA-2048"
    if pk_key in QUANTUM_THREAT_TIMELINE:
        e = QUANTUM_THREAT_TIMELINE[pk_key]
        timeline_entries.append({"component": f"Certificate Key ({cert_alg} {cert_bits}b)", "algorithm": pk_key, **e})

    # Symmetric
    if "AES_256" in cipher or "AES256" in cipher:
        sym_key = "AES-256"
    elif "AES_128" in cipher or "AES128" in cipher:
        sym_key = "AES-128"
    elif "3DES" in cipher:
        sym_key = "3DES"
    else:
        sym_key = "AES-256"
    if sym_key in QUANTUM_THREAT_TIMELINE:
        e = QUANTUM_THREAT_TIMELINE[sym_key]
        timeline_entries.append({"component": f"Symmetric Cipher ({sym_key})", "algorithm": sym_key, **e})

    threat_levels = [e.get("threat_level", "") for e in timeline_entries]
    if "VERIFICATION REQUIRED" in threat_levels:
        overall, verdict = "VERIFICATION REQUIRED", "TLS key-exchange group could not be independently verified; HNDL exposure cannot be assessed."
    elif "CRITICAL" in threat_levels or "BROKEN" in threat_levels:
        overall, verdict = "CRITICAL", "Immediate quantum migration required."
    elif "IMMINENT" in threat_levels:
        overall, verdict = "IMMINENT", "Quantum threat is imminent. Begin PQC migration immediately."
    elif "HIGH" in threat_levels:
        overall, verdict = "HIGH", "High HNDL risk. Classical algorithms broken within 5-10 years."
    elif "MEDIUM" in threat_levels:
        overall, verdict = "MEDIUM", "Moderate HNDL risk. Plan PQC migration within 2-3 years."
    elif any(t == "QUANTUM SAFE" for t in threat_levels):
        overall, verdict = "SAFE", "Post-quantum algorithms deployed. Protected against HNDL."
    else:
        overall, verdict = "LOW", "Low quantum threat to symmetric algorithms."

    return {
        "overall_threat": overall, "verdict": verdict, "timeline": timeline_entries,
        "data_shelf_life": "10+ years" if is_pqc else "5-8 years (estimated safe window)",
        "recommended_action": "Maintain PQC deployment" if is_pqc else "Deploy ML-KEM-768 + ML-DSA-65 immediately",
    }


# ── Compliance Evaluation ──────────────────────────────────────────────────
def evaluate_compliance(raw: dict, pqc: dict, risk: dict, headers_audit: dict) -> dict:
    tls_ver = raw.get("tls_version") or ""
    is_pqc = pqc.get("pqc_safe", False)
    score = risk.get("score", 0)
    hsts = raw.get("hsts", False)
    cert_days = raw.get("cert_days_left") or 999
    cert_expired = raw.get("cert_expired", False)
    cipher = (raw.get("cipher_suite") or "").upper()
    cert_bits = raw.get("cert_pubkey_bits") or 2048
    hdr_score = headers_audit.get("score", 0)

    check_results = {
        "tls_version": tls_ver in ("TLSv1.3", "TLSv1.2"),
        "cipher_strength": not any(d in cipher for d in DEPRECATED_CIPHERS) and cert_bits >= 2048,
        "cert_validity": not cert_expired and cert_days > 30,
        "cert_chain": not raw.get("cert_self_signed", False),
        "key_strength": cert_bits >= 2048,
        "key_rotation": cert_days < 365,
        "pqc_readiness": is_pqc,
        "cve_scan": score >= 70,
        "cipher_audit": not any(d in cipher for d in DEPRECATED_CIPHERS),
        "hsts": hsts,
        "security_headers": hdr_score >= 5,
        "asset_inventory": True, "cbom": True,
        "incident_response": True, "logging": True,
    }

    frameworks_result = {}
    for fw_id, fw_data in COMPLIANCE_FRAMEWORKS.items():
        controls = []
        passed = 0
        total = len(fw_data["controls"])
        for ctrl in fw_data["controls"]:
            ctrl_pass = all(check_results.get(c, False) for c in ctrl["checks"])
            if ctrl_pass:
                passed += 1
            controls.append({"id": ctrl["id"], "requirement": ctrl["requirement"],
                             "status": "PASS" if ctrl_pass else "FAIL", "checks": ctrl["checks"]})
        pct = round((passed / max(total, 1)) * 100)
        frameworks_result[fw_id] = {
            "name": fw_data["name"], "passed": passed, "total": total, "percentage": pct,
            "status": "COMPLIANT" if pct >= 80 else "PARTIAL" if pct >= 50 else "NON-COMPLIANT",
            "controls": controls,
        }
    return frameworks_result


# ── Crypto Agility ─────────────────────────────────────────────────────────
def calculate_crypto_agility(raw: dict, pqc: dict, risk: dict) -> dict:
    score = 0
    factors = []
    tls_ver = raw.get("tls_version") or ""
    cipher = (raw.get("cipher_suite") or "").upper()
    kex = (raw.get("kex_algorithm") or "").upper()
    is_pqc = pqc.get("pqc_safe", False)
    is_hybrid = pqc.get("is_hybrid", False)

    if tls_ver == "TLSv1.3":
        score += 30; factors.append({"factor": "TLS 1.3 Support", "score": 30, "max": 30, "status": "READY", "detail": "TLS 1.3 detected — optimal handshake security and performance."})
    elif tls_ver == "TLSv1.2":
        score += 15; factors.append({"factor": "TLS 1.3 Support", "score": 15, "max": 30, "status": "PARTIAL", "detail": "TLS 1.2 in use. Upgrade to TLS 1.3 for improved security and speed."})
    else:
        factors.append({"factor": "TLS 1.3 Support", "score": 0, "max": 30, "status": "BLOCKED", "detail": f"Outdated protocol {tls_ver or 'unknown'} detected. Immediate upgrade required."})

    if kex in ("ECDHE", "X25519") or is_pqc:
        score += 20; factors.append({"factor": "Forward Secrecy", "score": 20, "max": 20, "status": "READY", "detail": f"{'PQC KEM' if is_pqc else kex} provides ephemeral key exchange — session keys cannot be retroactively decrypted."})
    elif kex == "DHE":
        score += 10; factors.append({"factor": "Forward Secrecy", "score": 10, "max": 20, "status": "PARTIAL", "detail": "DHE provides forward secrecy but is slower than ECDHE. Consider upgrading to X25519 or a PQC KEM."})
    else:
        factors.append({"factor": "Forward Secrecy", "score": 0, "max": 20, "status": "BLOCKED", "detail": f"KEX algorithm {kex or 'unknown'} does not provide forward secrecy. Replace with ECDHE or PQC KEM."})

    if "GCM" in cipher or "CHACHA20" in cipher:
        score += 15; factors.append({"factor": "AEAD Ciphers", "score": 15, "max": 15, "status": "READY", "detail": "AEAD cipher suite in use — provides authenticated encryption preventing tampering."})
    elif "CBC" in cipher:
        score += 5; factors.append({"factor": "AEAD Ciphers", "score": 5, "max": 15, "status": "PARTIAL", "detail": "CBC mode cipher detected. Migrate to AES-GCM or ChaCha20-Poly1305 for AEAD protection."})
    else:
        factors.append({"factor": "AEAD Ciphers", "score": 0, "max": 15, "status": "BLOCKED", "detail": "No recognised AEAD cipher detected. Switch to AES-256-GCM or ChaCha20-Poly1305."})

    cert_bits = raw.get("cert_pubkey_bits") or 0
    if cert_bits >= 3072:
        score += 10; factors.append({"factor": "Cert Key Strength", "score": 10, "max": 10, "status": "READY", "detail": f"{cert_bits}-bit key meets NIST post-2030 recommendation for classical algorithms."})
    elif cert_bits >= 2048:
        score += 7; factors.append({"factor": "Cert Key Strength", "score": 7, "max": 10, "status": "PARTIAL", "detail": f"{cert_bits}-bit key is acceptable but upgrade to ≥3072 bits (or PQC) before 2030."})
    else:
        factors.append({"factor": "Cert Key Strength", "score": 0, "max": 10, "status": "BLOCKED", "detail": f"{cert_bits}-bit key is below minimum security threshold. Replace certificate immediately."})

    if raw.get("hsts", False):
        score += 5; factors.append({"factor": "HSTS", "score": 5, "max": 5, "status": "READY", "detail": "HTTP Strict Transport Security enforced — browsers will always use HTTPS."})
    else:
        factors.append({"factor": "HSTS", "score": 0, "max": 5, "status": "BLOCKED", "detail": "HSTS header missing. Add Strict-Transport-Security to prevent downgrade attacks."})

    if is_pqc and not is_hybrid:
        score += 20; factors.append({"factor": "PQC Deployment", "score": 20, "max": 20, "status": "COMPLETE", "detail": "Full post-quantum cryptography deployed — protected against harvest-now-decrypt-later attacks."})
    elif is_hybrid:
        score += 15; factors.append({"factor": "PQC Deployment", "score": 15, "max": 20, "status": "IN PROGRESS", "detail": "Hybrid PQC + classical KEM active — transitional protection in place. Complete migration to pure PQC."})
    else:
        factors.append({"factor": "PQC Deployment", "score": 0, "max": 20, "status": "NOT STARTED", "detail": "No PQC algorithms detected. Vulnerable to harvest-now-decrypt-later. Deploy ML-KEM-768 or higher."})

    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50 else "D" if score >= 30 else "F"
    return {
        "agility_score": score, "max_score": 100, "grade": grade, "factors": factors,
        "migration_difficulty": "None" if score >= 95 else "Easy" if score >= 80 else "Moderate" if score >= 60 else "Hard" if score >= 40 else "Very Hard",
        "estimated_migration_time": "Complete" if score >= 95 else "1-2 weeks" if score >= 80 else "1-3 months" if score >= 60 else "3-6 months" if score >= 40 else "6-12 months",
    }


# ── DNS Security ───────────────────────────────────────────────────────────
def scan_dns_security(host: str) -> dict:
    result = {"host": host, "dns_resolved": False, "ipv4": None, "ipv6": None,
              "caa_records": [], "has_caa": False, "nameservers": [], "mx_records": []}
    try:
        result["ipv4"] = socket.gethostbyname(host)
        result["dns_resolved"] = True
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET6)
        if infos:
            result["ipv6"] = infos[0][4][0]
    except Exception:
        pass
    return result

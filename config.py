"""
AegisGuard PQC Scanner — Configuration & Constants
All static data, algorithm databases, risk weights, CVE intel, compliance frameworks.
"""

import os
import secrets

PROJECT_NAME = "AegisGuard PQC Scanner"
VERSION      = "2.0.0"

# ── Auth Config ────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("AEGIS_SECRET_KEY", secrets.token_hex(32))
TOKEN_EXPIRY_HOURS = 72
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegisguard.db")

# ── Frontend ───────────────────────────────────────────────────────────────
FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")

# ── PQC Algorithms ─────────────────────────────────────────────────────────
PQC_SAFE_ALGORITHMS = [
    "Kyber", "ML-KEM", "MLKEM",
    "Dilithium", "ML-DSA", "MLDSA",
    "Falcon", "FN-DSA", "FNDSA",
    "SPHINCS+", "SPHINCS", "SLH-DSA", "SLHDSA",
    "NTRU", "BIKE", "HQC", "McEliece",
    "X25519MLKEM", "X25519Kyber768",
]

PQC_SIG_NAMES = {"ML-DSA", "SLH-DSA", "FALCON", "MLDSA", "SLHDSA", "FNDSA",
                 "DILITHIUM", "SPHINCS"}

HYBRID_INDICATORS = ["X25519KYBER768", "X25519MLKEM", "X25519+ML-KEM", "P256KYBER", "HYBRID"]

# ── Risk Weights ───────────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "tls_1_0":              40,
    "tls_1_1":              30,
    "tls_1_2":              10,
    "expired_cert":         30,
    "sha1_sig":             20,
    "md5_sig":              50,
    "weak_cipher":          25,
    "quantum_vulnerable_kex": 20,
    "missing_hsts":          5,
    "cert_expiry_warning":   5,
    "classical_cert_sig":    3,
}

# ── Port/Asset Map ─────────────────────────────────────────────────────────
PORT_ASSET_MAP = {
    443:  "Web Server (HTTPS)",
    8443: "Web Server (HTTPS Alt)",
    465:  "Mail Server (SMTPS)",
    587:  "Mail Server (SMTP Submission)",
    993:  "Mail Server (IMAPS)",
    995:  "Mail Server (POP3S)",
    636:  "Directory Server (LDAPS)",
    3389: "Remote Desktop (RDP)",
    853:  "DNS over TLS (DoT)",
    8080: "Web App (HTTP Alt)",
    8888: "API Gateway",
    9443: "API Server (HTTPS)",
}

# ── Classical KEX ──────────────────────────────────────────────────────────
CLASSICAL_KEX = {
    "ECDHE": {"std": "ANSI X9.63", "ks": "~256 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "ECDH":  {"std": "ANSI X9.63", "ks": "~256 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "DHE":   {"std": "RFC 3526",   "ks": "2048 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "DH":    {"std": "RFC 3526",   "ks": "2048 bits (vulnerable)", "rec": "Replace with ML-KEM-768"},
    "RSA":   {"std": "PKCS#1",     "ks": "~256B (vulnerable)",     "rec": "Replace with ML-KEM-1024"},
}

DEPRECATED_CIPHERS = {"RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "RC2", "MD5"}

# ── Known PQC Hosts ────────────────────────────────────────────────────────
# NOTE: Retained only as descriptive/documentation metadata (e.g. for UI
# hints). It is NEVER used to classify a scanned endpoint's KEX — doing so
# would fabricate results for hosts that happen to share a domain suffix.
# Actual classification always comes from KEX_GROUP_CLASSIFICATION below,
# populated only from an OpenSSL-verified probe (see scanner/tls_probe.py).
KNOWN_PQC_HOSTS = {
    "google.com":                ["X25519Kyber768 (Hybrid)"],
    "cloudflare.com":            ["X25519MLKEM768 (Hybrid PQC)"],
    "test.openquantumsafe.org":  ["ML-KEM", "ML-DSA", "SLH-DSA"],
    "pq.cloudflareresearch.com": ["X25519MLKEM768"],
}

# ── Verified TLS Key-Exchange NamedGroup Classification (Research-Grade) ────
# Centralized, single source of truth mapping an EXPLICITLY OBSERVED
# NamedGroup (from OpenSSL's "Server Temp Key" line, or a verified
# static-RSA suite) to a classification. Absence from this table always
# means "Unknown" — classification is never inferred for unlisted values.
# Add new algorithms here only; do not duplicate this logic elsewhere.
KEX_GROUP_CLASSIFICATION = {
    # Classical
    "X25519":    "CLASSICAL",
    "X448":      "CLASSICAL",
    "SECP256R1": "CLASSICAL",
    "SECP384R1": "CLASSICAL",
    "SECP521R1": "CLASSICAL",
    "RSA":       "CLASSICAL",
    # Hybrid PQC (classical curve + PQC KEM combined)
    "X25519MLKEM768":    "HYBRID_PQC",
    "SECP256R1MLKEM768": "HYBRID_PQC",
    # Pure PQC
    "MLKEM768":  "PQC",
    "MLKEM1024": "PQC",
}

# Confidence is HIGH whenever the group was matched against the table above
# (i.e. explicitly observed and recognized); UNKNOWN whenever it was not.
PQC_CONFIDENCE_BY_STATUS = {
    "NOT_VERIFIED": "UNKNOWN",
    "CLASSICAL":    "HIGH",
    "HYBRID_PQC":   "HIGH",
    "PQC":          "HIGH",
}

# ── CVE Intelligence Database ──────────────────────────────────────────────
CVE_DATABASE = [
    {"id": "CVE-2014-3566", "name": "POODLE", "severity": "HIGH", "cvss": 7.5,
     "affects": ["SSLv3", "TLS_CBC"], "description": "Padding Oracle On Downgraded Legacy Encryption — allows man-in-the-middle attackers to obtain cleartext data via padding-oracle attack against CBC-mode ciphers.",
     "remediation": "Disable SSLv3 entirely. Prefer TLS 1.2+ with AEAD ciphers (AES-GCM, ChaCha20).",
     "year": 2014, "cwe": "CWE-310"},
    {"id": "CVE-2014-0160", "name": "Heartbleed", "severity": "CRITICAL", "cvss": 9.8,
     "affects": ["OpenSSL_1.0.1"], "description": "Buffer over-read in OpenSSL TLS heartbeat extension allows remote attackers to read server memory.",
     "remediation": "Upgrade OpenSSL to 1.0.1g or later. Revoke and reissue all certificates.",
     "year": 2014, "cwe": "CWE-126"},
    {"id": "CVE-2011-3389", "name": "BEAST", "severity": "MEDIUM", "cvss": 5.9,
     "affects": ["TLSv1.0", "TLS_CBC"], "description": "Browser Exploit Against SSL/TLS — CBC-mode vulnerability in TLS 1.0.",
     "remediation": "Upgrade to TLS 1.1+ or use RC4 as workaround (deprecated). Best: TLS 1.2+ with AEAD.",
     "year": 2011, "cwe": "CWE-326"},
    {"id": "CVE-2016-0800", "name": "DROWN", "severity": "HIGH", "cvss": 7.5,
     "affects": ["SSLv2"], "description": "Decrypting RSA with Obsolete and Weakened eNcryption — SSLv2 cross-protocol attack.",
     "remediation": "Disable SSLv2 on all servers sharing RSA keys.",
     "year": 2016, "cwe": "CWE-310"},
    {"id": "CVE-2013-0169", "name": "Lucky13", "severity": "MEDIUM", "cvss": 5.9,
     "affects": ["TLS_CBC"], "description": "Timing side-channel attack on CBC-mode ciphers in TLS/DTLS.",
     "remediation": "Migrate to AEAD cipher suites (AES-GCM, ChaCha20-Poly1305).",
     "year": 2013, "cwe": "CWE-203"},
    {"id": "CVE-2017-13099", "name": "ROBOT", "severity": "HIGH", "cvss": 7.5,
     "affects": ["RSA_KEX"], "description": "Return Of Bleichenbacher's Oracle Threat — RSA key exchange vulnerable.",
     "remediation": "Disable RSA key exchange. Use ECDHE or DHE for forward secrecy.",
     "year": 2017, "cwe": "CWE-203"},
    {"id": "CVE-2015-0204", "name": "FREAK", "severity": "HIGH", "cvss": 7.5,
     "affects": ["EXPORT"], "description": "Factoring RSA Export Keys — forces use of weak 512-bit export-grade RSA keys.",
     "remediation": "Disable all EXPORT cipher suites. Enforce minimum 2048-bit RSA keys.",
     "year": 2015, "cwe": "CWE-310"},
    {"id": "CVE-2015-4000", "name": "Logjam", "severity": "HIGH", "cvss": 7.5,
     "affects": ["DHE_WEAK"], "description": "Weak Diffie-Hellman parameters allow man-in-the-middle downgrade attacks.",
     "remediation": "Use DH groups of 2048 bits or larger. Prefer ECDHE. Best: ML-KEM.",
     "year": 2015, "cwe": "CWE-310"},
    {"id": "CVE-2016-2107", "name": "OpenSSL AES-NI Padding Oracle", "severity": "HIGH", "cvss": 7.5,
     "affects": ["TLS_CBC", "AES_CBC"], "description": "Padding oracle in AES-NI CBC MAC check.",
     "remediation": "Update OpenSSL. Disable CBC-mode ciphers. Use AES-GCM or ChaCha20-Poly1305.",
     "year": 2016, "cwe": "CWE-310"},
    {"id": "CVE-2020-13777", "name": "GnuTLS Session Ticket", "severity": "HIGH", "cvss": 7.4,
     "affects": ["TLS_SESSION"], "description": "GnuTLS failed to verify session ticket HMAC.",
     "remediation": "Update GnuTLS library. Rotate session ticket keys regularly.",
     "year": 2020, "cwe": "CWE-287"},
    {"id": "QUANTUM-HNDL-2024", "name": "Harvest Now Decrypt Later", "severity": "CRITICAL", "cvss": 10.0,
     "affects": ["RSA_KEX", "ECDHE", "DHE", "DH", "ECDH", "NO_PQC"], "description": "Nation-state adversaries can intercept and store encrypted traffic today, then decrypt it once quantum computers become available.",
     "remediation": "Deploy NIST FIPS 203 ML-KEM-768 for key exchange. Use hybrid X25519+ML-KEM during transition.",
     "year": 2024, "cwe": "CWE-327"},
    {"id": "CVE-2022-4304", "name": "OpenSSL Timing Oracle in RSA", "severity": "MEDIUM", "cvss": 5.9,
     "affects": ["RSA_KEX"], "description": "Timing-based side channel in RSA decryption.",
     "remediation": "Update OpenSSL to 3.0.8+. Disable RSA key exchange entirely.",
     "year": 2022, "cwe": "CWE-203"},
    {"id": "CVE-2021-3449", "name": "NULL Pointer Deref in TLS", "severity": "HIGH", "cvss": 7.5,
     "affects": ["TLS_RENEGOTIATION"], "description": "Malicious renegotiation extension causes server crash.",
     "remediation": "Update OpenSSL. Disable TLS renegotiation where possible.",
     "year": 2021, "cwe": "CWE-476"},
]

# ── Quantum Threat Timeline ───────────────────────────────────────────────
QUANTUM_THREAT_TIMELINE = {
    "RSA-1024":  {"years_to_break": "< 5",  "threat_level": "IMMINENT",  "nist_deadline": "2026", "qubits_needed": "~2000 logical"},
    "RSA-2048":  {"years_to_break": "5-10",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~4000 logical"},
    "RSA-3072":  {"years_to_break": "7-12",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~6000 logical"},
    "RSA-4096":  {"years_to_break": "8-15",  "threat_level": "MEDIUM",    "nist_deadline": "2035", "qubits_needed": "~8000 logical"},
    "ECDH-P256": {"years_to_break": "5-10",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~2300 logical"},
    "ECDH-P384": {"years_to_break": "7-12",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~3500 logical"},
    "ECDHE":     {"years_to_break": "5-10",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~2300 logical"},
    "DHE-2048":  {"years_to_break": "5-10",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~4000 logical"},
    "AES-128":   {"years_to_break": "15-25", "threat_level": "LOW",       "nist_deadline": "2040", "qubits_needed": "~2^64 (Grover)"},
    "AES-256":   {"years_to_break": "30+",   "threat_level": "SAFE",      "nist_deadline": "N/A",  "qubits_needed": "~2^128 (Grover)"},
    "ML-KEM":    {"years_to_break": "∞",     "threat_level": "QUANTUM SAFE", "nist_deadline": "N/A", "qubits_needed": "N/A — lattice-based"},
    "ML-DSA":    {"years_to_break": "∞",     "threat_level": "QUANTUM SAFE", "nist_deadline": "N/A", "qubits_needed": "N/A — lattice-based"},
    "SLH-DSA":   {"years_to_break": "∞",     "threat_level": "QUANTUM SAFE", "nist_deadline": "N/A", "qubits_needed": "N/A — hash-based"},
    "X25519":    {"years_to_break": "5-10",  "threat_level": "HIGH",      "nist_deadline": "2030", "qubits_needed": "~2300 logical"},
    "SHA-1":     {"years_to_break": "BROKEN","threat_level": "CRITICAL",  "nist_deadline": "2013", "qubits_needed": "Classical collision"},
    "SHA-256":   {"years_to_break": "20+",   "threat_level": "LOW",       "nist_deadline": "N/A",  "qubits_needed": "~2^128 (Grover)"},
    "3DES":      {"years_to_break": "BROKEN","threat_level": "CRITICAL",  "nist_deadline": "2023", "qubits_needed": "Classical Sweet32"},
}

# ── Security Headers Database ──────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security":   {"priority": "CRITICAL", "description": "HSTS — forces HTTPS connections", "recommended": "max-age=31536000; includeSubDomains; preload"},
    "Content-Security-Policy":     {"priority": "HIGH",     "description": "Prevents XSS, clickjacking, code injection", "recommended": "default-src 'self'; script-src 'self'"},
    "X-Content-Type-Options":      {"priority": "MEDIUM",   "description": "Prevents MIME-type sniffing attacks", "recommended": "nosniff"},
    "X-Frame-Options":             {"priority": "MEDIUM",   "description": "Prevents clickjacking via iframe", "recommended": "DENY"},
    "Referrer-Policy":             {"priority": "MEDIUM",   "description": "Controls referrer information", "recommended": "strict-origin-when-cross-origin"},
    "Permissions-Policy":          {"priority": "MEDIUM",   "description": "Controls browser feature access", "recommended": "geolocation=(), microphone=(), camera=()"},
    "X-XSS-Protection":           {"priority": "LOW",      "description": "Legacy XSS filter", "recommended": "1; mode=block"},
    "Cross-Origin-Opener-Policy":  {"priority": "MEDIUM",   "description": "Isolates browsing context", "recommended": "same-origin"},
    "Cross-Origin-Resource-Policy":{"priority": "MEDIUM",   "description": "Restricts cross-origin resource loading", "recommended": "same-origin"},
    "Cross-Origin-Embedder-Policy":{"priority": "LOW",      "description": "Prevents loading cross-origin resources without CORS", "recommended": "require-corp"},
}

# ── Compliance Frameworks ──────────────────────────────────────────────────
COMPLIANCE_FRAMEWORKS = {
    "RBI-CSCRF-2024": {
        "name": "RBI Cyber Security & Cyber Resilience Framework",
        "controls": [
            {"id": "RBI-CSCRF-4.3", "requirement": "Encryption of data in transit using TLS 1.2+", "checks": ["tls_version"]},
            {"id": "RBI-CSCRF-4.5", "requirement": "PKI infrastructure and certificate management", "checks": ["cert_validity", "cert_chain"]},
            {"id": "RBI-CSCRF-5.1", "requirement": "Cryptographic key management lifecycle", "checks": ["key_strength", "key_rotation"]},
            {"id": "RBI-CSCRF-6.2", "requirement": "Quantum-resistant cryptography readiness", "checks": ["pqc_readiness"]},
            {"id": "RBI-CSCRF-7.1", "requirement": "Vulnerability assessment and penetration testing", "checks": ["cve_scan", "cipher_audit"]},
        ]
    },
    "CERT-IN-2023": {
        "name": "CERT-In Cybersecurity Directions 2023",
        "controls": [
            {"id": "CERT-IN-DIR-1", "requirement": "Report cyber incidents within 6 hours", "checks": ["incident_response"]},
            {"id": "CERT-IN-DIR-3", "requirement": "Enable and maintain logs for 180 days", "checks": ["logging"]},
            {"id": "CERT-IN-DIR-5", "requirement": "Maintain asset inventory with crypto posture", "checks": ["asset_inventory", "cbom"]},
        ]
    },
    "PCI-DSS-4.0": {
        "name": "Payment Card Industry Data Security Standard v4.0",
        "controls": [
            {"id": "PCI-DSS-2.2.7", "requirement": "Strong cryptography for admin access", "checks": ["tls_version", "cipher_strength"]},
            {"id": "PCI-DSS-4.2.1", "requirement": "Strong cryptography for cardholder data", "checks": ["tls_version", "pqc_readiness"]},
            {"id": "PCI-DSS-6.2.4", "requirement": "Protection against known vulnerabilities", "checks": ["cve_scan"]},
            {"id": "PCI-DSS-12.3.3","requirement": "Cryptographic cipher suites inventory", "checks": ["cbom"]},
        ]
    },
    "ISO-27001-2022": {
        "name": "ISO/IEC 27001:2022 Information Security",
        "controls": [
            {"id": "ISO-A.8.24", "requirement": "Use of cryptography — policy and key management", "checks": ["key_strength", "cipher_strength"]},
            {"id": "ISO-A.8.20", "requirement": "Network security controls", "checks": ["tls_version", "hsts"]},
            {"id": "ISO-A.8.9",  "requirement": "Configuration management", "checks": ["asset_inventory", "security_headers"]},
        ]
    },
    "NIST-CSF-2.0": {
        "name": "NIST Cybersecurity Framework 2.0",
        "controls": [
            {"id": "NIST-PR.DS-1", "requirement": "Data-at-rest and data-in-transit protection", "checks": ["tls_version", "cipher_strength"]},
            {"id": "NIST-PR.DS-2", "requirement": "Cryptographic mechanisms for data integrity", "checks": ["cert_validity", "hsts"]},
            {"id": "NIST-ID.AM-1", "requirement": "Physical and software asset inventory", "checks": ["asset_inventory", "cbom"]},
            {"id": "NIST-PR.IP-1", "requirement": "Security configuration baselines", "checks": ["security_headers", "tls_version"]},
        ]
    },
    "SEBI-CSCRF-2024": {
        "name": "SEBI Cybersecurity & Cyber Resilience Framework",
        "controls": [
            {"id": "SEBI-5.3.1", "requirement": "Encryption standards for market data", "checks": ["tls_version", "cipher_strength"]},
            {"id": "SEBI-5.5.2", "requirement": "Cryptographic inventory and lifecycle", "checks": ["cbom", "cert_validity"]},
            {"id": "SEBI-6.1.1", "requirement": "Post-quantum cryptography migration", "checks": ["pqc_readiness"]},
        ]
    },
}

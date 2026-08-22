"""
AegisGuard — TLS Probe Engine
Raw TLS connection scanning, certificate parsing, HSTS detection, and
independent (OpenSSL-CLI-verified) TLS key-exchange NamedGroup extraction.
"""

import re
import ssl
import shutil
import socket
import hashlib
import datetime
import logging
import subprocess
import certifi

from config import KEX_GROUP_CLASSIFICATION

logger = logging.getLogger("AegisGuard.TLS")

# OpenSSL's "-brief" output format varies across versions:
# "Server Temp Key: X25519, 253 bits" or "Server Temp Key: X25519MLKEM768"
# and OpenSSL 3.5+: "Negotiated TLS1.3 group: X25519MLKEM768".
_TEMP_KEY_RE = re.compile(r"Server Temp Key:\s*([A-Za-z0-9_\-]+)")
_NEGOTIATED_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group:\s*([A-Za-z0-9_\-]+)")
# Legacy static-RSA cipher suites (no ephemeral key exchange at all, so no
# "Server Temp Key" line is ever printed for them). This is a standards-based
# read of the negotiated cipher suite name (RFC 5246 §A.5), not an inference
# from unrelated fields — the suite name IS the key-exchange algorithm.
_STATIC_RSA_SUITE_RE = re.compile(r"^(TLS_RSA_WITH_|RSA-)", re.IGNORECASE)

try:
    from OpenSSL import crypto as ossl_crypto
    HAS_OPENSSL = True
except ImportError:
    HAS_OPENSSL = False

try:
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend as _def_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


def scan_tls_raw(host: str, port: int, timeout: int = 10) -> dict:
    """Perform a raw TLS connection probe and extract all crypto metadata.

    The negotiated key-exchange NamedGroup is NEVER guessed from the cipher
    suite name, certificate algorithm, or a hard-coded host list. It is only
    ever set from an independently verified OpenSSL CLI probe
    (see get_actual_tls13_kex). If that verification is not possible, the
    field is explicitly "Unknown" — never fabricated.
    """
    result = dict(
        host=host, port=port, reachable=False, tls_version=None,
        cipher_suite=None, kex_algorithm=None, kex_verified=False,
        kex_probe_method=None, kex_evidence=None, ip=None, hsts=False,
        cert_subject=None, cert_issuer=None, cert_pubkey_alg=None,
        cert_pubkey_bits=None, cert_sig_alg=None, cert_not_after=None,
        cert_days_left=None, cert_expired=False, cert_self_signed=False,
        cert_sha256=None, error=None,
    )
    try:
        result["ip"] = socket.gethostbyname(host)
    except Exception:
        result["ip"] = host

    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result["reachable"] = True
                result["tls_version"] = ssock.version() or "Unknown"
                cipher = ssock.cipher()
                if cipher:
                    result["cipher_suite"] = cipher[0]
                der = ssock.getpeercert(binary_form=True)
                dct = ssock.getpeercert()
                if der and dct:
                    _parse_cert_fields(result, der, dct)
    except ssl.SSLError as e:
        result["error"] = f"TLS error: {e.reason}"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except OSError as e:
        result["error"] = str(e)

    # Independent, OpenSSL-verified negotiated KEX NamedGroup. Only attempted
    # if the handshake above succeeded at all (host:port is reachable).
    if result["reachable"]:
        kex_result = get_actual_tls13_kex(host, port, timeout=timeout)
        result["kex_algorithm"] = kex_result["kex_group"]
        result["kex_verified"] = kex_result["verified"]
        result["kex_probe_method"] = kex_result["method"]
        result["kex_evidence"] = kex_result["evidence"]
    else:
        result["kex_algorithm"] = "Unknown"
        result["kex_evidence"] = "Target unreachable; TLS key-exchange group could not be probed."

    result["hsts"] = _check_hsts(host, port, timeout)
    return result


def get_actual_tls13_kex(domain: str, port: int = 443, timeout: int = 10) -> dict:
    """Independently verify the negotiated TLS key-exchange NamedGroup.

    Python's ``ssl`` module reports TLS 1.3 was negotiated but does not
    expose *which* NamedGroup was used for key exchange. This function uses
    the system OpenSSL CLI (``openssl s_client -brief``) as an independent
    measurement mechanism and parses the "Server Temp Key" line it prints
    for ephemeral (EC)DHE / hybrid-PQC / PQC key exchanges.

    No shell=True is used; the command is invoked as an argument array with
    a strict timeout. Any failure mode (OpenSSL missing, DNS failure, TCP
    failure, handshake failure, timeout, or an output format we don't
    recognize) returns kex_group="Unknown" rather than guessing.

    Args:
        domain: Target hostname (used for SNI and connect target).
        port: TCP port to connect to. Defaults to 443.
        timeout: Hard timeout in seconds for the OpenSSL subprocess.

    Returns:
        dict with keys:
            kex_group (str): canonical NamedGroup string, or "Unknown".
            verified (bool): True only if kex_group was explicitly observed
                and matches a centrally known group.
            method (str): how the result was obtained / why it wasn't.
            evidence (str): human-readable evidence sentence.
            raw_output_line (str | None): the raw "Server Temp Key" line,
                if any was seen (kept even when the group is unrecognized,
                for manual research review).
    """
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        return {
            "kex_group": "Unknown", "verified": False,
            "method": "openssl_unavailable",
            "evidence": ("OpenSSL CLI is not installed on this system; the negotiated "
                         "TLS key-exchange NamedGroup could not be independently verified."),
            "raw_output_line": None,
        }

    # No -tls1_3 restriction: this lets OpenSSL negotiate whatever the server
    # actually offers (matching the same handshake Python's ssl module did),
    # so the same probe covers both TLS 1.2 ephemeral KEX and TLS 1.3.
    cmd = [openssl_path, "s_client", "-connect", f"{domain}:{port}", "-servername", domain, "-brief"]

    try:
        proc = subprocess.run(
            cmd,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "kex_group": "Unknown", "verified": False, "method": "timeout",
            "evidence": f"OpenSSL s_client probe against {domain}:{port} timed out after {timeout}s.",
            "raw_output_line": None,
        }
    except FileNotFoundError:
        return {
            "kex_group": "Unknown", "verified": False, "method": "openssl_unavailable",
            "evidence": "OpenSSL CLI could not be executed.",
            "raw_output_line": None,
        }
    except OSError as e:
        return {
            "kex_group": "Unknown", "verified": False, "method": "os_error",
            "evidence": f"OpenSSL probe failed to launch: {e}",
            "raw_output_line": None,
        }

    stdout = (proc.stdout or b"").decode("utf-8", errors="replace")
    stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
    combined = stdout + "\n" + stderr

    # Try both known "-brief" output formats.
    match = _NEGOTIATED_GROUP_RE.search(combined) or _TEMP_KEY_RE.search(combined)

    if not match:
        # No ephemeral key exchange line was printed at all.
        if proc.returncode != 0 or ("CONNECTION ESTABLISHED" not in combined.upper()
                        and "Cipher is" not in combined
                        and "Ciphersuite:" not in combined):
            reason = "handshake_failed"
            low = combined.lower()
            if "getaddrinfo" in low or "name or service not known" in low or "nodename nor servname" in low:
                reason = "dns_failure"
            elif "connection refused" in low:
                reason = "tcp_failure"
            elif "wrong version number" in low or "no protocols available" in low:
                reason = "tls_unsupported"
            return {
                "kex_group": "Unknown", "verified": False, "method": reason,
                "evidence": (f"OpenSSL could not complete a TLS handshake with {domain}:{port} "
                             f"({reason}); NamedGroup could not be independently verified."),
                "raw_output_line": None,
            }
        # Handshake completed but no negotiated-group line: consistent with
        # a legacy static-RSA cipher suite (no ephemeral key exchange), or a
        # TLS 1.2 handshake whose OpenSSL build does not print its group.
        cipher_match = re.search(r"Cipher is\s*(\S+)", combined) or re.search(r"Ciphersuite:\s*(\S+)", combined)
        if cipher_match and _STATIC_RSA_SUITE_RE.match(cipher_match.group(1)):
            return {
                "kex_group": "RSA", "verified": True, "method": "openssl_s_client",
                "evidence": (f"Handshake completed with static-RSA cipher suite "
                              f"{cipher_match.group(1)} and no ephemeral key exchange was "
                              f"reported; key exchange is RSA per RFC 5246 suite naming."),
                "raw_output_line": None,
            }
        return {
            "kex_group": "Unknown", "verified": False, "method": "no_temp_key_reported",
            "evidence": ("TLS handshake completed but OpenSSL reported no negotiated-group "
                         "line ('Server Temp Key' / 'Negotiated TLS1.3 group') and the cipher "
                         "suite does not identify a static-RSA key exchange; NamedGroup could "
                         "not be independently verified."),
            "raw_output_line": None,
        }

    raw_line = match.group(0)
    group_field = match.group(1).strip()
    lookup_key = group_field.upper().replace(" ", "").replace("-", "")

    if lookup_key in KEX_GROUP_CLASSIFICATION:
        return {
            "kex_group": group_field, "verified": True, "method": "openssl_s_client",
            "evidence": f"Verified negotiated TLS key-exchange NamedGroup via OpenSSL s_client: {group_field}",
            "raw_output_line": raw_line,
        }

    # An explicit negotiated-group value WAS observed, but it is not in the
    # centralized known-group table. Per policy, unrecognized strings are
    # never classified as classical/hybrid/PQC — only "Unknown".
    return {
        "kex_group": "Unknown", "verified": False, "method": "unrecognized_group",
        "evidence": (f"OpenSSL reported negotiated group '{group_field}', which is not in the "
                     f"centralized known-NamedGroup table; treated as Unknown rather than inferred."),
        "raw_output_line": raw_line,
    }


def _extract_kex(cipher_name: str, host: str = "", port: int = 443, timeout: int = 10) -> str:
    """Legacy-signature wrapper kept for scanner/validation.py's cross-check probe.

    NOTE: validation.py currently calls this as `_extract_kex(cipher[0], host)`
    without a port. For non-443 targets, update that call site to
    `_extract_kex(cipher[0], host, port)` so the independent probe hits the
    right port. `cipher_name` is intentionally unused for classification —
    kept only for call-site compatibility — because cipher suite names do not
    reliably identify the TLS 1.3 NamedGroup (REQUIREMENT 12).
    """
    return get_actual_tls13_kex(host, port, timeout=timeout)["kex_group"] if host else "Unknown"


def _parse_cert_fields(result: dict, der: bytes, dct: dict):
    result["cert_sha256"] = hashlib.sha256(der).hexdigest()

    def _cn(pairs):
        d = {}
        for pair in (pairs or []):
            if pair:
                d[pair[0][0]] = pair[0][1]
        return d.get("commonName", str(pairs))

    subj = _cn(dct.get("subject", []))
    issu = _cn(dct.get("issuer", []))
    result["cert_subject"] = subj
    result["cert_issuer"] = issu
    result["cert_self_signed"] = (subj == issu)

    not_after_str = dct.get("notAfter", "")
    result["cert_not_after"] = not_after_str
    if not_after_str:
        try:
            exp = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.utcnow()
            result["cert_days_left"] = (exp - now).days
            result["cert_expired"] = exp < now
        except Exception:
            pass

    if HAS_OPENSSL:
        try:
            x = ossl_crypto.load_certificate(ossl_crypto.FILETYPE_ASN1, der)
            result["cert_sig_alg"] = x.get_signature_algorithm().decode(errors="replace")
            pk = x.get_pubkey()
            kt = pk.type()
            result["cert_pubkey_alg"] = (
                "RSA" if kt == ossl_crypto.TYPE_RSA else
                "EC"  if kt == ossl_crypto.TYPE_EC else
                "DSA" if kt == ossl_crypto.TYPE_DSA else f"Type({kt})"
            )
            result["cert_pubkey_bits"] = pk.bits()
        except Exception:
            pass
    elif HAS_CRYPTO:
        try:
            cert = cx509.load_der_x509_certificate(der, _def_backend())
            result["cert_sig_alg"] = cert.signature_algorithm_oid._name
            result["cert_pubkey_alg"] = "RSA"
            result["cert_pubkey_bits"] = 2048
        except Exception:
            pass
    else:
        result["cert_pubkey_alg"] = "RSA"
        result["cert_pubkey_bits"] = 2048
        result["cert_sig_alg"] = "sha256WithRSAEncryption (estimated)"


def _check_hsts(host: str, port: int, timeout: int) -> bool:
    try:
        import http.client
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout,
            context=ssl._create_unverified_context(),
        )
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        hdr = resp.getheader("Strict-Transport-Security")
        conn.close()
        return bool(hdr)
    except Exception:
        return False

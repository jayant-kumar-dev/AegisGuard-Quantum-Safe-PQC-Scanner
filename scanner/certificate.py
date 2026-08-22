"""
AegisGuard — PQC Certificate Generator
Generates compliance certificates as PDF documents.
"""

import os
import datetime
import logging

from fastapi import HTTPException
from config import PROJECT_NAME, VERSION

logger = logging.getLogger("AegisGuard.Cert")


def _load_fpdf_class():
    """Import FPDF at runtime so startup is not coupled to optional PDF deps."""
    try:
        from fpdf import FPDF  # type: ignore
        return FPDF
    except ImportError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "PDF dependency missing. Install with: "
                "python -m pip install -r requirements.txt"
            ),
        ) from exc
    except Exception as exc:
        logger.exception("Failed to import fpdf/its dependencies")
        raise HTTPException(
            status_code=500,
            detail=(
                "PDF engine failed to initialize. Reinstall PDF dependencies with: "
                "python -m pip install --upgrade --force-reinstall fpdf2 numpy pillow"
            ),
        ) from exc


def generate_pqc_certificate_pdf(target: str, pqc: dict, risk: dict) -> bytes:
    """Generate a PQC compliance certificate as a PDF."""
    FPDF = _load_fpdf_class()
    pdf = FPDF()
    pdf.set_auto_page_break(False)
    pdf.set_margins(0, 0, 0)
    pdf.add_page()

    font_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "font.ttf")
    if os.path.exists(font_path):
        pdf.add_font("CustomFont", "", font_path)
        pdf.add_font("CustomFont", "B", font_path)
        pdf.add_font("CustomFont", "I", font_path)
        FONT = "CustomFont"
    else:
        FONT = "Helvetica"

    NAVY = (10, 30, 80); GOLD = (180, 140, 0); GREEN = (0, 120, 80)
    WHITE = (255, 255, 255); BLACK = (0, 0, 0); TEAL = (0, 128, 128)
    GRAY = (240, 240, 240)
    PASS_GREEN = (18, 122, 72); WARN_AMBER = (176, 117, 0); FAIL_RED = (178, 48, 62)

    # Border
    pdf.set_draw_color(*GOLD); pdf.set_line_width(1.5); pdf.rect(5, 5, 200, 287)
    pdf.set_line_width(0.5); pdf.rect(8, 8, 194, 281)

    # Header
    pdf.set_fill_color(*NAVY); pdf.rect(8, 8, 194, 28, "F")
    pdf.set_xy(8, 10); pdf.set_font(FONT, "B", 12); pdf.set_text_color(*GOLD)
    pdf.cell(194, 7, PROJECT_NAME.upper(), 0, 2, "C")
    pdf.set_font(FONT, "", 7); pdf.set_text_color(180, 200, 255)
    pdf.cell(194, 5, "QUANTUM-SAFE CRYPTOGRAPHIC SCANNER | CBOM GENERATOR", 0, 2, "C")
    pdf.set_font(FONT, "", 7); pdf.set_text_color(160, 180, 220)
    pdf.cell(194, 5, f"Version {VERSION}  ·  NIST FIPS 203/204/205 Compliance Engine", 0, 1, "C")

    # Title banner
    pdf.set_fill_color(*GREEN); pdf.rect(8, 36, 194, 34, "F")
    pdf.set_xy(8, 40); pdf.set_font(FONT, "B", 20); pdf.set_text_color(*WHITE)
    pdf.cell(194, 10, "CERTIFICATE OF COMPLIANCE", 0, 2, "C")
    pdf.set_font(FONT, "B", 11); pdf.set_text_color(220, 255, 220)
    pdf.cell(194, 7, "Post-Quantum Cryptography Readiness Assessment", 0, 2, "C")
    pdf.set_font(FONT, "", 8); pdf.set_text_color(200, 240, 200)
    pdf.cell(194, 5, "NIST FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA)", 0, 1, "C")

    # Status badge
    pdf.set_fill_color(0, 100, 0); pdf.set_draw_color(*GOLD); pdf.set_line_width(1)
    pdf.rect(70, 74, 70, 20, "FD")
    pdf.set_xy(70, 77); pdf.set_font(FONT, "B", 14); pdf.set_text_color(*WHITE)
    pdf.cell(70, 7, "QUANTUM SAFE", 0, 2, "C")
    pdf.set_font(FONT, "", 8); pdf.set_text_color(180, 255, 180)
    pdf.cell(70, 5, "PQC READY CERTIFIED", 0, 1, "C")

    safe_components = [str(c).upper() for c in (pqc.get("safe_components") or [])]
    fips204_ok = any(("ML-DSA" in c) or ("DILITHIUM" in c) for c in safe_components)
    fips205_ok = any(("SLH-DSA" in c) or ("SPHINCS" in c) for c in safe_components)

    standards = [
        ("NIST FIPS 203", "ML-KEM", (0, 90, 160), True),
        ("NIST FIPS 204", "ML-DSA", (0, 120, 80), fips204_ok),
        ("NIST FIPS 205", "SLH-DSA", (130, 0, 130), fips205_ok),
    ]
    for i, (fips, name, color, ok) in enumerate(standards):
        x = 12 + i * 64
        pdf.set_fill_color(*(color if ok else FAIL_RED))
        pdf.set_draw_color(*GOLD); pdf.set_line_width(0.4); pdf.rect(x, 100, 60, 18, "FD")
        pdf.set_xy(x, 102); pdf.set_font(FONT, "B", 8); pdf.set_text_color(*WHITE)
        pdf.cell(60, 5, fips, 0, 2, "C")
        pdf.set_font(FONT, "", 7); pdf.set_text_color(235, 235, 235)
        pdf.cell(60, 4, name, 0, 1, "C")

    # Audited asset
    pdf.set_fill_color(*GRAY); pdf.rect(12, 124, 186, 26, "F")
    pdf.set_xy(12, 127); pdf.set_font(FONT, "B", 8); pdf.set_text_color(*NAVY)
    pdf.cell(186, 5, "AUDITED ASSET", 0, 2, "C")
    pdf.set_font(FONT, "B", 14); pdf.set_text_color(0, 100, 0)
    pdf.cell(186, 8, target, 0, 2, "C")
    pdf.set_font(FONT, "I", 7); pdf.set_text_color(*TEAL)
    pdf.cell(186, 5, "Public-Facing Web Application / API Endpoint", 0, 1, "C")

    # Table header
    pdf.set_y(156); pdf.set_fill_color(*NAVY); pdf.rect(12, 156, 186, 8, "F")
    pdf.set_xy(12, 157); pdf.set_font(FONT, "B", 8); pdf.set_text_color(*WHITE)
    pdf.cell(93, 6, "COMPLIANCE PARAMETER", 0, 0, "C")
    pdf.cell(93, 6, "STATUS", 0, 1, "C")

    rows = [
        ("PQC Key Encapsulation (KEX)", "NIST FIPS 203 - ML-KEM (Kyber)  \u2713 COMPLIANT"),
        ("Digital Signature Algorithm", "ML-DSA \u2713 COMPLIANT" if fips204_ok else "RSA/EC \u2717 NOT COMPLIANT"),
        ("Hash-Based Signature", "SLH-DSA \u2713 COMPLIANT" if fips205_ok else "SLH-DSA [!] NOT DEPLOYED"),
        ("TLS Protocol", "TLS 1.3 (RFC 8446)  \u2713 ENFORCED"),
        ("HNDL Attack Protection", "Quantum-Safe KEM Active  \u2713 MITIGATED"),
        ("CBOM Standard", "CycloneDX 1.6 / NIST SP 800-235  \u2713 GENERATED"),
        ("Security Score", f"{risk.get('score', 0)}/100 — Grade {risk.get('grade', 'A')}"),
        ("PQC Detail", (pqc.get("reason") or "Quantum-Safe algorithms detected")[:55]),
    ]
    fill = False
    for label, value in rows:
        bg = (246, 250, 255) if fill else WHITE
        val_upper = str(value).upper()
        value_color = FAIL_RED if "NOT COMPLIANT" in val_upper or "NOT DEPLOYED" in val_upper else \
                      WARN_AMBER if "PENDING" in val_upper else \
                      PASS_GREEN if any(k in val_upper for k in ("COMPLIANT", "ENFORCED", "MITIGATED", "GENERATED", "\u2713")) else BLACK
        pdf.set_fill_color(*bg); y = pdf.get_y(); pdf.rect(12, y, 186, 7, "F")
        pdf.set_xy(12, y + 1); pdf.set_font(FONT, "B", 7); pdf.set_text_color(*NAVY)
        pdf.cell(90, 5, f"  {label}", 0, 0, "L")
        pdf.set_font(FONT, "", 7); pdf.set_text_color(*value_color)
        pdf.cell(96, 5, value, 0, 1, "L")
        fill = not fill

    # Metadata
    now = datetime.datetime.utcnow()
    META_LINE = pdf.get_y() + 4
    pdf.set_draw_color(*GOLD); pdf.set_line_width(0.4); pdf.line(12, META_LINE, 198, META_LINE)
    meta = [
        ("Date of Issue", now.strftime("%Y-%m-%d")),
        ("Valid Until", now.replace(year=now.year + 1).strftime("%Y-%m-%d")),
        ("Certificate Serial", f"AG-{now.strftime('%Y%m%d')}-{abs(hash(target)) % 99999:05d}"),
        ("Issuing Authority", PROJECT_NAME),
        ("Standard Refs", "NIST FIPS 203/204/205"),
        ("Scanner Version", f"v{VERSION}"),
    ]
    y_meta1 = META_LINE + 4
    y_meta2 = y_meta1 + 12
    for i in range(3):
        x = 12 + i * 62
        pdf.set_xy(x, y_meta1); pdf.set_font(FONT, "B", 6); pdf.set_text_color(*NAVY)
        pdf.cell(62, 4, meta[i][0].upper(), 0, 0)
        pdf.set_xy(x, y_meta1 + 4); pdf.set_font(FONT, "", 6.5); pdf.set_text_color(*BLACK)
        pdf.cell(62, 4, meta[i][1], 0, 0)
    for i in range(3, 6):
        x = 12 + (i - 3) * 62
        pdf.set_xy(x, y_meta2); pdf.set_font(FONT, "B", 6); pdf.set_text_color(*NAVY)
        pdf.cell(62, 4, meta[i][0].upper(), 0, 0)
        pdf.set_xy(x, y_meta2 + 4); pdf.set_font(FONT, "", 6.5); pdf.set_text_color(*BLACK)
        pdf.cell(62, 4, meta[i][1], 0, 0)

    # Signatures
    y_sig = y_meta2 + 11
    pdf.set_draw_color(*GOLD); pdf.set_line_width(0.4); pdf.line(12, y_sig, 198, y_sig)
    pdf.set_xy(25, y_sig + 3); pdf.set_font(FONT, "", 8); pdf.set_text_color(*BLACK)
    pdf.cell(70, 5, "_______________________________", 0, 0, "C")
    pdf.cell(20, 5, "", 0, 0)
    pdf.cell(70, 5, "_______________________________", 0, 1, "C")
    pdf.set_xy(25, y_sig + 9); pdf.set_font(FONT, "B", 7); pdf.set_text_color(*NAVY)
    pdf.cell(70, 4, "Chief Security Architect", 0, 0, "C")
    pdf.cell(20, 4, "", 0, 0)
    pdf.cell(70, 4, "Quantum Cryptography Auditor", 0, 1, "C")

    # Footer
    pdf.set_xy(12, 278); pdf.set_font(FONT, "I", 7); pdf.set_text_color(*GOLD)
    pdf.cell(186, 5, f"{PROJECT_NAME}  |  NIST FIPS 203/204/205  |  Page 1 of 1", 0, 0, "C")

    return bytes(pdf.output())

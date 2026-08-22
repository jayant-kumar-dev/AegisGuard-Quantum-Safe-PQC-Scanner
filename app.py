"""
AegisGuard PQC Scanner v2.0.0 — Main Application
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Modular architecture with:
  • JWT-based login system with scan history per user
  • Segmented codebase: scanner/, auth/, routes/, scan_history/
  • Full PQC scanning pipeline with 13-stage intelligence enrichment

Run:
  pip install fastapi uvicorn pyOpenSSL cryptography fpdf2
  python app.py

Frontend:  http://localhost:8000/
API Docs:  http://localhost:8000/docs
"""

import os
import sys
import socket
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

from config import PROJECT_NAME, VERSION, FRONTEND_DIR
from database import init_db
from services.discovery_service import discovery_job_manager
from services.scheduler_service import init_scheduler, shutdown_scheduler

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-18s │ %(levelname)-7s │ %(message)s",
)
logger = logging.getLogger("AegisGuard")


# ── Lifespan ───────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"{PROJECT_NAME} v{VERSION} — starting up")
    init_db()
    init_scheduler()
    await discovery_job_manager.start()
    yield
    await discovery_job_manager.stop()
    shutdown_scheduler()
    logger.info(f"{PROJECT_NAME} — shutting down")


# ── FastAPI App ────────────────────────────────────────────────────────────
app = FastAPI(
    title=PROJECT_NAME,
    version=VERSION,
    description="Quantum-Safe Cryptographic Scanner — CBOM Generator — PQC Certificate Issuer — Login System",
    lifespan=lifespan,
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Include Routers ────────────────────────────────────────────────────────
from auth.routes import router as auth_router
from routes.scan import router as scan_router
from routes.discovery import router as discovery_router
from routes.reporting import router as reporting_router
from scan_history.routes import router as history_router

app.include_router(auth_router)
app.include_router(scan_router)
app.include_router(discovery_router)
app.include_router(reporting_router)
app.include_router(history_router)


# ── Root & Health ──────────────────────────────────────────────────────────
@app.get("/")
def serve_frontend():
    index = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.isfile(index):
        return FileResponse(index)
    return {"message": f"{PROJECT_NAME} v{VERSION} — API active. Frontend not found."}


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": PROJECT_NAME,
        "version": VERSION,
        "endpoints": {
            "auth": ["/auth/register", "/auth/login", "/auth/me"],
            "scan": ["/scan", "/export", "/scan/bulk", "/scan/test"],
            "cbom": ["/cbom", "/cbom/search"],
            "certificate": ["/certificate"],
            "discovery": ["/discover"],
            "reports": [
                "/report/executive",
                "/report/on-demand",
                "/report/history",
                "/report/scans",
                "/report/{id}",
                "/report/schedule",
                "/report/schedules",
                "/report/{id}/pdf",
                "/report/{id}/json",
            ],
            "history": ["/history", "/history/{scan_id}"],
        },
    }



# Serve favicon (avoid 404 in logs)
@app.get('/favicon.ico')
def serve_favicon():
    ico = os.path.join(FRONTEND_DIR, 'favicon.ico')
    png = os.path.join(FRONTEND_DIR, 'favicon.png')
    if os.path.isfile(ico):
        return FileResponse(ico)
    if os.path.isfile(png):
        return FileResponse(png, media_type='image/png')
    svg = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='100%' height='100%' fill='#0b6e68'/><text x='50%' y='50%' fill='#fff' font-size='18' font-family='Arial' text-anchor='middle' alignment-baseline='central'>A</text></svg>"""
    return Response(content=svg, media_type='image/svg+xml')


# ── Frontend Static Assets (must be last — catches /script.js, /style.css, etc.) ──
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR), name="frontend")
    logger.info(f"Frontend static files mounted from: {FRONTEND_DIR}")
else:
    logger.warning(f"Frontend directory NOT found at: {FRONTEND_DIR}")


# ── Main ───────────────────────────────────────────────────────────────────
def _check_port_available(host: str, port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            return True
    except OSError:
        return False


def _select_available_port(host: str, preferred_port: int, attempts: int = 10) -> int | None:
    """Return the first available port starting from preferred_port within attempts."""
    for candidate in range(preferred_port, preferred_port + max(1, attempts)):
        if _check_port_available(host, candidate):
            return candidate
    return None


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))

    print("=" * 65)
    print(f"  {PROJECT_NAME}  v{VERSION}")
    print("=" * 65)
    print(f"  Frontend:   http://localhost:{port}/")
    print(f"  API Docs:   http://localhost:{port}/docs")
    print()
    print("  Auth Endpoints:")
    print("    POST /auth/register — Create account")
    print("    POST /auth/login    — Login & get token")
    print("    GET  /auth/me       — User profile")
    print()
    print("  Scan Endpoints:")
    print("    POST /scan          — Full PQC scan (auto-saved if logged in)")
    print("    POST /export        — Full scan + export JSON")
    print("    POST /scan/bulk     — Concurrent multi-target scan")
    print("    POST /cbom          — Export CBOM as JSON")
    print("    POST /certificate   — Generate PQC Certificate PDF")
    print("    POST /discover      — Asset discovery")
    print()
    print("  History Endpoints:")
    print("    GET  /history       — Your past scans")
    print("    GET  /history/{id}  — Full scan details")
    print("=" * 65)

    if not os.path.isdir(FRONTEND_DIR):
        print(f"  [WARN] frontend/ not found at {FRONTEND_DIR}")

    selected_port = _select_available_port(host, port, attempts=15)
    if selected_port is None:
        print(f"\n  [ERROR] Could not find a free port from {port} to {port + 14}.")
        sys.exit(1)

    if selected_port != port:
        print(f"\n  [WARN] Port {port} already in use. Falling back to port {selected_port}.")
        print(f"  Frontend:   http://localhost:{selected_port}/")
        print(f"  API Docs:   http://localhost:{selected_port}/docs")
        port = selected_port

    print()
    try:
        uvicorn.run(app, host=host, port=port, log_level="info",
                    timeout_keep_alive=65, access_log=True)
    except KeyboardInterrupt:
        print("\n  Server stopped by user (Ctrl+C)")
    except Exception as e:
        print(f"\n  [FATAL] Server crashed: {e}")
        sys.exit(1)

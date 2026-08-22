# AegisGuard PQC Scanner v2.0.0

**Quantum-Safe Cryptographic Scanner with Login System & Modular Architecture**

## What's New in v2.0.0

### 1. Login System
- **Register/Login** with username, email, password
- **JWT-like token auth** (HMAC-signed, 72h expiry)
- **Per-user scan history** — every scan is saved when logged in
- **Profile endpoint** — view your account details and scan count
- Scans still work without login (just not saved to history)

### 2. Code Segmentation
The monolithic 2400-line `app.py` has been split into **15 focused modules**:

```
AegisGuard_v2/
├── app.py                    ← Slim entry point (wires routers together)
├── config.py                 ← All constants, CVE DB, compliance frameworks
├── database.py               ← SQLite setup (users + scan_history tables)
│
├── auth/                     ← Authentication system
│   ├── utils.py              ← Password hashing, token create/verify
│   ├── models.py             ← Pydantic models (Register, Login, Profile)
│   └── routes.py             ← /auth/register, /auth/login, /auth/me
│
├── scanner/                  ← Core scanning engine (separated by stage)
│   ├── tls_probe.py          ← Stage 1: Raw TLS connection + cert parsing
│   ├── pqc_analyzer.py       ← Stage 2: PQC algorithm detection
│   ├── risk_scorer.py        ← Stage 3: Weighted risk scoring + grading
│   ├── cbom_generator.py     ← Stage 4: CycloneDX 1.6 CBOM generation
│   ├── intelligence.py       ← Stages 5-10: Headers, CVEs, HNDL, compliance
│   ├── certificate.py        ← PQC compliance certificate PDF generation
│   └── pipeline.py           ← Full scan orchestrator + UI response builder
│
├── routes/                   ← API route handlers
│   ├── scan.py               ← /scan, /export, /scan/bulk, /cbom, /certificate
│   └── discovery.py          ← /discover, /report/generate, /report/schedule
│
├── scan_history/             ← Scan history persistence
│   └── routes.py             ← /history (list, view, delete, clear)
│
├── frontend/                 ← Updated with login UI + history tab
│   ├── index.html            ← Added auth modal + scan history tab
│   ├── script.js             ← Added auth logic + history management
│   ├── style.css             ← (unchanged)
│   └── chart.js              ← (unchanged)
│
└── requirements.txt
```

## Quick Start

### Windows PowerShell

```powershell
py -3.14 -m venv .venv314
.\.venv314\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

### One-line Run (without activation)

```powershell
.\.venv314\Scripts\python.exe -u app.py
```

Then open `http://localhost:8000/`

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create new account |
| POST | `/auth/login` | Login, get token |
| GET | `/auth/me` | Get profile (requires token) |

### Scanning
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Full PQC scan (auto-saved if logged in) |
| POST | `/export` | Scan + export JSON |
| POST | `/scan/bulk` | Multi-target concurrent scan |
| POST | `/cbom` | Export CBOM |
| POST | `/certificate` | Generate PQC certificate PDF |
| POST | `/discover` | Start async discovery job (returns job_id) |
| GET | `/status/{job_id}` | Discovery job progress + partial status |
| GET | `/discover/result/{job_id}` | Discovery job final payload |
| POST | `/discover/sync` | Compatibility blocking discovery (bounded wait) |

### History (requires login)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/history/` | List your past scans |
| GET | `/history/{id}` | Full details of a scan |
| DELETE | `/history/{id}` | Delete a scan |
| DELETE | `/history/` | Clear all history |

### Reports
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/report/generate` | Multi-target executive report |
| POST | `/report/schedule` | Schedule recurring reports |

## Authentication Flow

1. **Register**: `POST /auth/register` with `{username, email, password}`
2. **Login**: `POST /auth/login` with `{username, password}`
3. **Use token**: Add `Authorization: Bearer <token>` header to requests
4. **Scans auto-save**: When token is present, scans save to your history
5. **View history**: `GET /history/` shows all your past scans

## Tech Stack
- **Backend**: FastAPI + Uvicorn
- **Database**: SQLite (zero-config, file-based)
- **Auth**: SHA-256 + salt password hashing, HMAC-signed tokens
- **Scanner**: pyOpenSSL, cryptography
- **PDF**: fpdf2
- **Frontend**: Vanilla HTML/CSS/JS + Chart.js

## Discovery Tuning

Subdomain discovery coverage is configured in `scanner/enumeration_config.py`.

- `SUBDOMAIN_LIMIT`: maximum number of discovered hosts returned.
- `RECURSION_DEPTH`: supports multi-level subdomains like `dev.test.example.com`.
- `SUBDOMAIN_WORDLIST`: path to brute-force dictionary (default: `scanner/wordlists/extended_recon_list.txt`).
- `USE_DNS_BRUTEFORCING`: enable/disable active DNS brute-force mode.
- `MAX_THREADS`: concurrency level for DNS resolution attempts.
- `ENABLE_CRTSH_OSINT`: query Certificate Transparency records from crt.sh.
- `ENABLE_HACKERTARGET_OSINT`: query passive host records from HackerTarget.
- `OSINT_TIMEOUT_SECONDS` / `OSINT_RETRIES`: timeout and retry behavior for passive APIs.

The `/discover` response includes `discovered_subdomains` and `domains` entries for the full discovered set, not just TLS-reachable hosts.

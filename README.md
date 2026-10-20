# SENTINEL AI — Phishing & Social Engineering Threat Detector

An advanced full-stack AI-powered phishing detector that inspects URLs, email body text, and raw email headers using heuristic analysis engines and optional Google Gemini AI integration.

---

## 🚀 Features

- **URL Analysis** — Detects typosquatting, brand-jacking, suspicious TLDs, IP-based hosting, excessive subdomains, and insecure protocols
- **Email Text Analysis** — Identifies urgency keywords, social engineering tactics, and embedded malicious links
- **Email Header Analysis** — Validates SPF/DKIM/DMARC authentication and detects From/Return-Path sender spoofing
- **Privacy-first Analysis** — Local-only analysis is the default; external providers require explicit per-scan opt-in
- **Optional External Analysis** — Explicitly opt in per scan to send relevant content/URL indicators to configured threat-intelligence providers or Gemini
- **Scan History** — Server-side, scoped per account or guest session; stores a bounded, sanitized input preview plus the stored analysis result (up to 30 records are listed per request)
- **Cinematic UI** — Dark glassmorphism design with animated scanning overlays and live risk gauges

---

## 📁 Project Structure

```
Ai phishing detector/
├── backend/                  # FastAPI Python backend
│   ├── app/
│   │   ├── main.py           # API routes, rate limiting, and orchestration
│   │   ├── config.py         # Environment configuration
│   │   ├── models/
│   │   │   ├── domain.py     # SQLAlchemy models (User, ScanHistory, ThreatIndicator)
│   │   │   └── schemas.py    # Pydantic request/response models
│   │   └── services/
│   │       ├── url_service.py         # URL heuristic analyzer
│   │       ├── email_service.py       # Email text + header analyzer
│   │       ├── email_auth_service.py  # Standards-aware SPF/DKIM/DMARC parser
│   │       ├── webrisk_service.py     # Google Web Risk Lookup API provider
│   │       ├── threat_feed_service.py # Normalized threat feed layer & lookup
│   │       ├── provider_guard.py      # Provider concurrency & TTL caches
│   │       └── llm_service.py         # Gemini AI integration
│   ├── requirements.txt
│   ├── .env                  # API key configuration
│   └── tests/                # Test suite (114 passed specifications)
│       ├── test_security_hardening.py # Gateway v1.2 security tests
│       ├── test_webrisk.py            # Web Risk provider tests
│       ├── test_email_auth.py         # Email auth parser tests
│       └── test_threat_feeds.py       # Threat feed layer tests
│
└── frontend/                 # React + Vite + TypeScript frontend
    ├── src/
    │   ├── App.tsx            # Main application layout
    │   ├── components/        # UI components (SignalList, ThreatRadar, History)
    │   ├── types.ts           # TypeScript type definitions
    │   └── mockData.ts        # Quick-test sample payloads
    └── package.json
```

---

## ⚙️ Setup & Running

### 1. Backend (FastAPI)

> **Prerequisites:** Python 3.10+ installed, `venv` already set up in `backend/venv/`.

```powershell
# From the project root, activate the virtual environment
cd backend
.\venv\Scripts\activate

# Install / verify dependencies
pip install -r requirements.txt

# Run authoritative database schema migrations
alembic upgrade head

# Start the API server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend will be running at: `http://localhost:8000`

### 2. Frontend (React + Vite)

```powershell
# From the project root
cd frontend

# Install dependencies (if not already done)
npm install

# Start the dev server
npm run dev
```

The frontend will be running at: `http://localhost:5173`

---

## 🚀 Production Deployment & Persistence

| Environment | Database |
|---|---|
| development | SQLite (deterministic local fallback) |
| test | SQLite (deterministic local fallback) |
| production | PostgreSQL (explicit `DATABASE_URL`, fail closed) |

Production **never** falls back to SQLite: startup fails closed when
`DATABASE_URL` is missing, blank, SQLite-based, malformed, or uses an
unsupported scheme. Schema changes are migration-driven only
(`alembic upgrade head`, executed by Render's `preDeployCommand` before the
app starts), and runtime startup performs strictly read-only schema
invariant verification. See **[docs/deployment.md](docs/deployment.md)** for
the full deployment contract (Render Blueprint, `$PORT`, health check,
PostgreSQL provisioning, live verification).

**Frontend origin.** The frontend is a static Vite build with no runtime
configuration: its API origin is compiled into the bundle from
`VITE_API_BASE_URL`, which must be set in the hosting provider's build
environment for the production deployment (scheme + host only — the client
appends `/api/...`). It is **build-time and public**, never a secret, and a
change requires a rebuild. A placeholder always fails the build; missing,
loopback, or non-HTTPS values fail deployment builds, while local builds warn
when the origin is unset or loopback — see the
[frontend build & API origin contract](docs/deployment.md#10-frontend-build--api-origin-contract)
and the [production configuration matrix](docs/deployment.md#111-variable-and-configuration-matrix).

---

## 🔑 Gemini AI & Threat Intelligence Setup (Optional)

The detector defaults to local-only analysis: local heuristics and locally stored threat-feed indicators run without invoking VirusTotal, URLhaus, Google Web Risk, or Gemini. Users may explicitly opt in for external analysis on an individual scan. External providers have different data-handling policies; see [Privacy and Data Processing](docs/privacy-and-data-processing.md). API keys alone never enable external processing. To configure optional providers:

1. **Google Gemini AI**: Get an API key from [Google AI Studio](https://aistudio.google.com/) and set `GEMINI_API_KEY=your_key_here` in `backend/.env`.
2. **Google Web Risk**: Get an API key from [Google Cloud Console](https://console.cloud.google.com/) (Web Risk API) and set `GOOGLE_WEB_RISK_API_KEY=your_key_here` in `backend/.env`.
3. **VirusTotal**: Set `VIRUSTOTAL_API_KEY=your_key_here` in `backend/.env`.
4. **URLhaus**: No API key required; bounded URL lookups run only when the user explicitly opts in to external processing for that scan.
5. **PhishTank Feed**: (Implemented connector) Set `PHISHTANK_API_KEY=your_key_here` in `backend/.env` (optional; feed works without key or with application key).
6. **OpenPhish Feed**: (Implemented connector) Enabled by default via community feed (`https://openphish.com/feed.txt`).
7. **MISP Threat Sharing**: (Configurable adapter) Set `MISP_SERVER_URL=https://misp.your-org.local` and `MISP_API_KEY=your_key_here` in `backend/.env` (disabled if unconfigured).

All keys are server-side only and never leaked to frontend clients or persisted in logs. External processing is controlled per scan by `allow_external_processing`, which defaults to `false`.

### What scan history stores

Scan history keeps a bounded, sanitized input preview (100 characters plus an ellipsis) together with the risk score, status, phishing signals, structured diagnostic `details`, and the validated `ai_explanation`. URL user-information, secret-bearing query and fragment parameters, signed-URL parameters, sensitive header values, and common credential shapes are masked in the stored preview and URL-bearing detail fields; scheme, host, path, parameter names, and harmless values remain visible. Redaction is best-effort pattern matching, not a guarantee that stored history is secret-free, and the stored explanation may still quote input content. See [Privacy and Data Processing](docs/privacy-and-data-processing.md#what-sentinel-stores).

---

## 📡 API Endpoints

| Method | Endpoint | Access Control | Description |
|--------|----------|----------------|-------------|
| `GET` | `/api/health` | Public | Cheap process liveness and CSRF bootstrap (no DB/provider query) |
| `GET` | `/api/ready` | Public | DB connectivity readiness: 200 ready / 503 sanitized unavailable |
| `POST` | `/api/auth/register` | Public (5/min) | Account registration with HttpOnly session |
| `POST` | `/api/auth/login` | Public (5/min) | Authentication with HttpOnly session |
| `POST` | `/api/auth/logout` | Public/Auth | Session revocation and cookie clearance |
| `GET` | `/api/auth/me` | Authenticated | Profile of current authenticated user |
| `POST` | `/api/analyze` | Public / Auth (10/min + 100/day) | Threat vector analysis (URL, email body, headers) |
| `GET` | `/api/history` | User / Guest Scoped | Retrieve scoped scan history |
| `GET` | `/api/history/{scan_id}` | Owner / Admin Scoped | Single scan threat report (IDOR protected) |
| `DELETE` | `/api/history/{scan_id}` | Owner / Admin Scoped | Delete single scan record |
| `DELETE` | `/api/history` | User / Guest Scoped | Bulk clear history for current session |
| `GET` | `/api/admin/metrics` | Admin RBAC | Platform-wide aggregation metrics |
| `GET` | `/api/admin/scans` | Admin RBAC | Global scan audit log |
| `GET` | `/api/admin/threat-feeds` | Admin RBAC | Sanitized sync status and freshness of threat feeds |
| `POST` | `/api/admin/threat-feeds/{source}/refresh` | Admin RBAC (5/min, CSRF) | Trigger manual atomic refresh for registered feed provider |

### Example: Analyze a URL

```bash
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: <token>" \
  -d '{"input_type": "url", "content": "http://paypa1-verification.xyz/login"}'
```

---

## 🧪 Running the Backend Test Suite

```bash
PYTHONPATH=backend pytest backend/tests
```
```

---

## 🛡️ Risk Score Interpretation

| Score | Status | Meaning |
|-------|--------|---------|
| 0–29 | ✅ Safe | No significant phishing indicators detected |
| 30–69 | ⚠️ Warning | Suspicious patterns found — verify independently |
| 70–100 | 🔴 Danger | High-confidence phishing attempt — do not interact |


### Operational intelligence

Optional, content-free OpenTelemetry traces and metrics cover HTTP requests, analysis,
provider latency/queue outcomes, caches and feed refreshes. No collector or public
metrics endpoint is required. See [configuration, privacy exclusions and metric catalog](docs/deployment.md#9-operational-intelligence-task-34).

From `backend/`, run `python -m app.jobs.refresh_threat_feeds` for a one-shot,
sequential refresh of registered feeds. Exit 0 accepts success/not-modified/disabled;
exit 1 includes partial failures. **No production scheduler or Render Cron resource
is configured**. The runner does not check per-provider due times: daily refresh
cannot keep all feeds fresh, while a two-hour refresh-all over-polls slower sources.
See the [freshness boundaries and scheduling tradeoff](docs/deployment.md#one-shot-feed-runner--scheduling-is-not-deployed);
source-aware orchestration and cross-process coordination remain separate work.

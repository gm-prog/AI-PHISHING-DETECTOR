# SENTINEL AI — Phishing & Social Engineering Threat Detector

An advanced full-stack AI-powered phishing detector that inspects URLs, email body text, and raw email headers using heuristic analysis engines and optional Google Gemini AI integration.

---

## 🚀 Features

- **URL Analysis** — Detects typosquatting, brand-jacking, suspicious TLDs, IP-based hosting, excessive subdomains, and insecure protocols
- **Email Text Analysis** — Identifies urgency keywords, social engineering tactics, and embedded malicious links
- **Email Header Analysis** — Validates SPF/DKIM/DMARC authentication and detects From/Return-Path sender spoofing
- **AI Threat Reports** — Generates a rich Markdown intelligence report using a local heuristic engine (works 100% offline)
- **Gemini AI Mode** — Optional integration with Google Gemini 2.5 Flash for deep semantic phishing analysis
- **Scan History** — Persists up to 30 previous scans in local browser storage
- **Cinematic UI** — Dark glassmorphism design with animated scanning overlays and live risk gauges

---

## 📁 Project Structure

```
Ai phishing detector/
├── backend/                  # FastAPI Python backend
│   ├── app/
│   │   ├── main.py           # API routes and report generation
│   │   ├── config.py         # Environment configuration
│   │   ├── models/
│   │   │   └── schemas.py    # Pydantic request/response models
│   │   └── services/
│   │       ├── url_service.py    # URL heuristic analyzer
│   │       ├── email_service.py  # Email text + header analyzer
│   │       └── llm_service.py    # Gemini AI integration
│   ├── requirements.txt
│   ├── .env                  # API key configuration
│   └── test_backend.py       # Standalone backend test script
│
└── frontend/                 # React + Vite + TypeScript frontend
    ├── src/
    │   ├── App.tsx            # Main application layout
    │   ├── components/        # UI components
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

## 🔑 Gemini AI Setup (Optional)

The detector works fully offline with its autonomous heuristic engine. To enable server-side AI-powered semantic threat analysis:

1. Get an API key from [Google AI Studio](https://aistudio.google.com/)
2. Set `GEMINI_API_KEY=your_key_here` in `backend/.env` (or environment variables).
   - In production, keys are managed securely on the backend; the client never directly handles or exposes third-party provider keys.

---

## 📡 API Endpoints

| Method | Endpoint | Access Control | Description |
|--------|----------|----------------|-------------|
| `GET` | `/api/health` | Public | Backend health telemetry |
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
cd backend
pytest -q tests/test_security_hardening.py
```

---

## 🛡️ Risk Score Interpretation

| Score | Status | Meaning |
|-------|--------|---------|
| 0–29 | ✅ Safe | No significant phishing indicators detected |
| 30–69 | ⚠️ Warning | Suspicious patterns found — verify independently |
| 70–100 | 🔴 Danger | High-confidence phishing attempt — do not interact |

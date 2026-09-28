# Endpoint Security Inventory — SENTINEL AI Phishing Detector

## Architecture & Trust Boundaries
- **Frontend**: React + Vite + TypeScript (Single-Page Application)
- **Backend API Gateway**: FastAPI (Python 3.12, Uvicorn)
- **Database / ORM**: SQLite (`phishing_detector.db`) + SQLAlchemy 2.0 ORM
- **Authentication**: Opaque Server-Side Sessions with HttpOnly/SameSite Cookies (`backend/app/auth.py`), bcrypt password hashing
- **External Engines**: Google Gemini 3.6 Flash (Interactions API with `store=False`), VirusTotal API, URLhaus threat feeds

---

## Endpoint Inventory Matrix

| HTTP Method | Route Path | Access Control | Resource Isolation | Input Sources | Sensitive Outputs | Rate Limit | Risk Level |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/health` | Public | None | None | Engine status, API key presence bools | Baseline (limiter) | Low |
| `POST` | `/api/auth/register` | Public | None | JSON Body (`UserCreate`) | User profile, HttpOnly cookie | 10 / min | High |
| `POST` | `/api/auth/login` | Public | None | JSON Body (`UserLogin`) | User profile, HttpOnly cookie | 10 / min | High |
| `GET` | `/api/auth/me` | Authenticated | Scoped to active session | Cookie `sentinel_session` | User profile | Standard | Low |
| `POST` | `/api/analyze` | Public / Optional Auth | Scoped to user or guest hash | JSON Body (`AnalysisRequest`) | Detailed Threat Analysis Report | 10 / min (Burst) + 100 / day (Account Quota) | Medium |
| `GET` | `/api/history` | Authenticated / Guest | User / Guest Scoped | Cookie `sentinel_session` / `sentinel_guest` | User scan history list | Standard | Low |
| `GET` | `/api/history/{scan_id}` | Authenticated | Strict IDOR check (`scan.user_id == current_user.id`) | Path Param `scan_id`, Cookie | Single scan threat report | Standard | Medium |
| `POST` | `/api/verify-gemini-key` | Authenticated | Scoped to caller | JSON Body (`VerifyKeyRequest`) | Verification status bool | 10 / min | Medium |
| `GET` | `/api/admin/metrics` | Admin RBAC (`role == 'admin'`) | Global Aggregation | Cookie `sentinel_session` | Platform threat metrics | Strict Admin | High |
| `GET` | `/api/admin/scans` | Admin RBAC (`role == 'admin'`) | Global Scans | Cookie `sentinel_session`, Query `limit` | System-wide scan telemetry | Strict Admin | High |

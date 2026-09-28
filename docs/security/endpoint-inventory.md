# Endpoint Security Inventory — SENTINEL AI Phishing Detector

## Architecture & Trust Boundaries
- **Frontend**: React + Vite + TypeScript (Single-Page Application)
- **Backend API Gateway**: FastAPI (Python 3.11+, Uvicorn)
- **Database / ORM**: SQLite (`phishing_detector.db`) + SQLAlchemy 2.0 ORM
- **Authentication**: Opaque Server-Side Sessions with HttpOnly/SameSite Cookies (`backend/app/auth.py`), bcrypt password hashing
- **External Engines**: Google Gemini 3.6 Flash (Interactions API with explicit `store=False`), VirusTotal API, URLhaus threat feeds

---

## Endpoint Inventory Matrix

| HTTP Method | Route Path | Access Control | Resource Isolation | Input Sources | Sensitive Outputs | Rate Limit | Risk Level |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/health` | Public | None | None | Minimal health telemetry (status, timestamp, version) | Baseline | Low |
| `POST` | `/api/auth/register` | Public | None | JSON Body (`UserCreate`) | User profile, HttpOnly session cookie, CSRF cookie | 10 / min | High |
| `POST` | `/api/auth/login` | Public | None | JSON Body (`UserLogin`) | User profile, HttpOnly session cookie, CSRF cookie | 10 / min | High |
| `POST` | `/api/auth/logout` | Public / Auth | Current Session | Cookie `sentinel_session` | None (clears session and auth cookies) | Standard | Low |
| `GET` | `/api/auth/me` | Authenticated | Scoped to active session | Cookie `sentinel_session` | User profile (`UserOut`) | Standard | Low |
| `GET` | `/api/admin/metrics` | Admin RBAC (`role == 'admin'`) | Global Aggregation | Cookie `sentinel_session` | Platform threat metrics | Strict Admin | High |
| `GET` | `/api/admin/scans` | Admin RBAC (`role == 'admin'`) | Global Scans | Cookie `sentinel_session`, Query `limit` | System-wide scan telemetry | Strict Admin | High |
| `POST` | `/api/analyze` | Public / Optional Auth | Scoped to user or guest hash | JSON Body (`AnalysisRequest`) | Detailed Threat Analysis Report | 10 / min (Burst) + 100 / day (Account Quota) | Medium |
| `GET` | `/api/history` | Authenticated / Guest | User / Guest Scoped | Cookie `sentinel_session` / `sentinel_guest` | User scan history list | Standard | Low |
| `GET` | `/api/history/{scan_id}` | Authenticated | Strict IDOR check (`scan.user_id == current_user.id` or admin) | Path Param `scan_id`, Cookie | Single scan threat report | Standard | Medium |
| `DELETE` | `/api/history/{scan_id}` | Authenticated | Strict IDOR check (`scan.user_id == current_user.id`) | Path Param `scan_id`, Cookie | Deletion status confirmation | Standard | Medium |
| `DELETE` | `/api/history` | Authenticated / Guest | User / Guest Scoped | Cookie `sentinel_session` / `sentinel_guest` | Bulk deletion count | Standard | Medium |

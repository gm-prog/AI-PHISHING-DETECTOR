# Endpoint Security Inventory — SENTINEL AI Phishing Detector

## Architecture & Trust Boundaries
- **Frontend**: React + Vite + TypeScript (Single-Page Application)
- **Backend API Gateway**: FastAPI (Python 3.11+, Uvicorn)
- **Database / ORM**: SQLAlchemy 2.x ORM — SQLite (`phishing_detector.db`) in development/test, PostgreSQL (psycopg2, explicit fail-closed `DATABASE_URL`) in staging/production (see `docs/deployment.md`)
- **Authentication**: Opaque Server-Side Sessions with HttpOnly/SameSite Cookies (`sentinel_session`), CSRF double-submit validation (`sentinel_csrf` cookie + `X-CSRF-Token` header), bcrypt password hashing
- **External AI Tier**: Google Gemini 3.6 Flash (Interactions API with explicit `store=False`; Generate Content compatibility fallback is non-persistent by default)
- **External Intel Tier**: VirusTotal API, URLhaus Threat Feeds, Google Web Risk Lookup API, and local synchronized threat feeds (sanitized normalized contracts, bounded semaphores, TTL caching, O(1) indexed lookup)
- **Persistence Boundary**: `ScanHistory` stores a bounded (100 characters plus an ellipsis), sanitized content preview; the risk score, status, phishing signals, structured `details`, and the validated `ai_explanation` (which in external mode derives from the Gemini completion); and ownership metadata. URL user-information, secret-bearing query/fragment values, signed-URL parameters, sensitive header values, and common credential shapes are masked in the stored preview and in URL-bearing persisted result fields on a best-effort basis. Raw prompts and raw third-party provider responses are not persisted. Free-form explanation prose is stored as generated apart from that credential masking; see [privacy and data processing](../privacy-and-data-processing.md#what-sentinel-stores).

---

## Endpoint Inventory Matrix

| HTTP Method | Route Path | Access Control | Resource Isolation | Input Sources | Sensitive Outputs | Rate Limit | Risk Level |
|---|---|---|---|---|---|---|---|
| `GET` | `/api/health` | Public | None | None | Cheap liveness fields and CSRF bootstrap; no DB/provider query | Baseline | Low |
| `GET` | `/api/ready` | Public | None | None | DB connectivity only: 200 ready/available or 503 sanitized unavailable | Standard | Low |
| `POST` | `/api/auth/register` | Public | None | JSON Body (`UserCreate`) | User profile, HttpOnly session cookie, CSRF cookie | 5 / min | High |
| `POST` | `/api/auth/login` | Public | None | JSON Body (`UserLogin`) | User profile, HttpOnly session cookie, CSRF cookie | 5 / min | High |
| `POST` | `/api/auth/logout` | Public / Auth | Current Session | Cookie `sentinel_session` | None (clears session and auth cookies) | Standard | Low |
| `GET` | `/api/auth/me` | Authenticated | Scoped to active session | Cookie `sentinel_session` | User profile (`UserOut`) | Standard | Low |
| `GET` | `/api/admin/metrics` | Admin RBAC (`role == 'admin'`) | Global Aggregation | Cookie `sentinel_session` | Platform threat metrics | Strict Admin | High |
| `GET` | `/api/admin/scans` | Admin RBAC (`role == 'admin'`) | Global Scans | Cookie `sentinel_session`, Query `limit` | System-wide scan telemetry | Strict Admin | High |
| `GET` | `/api/admin/threat-feeds` | Admin RBAC (`role == 'admin'`) | Global Feed States | Cookie `sentinel_session` | Sanitized feed sync status and freshness | Strict Admin | Medium |
| `POST` | `/api/admin/threat-feeds/{source}/refresh` | Admin RBAC (`role == 'admin'`) | Feed Provider Ingestion | Cookie, `X-CSRF-Token`, Path Param `source` | Refresh metrics (records processed/inserted/updated) | 5 / min | High |
| `POST` | `/api/analyze` | Public / Optional Auth | Scoped to user or guest hash | JSON Body (`AnalysisRequest`) | Detailed Threat Analysis Report | 10 / min (Burst) + 100 / day (Account Quota) | Medium |
| `GET` | `/api/history` | Authenticated / Guest | User / Guest Scoped | Cookie `sentinel_session` / `sentinel_guest` | User scan history list (sanitized previews and stored results) | Standard | Low |
| `GET` | `/api/history/{scan_id}` | Authenticated | Strict IDOR check (`scan.user_id == current_user.id` or admin) | Path Param `scan_id`, Cookie | Single stored scan report | Standard | Medium |
| `DELETE` | `/api/history/{scan_id}` | Authenticated | Strict IDOR check (`scan.user_id == current_user.id`) | Path Param `scan_id`, Cookie | Deletion status confirmation | Standard | Medium |
| `DELETE` | `/api/history` | Authenticated / Guest | User / Guest Scoped | Cookie `sentinel_session` / `sentinel_guest` | Bulk deletion count | Standard | Medium |


## Per-scan third-party analysis consent

`POST /api/analyze` accepts `allow_external_processing`, defaulting to `false`. With consent off, VirusTotal, URLhaus, Google Web Risk, and Gemini provider calls are skipped; local heuristics and locally stored threat indicators remain available. With consent on, only applicable configured providers are considered. The response and stored `details.external_processing_allowed` record the chosen mode; older records without that field remain unknown.

This control applies to third-party analysis calls for the current scan. Input still reaches the SENTINEL backend, and scan history retains a sanitized input preview plus the stored structured result described above. Provider result caching can avoid an outbound call, and the disclosure lists eligible configured integrations rather than proving every provider received data. Separate administrator-initiated threat-feed refreshes are outside this per-scan consent setting.

## Operational telemetry

OpenTelemetry export is optional and outbound-only. The API exposes no public metrics scrape endpoint; telemetry dimensions are finite and content-free, and health/readiness probes retain normal security headers. See [deployment telemetry and privacy controls](../deployment.md#9-operational-intelligence-task-34).

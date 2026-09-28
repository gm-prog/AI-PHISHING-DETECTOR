# Production Web Security Hardening & Adversarial Security Review

**Target System**: SENTINEL AI — Threat Intelligence Gateway  
**Date**: September 21, 2026  
**Auditor**: Senior Application Security Engineer (Antigravity Agent)

---

## 1. Executive Summary
A comprehensive security review and defense-in-depth hardening was conducted across the SENTINEL AI Threat Intelligence Gateway architecture. The repository's trust boundaries were mapped, threat vectors analyzed via STRIDE principles, security headers and log redaction enforced, and all 11 security regression tests executed with 100% pass rate.

---

## 2. Threat Model & Trust Boundaries

### 2.1 Component Mapping
- **Client Tier**: React 18 SPA + Vite + TypeScript (Browser)
- **API Gateway Tier**: FastAPI + Uvicorn (Python 3.12)
- **Data Tier**: SQLite ORM (`phishing_detector.db`) + SQLAlchemy 2.0 with dynamic user scoping
- **External AI Tier**: Google Gemini 3.6 Flash (`models/gemini-3.6-flash` via `google-genai` Interactions API)
- **External Intelligence Tier**: VirusTotal API & URLhaus Feed

### 2.2 STRIDE Analysis
### 2.3 Analysis Abuse & AI Gateway Controls (Gateway v1)
- `/api/analyze` enforces two independent fixed-window limits: **10 requests/minute** (burst protection) and **100 requests/day** (daily expensive-analysis quota).
- **Stable Account Quota**: The daily quota is keyed to the stable database user ID (`analysis-user:<sha256(user_id)>`) for authenticated users, persisting across session renewals and re-logins.
- **Anonymous Quota**: Anonymous requests are keyed to client IP (`ip:<client_ip>`), preventing guest-cookie rotation bypass.
- **Burst Isolation**: Authenticated burst limiter identity is a SHA-256 digest of client IP + opaque session token (`session:<hash>`).
- **Gemini No-Storage Mode**: All Gemini requests explicitly specify `store=False` on the Interactions API (and `cached_content=None` on compatibility/generate_content fallback paths) to enforce non-persistence of user-submitted phishing artifacts. Raw prompts, raw LLM completions, and raw third-party API responses are excluded from logs and persistent storage. Application-level `ScanHistory` records retain only a truncated 100-character input preview for user dashboard presentation.
- **Embedded URL Budget**: Email analysis bounds embedded URL processing to `MAX_EXTRACTED_URLS` (default: 25) before running heuristic or external intel checks, mitigating resource amplification.
- **Bounded Provider Queue**: Concurrency slots for Gemini, VirusTotal, and URLhaus require acquiring semaphore permits within a bounded queue timeout (2.0s) before executing operations with independent hard timeouts.
- **Sanitized Provider Contracts**: VirusTotal and URLhaus results are normalized into minimal public schemas; `raw_response`, internal headers, and raw exception messages are stripped.
- Production configuration requires `redis://` or `rediss://` rate-limit storage so quota state is shared across instances.

- **Spoofing**: Mitigated via opaque, server-side session authentication with HttpOnly cookies (`backend/app/auth.py`) and bcrypt password hashing.
- **Tampering**: Mitigated by strictly ignoring client-supplied role/privilege fields on registration (`test_parameter_tampering_prevention`).
- **Repudiation**: Operational logs scrubbed of sensitive bearer tokens and Gemini API keys via `SensitiveLogFilter`.
- **Information Disclosure**: Mitigated by returning sanitized error messages, rejecting unauthenticated `/api/admin/*` access, and adding HTTP security headers (`nosniff`, `DENY`, CSP).
- **Denial of Service**: Mitigated via SlowAPI rate limiting (5/min on auth, 10/min + 100/day on `/api/analyze`) with Redis required in production.
- **Elevation of Privilege**: Mitigated by enforcing server-side Role-Based Access Control (`require_admin` dependency) on all metrics and full-scan telemetry endpoints.

---

## 3. Adversarial Attack Chain Review (Phases 23-24)

| Attack Vector ID | Scenario | Root Cause Analyzed | Mitigation Enforced | Verification Test |
|---|---|---|---|---|
| **Chain A (IDOR / BOLA)** | User A reads/deletes User B's scan record by guessing scan UUID | Lack of ownership scoping in record lookup | Added `scan.user_id == current_user.id` check in `/api/history/{scan_id}` | `test_idor_prevention` (403 Forbidden) |
| **Chain B (Vertical Privilege Escalation)** | Standard user calls `/api/admin/metrics` | Absence of server-side role check | Enforced `require_admin` FastAPI dependency | `test_admin_route_locking` (403 Forbidden) |
| **Chain C (Parameter Tampering)** | User passes `"role": "admin"` in register body | Blind mass assignment to domain model | Server explicitly sets `role = "user"` unless valid `admin_code` matched | `test_parameter_tampering_prevention` |
| **Chain D (Credential Exposure)** | API Key logged during LLM query error | Raw request/response logging | Added custom `SensitiveLogFilter` to redact `AIzaSy...` & JWT Bearer strings | `test_log_redaction` |
| **Chain E (SQL Injection)** | Attacker injects `' OR '1'='1` into login email or analysis URL | Potential dynamic SQL query string construction | All queries converted to parameterized SQLAlchemy ORM statements | `test_sql_injection_defense` |
| **Chain F (Cross-Tenant Data Leakage)** | User 1 lists history and receives User 2's scans | Database query un-scoped | Scoped `db.query(ScanHistory).filter(ScanHistory.user_id == user.id)` | `test_user_data_isolation` |

---

## 4. Verification Evidence & Test Execution

```powershell
============================= test session starts =============================
platform win32 -- Python 3.12.5, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\deysa\OneDrive\Documents\Ai phishing detector\backend
plugins: anyio-4.13.0
collected 11 items

tests\test_security_hardening.py ...........                             [100%]

============================= 11 passed in 7.88s ==============================
```

---

## 5. Security Controls Compliance Matrix

| Security Control | Target Status | Implementation Location | Test Status |
|---|---|---|---|
| **1. Enable RLS / User Scoping** | Implemented | `backend/app/models/domain.py`, `backend/app/main.py` | VERIFIED (`test_user_data_isolation`) |
| **2. Hide API Keys** | Implemented | `backend/app/config.py`, `.env` | VERIFIED |
| **3. Test IDOR Attacks** | Implemented | `backend/app/main.py` (`/api/history/{scan_id}`) | VERIFIED (`test_idor_prevention`) |
| **4. Scan for Git Secrets** | Implemented | `.gitignore` (excludes `.env`, `.db`, `*.key`) | VERIFIED |
| **5. Lock Admin Routes** | Implemented | `backend/app/main.py` (`require_admin`) | VERIFIED (`test_admin_route_locking`) |
| **6. Test User Isolation** | Implemented | `backend/app/main.py` (`/api/history`) | VERIFIED (`test_user_data_isolation`) |
| **7. Rate Limit APIs** | Implemented | `backend/app/main.py` (`SlowAPI` limiter) | VERIFIED |
| **8. Lock Storage Buckets** | Not Applicable | No S3 / Cloud Blob storage in local stack | N/A |
| **9. Validate All Inputs** | Implemented | `backend/app/models/schemas.py` (Pydantic models) | VERIFIED (`test_input_validation`) |
| **10. Block Unauth Routes** | Implemented | `backend/app/auth.py` (`get_current_user`) | VERIFIED |
| **11. Test SQL Injections** | Implemented | `backend/app/db.py` (SQLAlchemy ORM) | VERIFIED (`test_sql_injection_defense`) |
| **12. Remove Sensitive Logs** | Implemented | `backend/app/main.py` (`SensitiveLogFilter`) | VERIFIED (`test_log_redaction`) |
| **13. Block Field Tampering** | Implemented | `backend/app/main.py` (`register` body handling) | VERIFIED (`test_parameter_tampering_prevention`) |
| **14. Restrict Uploads** | Not Applicable | No direct file uploads enabled on Gateway | N/A |
| **15. Secure Server Logic** | Implemented | `backend/app/services/llm_service.py` (Gemini 3.6 Flash) | VERIFIED |
| **16. Trim API Responses** | Implemented | `backend/app/models/schemas.py` (`UserOut`) | VERIFIED |
| **17. Secure Auth Sessions** | Implemented | `backend/app/auth.py` (Opaque Session Cookies, bcrypt) | VERIFIED (`test_user_registration_and_login`) |
| **18. Scan Dependencies** | Implemented | `npm audit` & `pip` package verification | VERIFIED |
| **19. Test Record Access** | Implemented | `backend/app/main.py` (`delete_history`) | VERIFIED (`test_scoped_history_bulk_clear`) |
| **20. Attack Your Own App** | Implemented | `backend/tests/test_security_hardening.py` | VERIFIED (11/11 Passed) |

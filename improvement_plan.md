# Sentinel AI — Architectural Evolution & Improvement Roadmap

> **Status Notice (Gateway v1.2 Hardened)**: The historical gaps identified in early prototype iterations (dormant LLM integration, missing rate limits, lack of backend persistence, missing threat intelligence feeds) have been resolved. The core platform now features server-side Gemini semantic analysis, bounded external intelligence pipelines (VirusTotal & URLhaus), SQLAlchemy session & scan persistence, and SlowAPI rate limiting.

---

## ✅ Completed Architectural Milestones

1. **AI Threat Analysis Gateway (v1 / v1.2 Hardened)**:
   - Full server-side Google Gemini 3.6 Flash integration with strict prompt injection delimitation (`<UNTRUSTED_INPUT>`, `<TRUSTED_HEURISTICS>`).
   - Explicit `store=False` on Interactions API for zero data retention.
   - Pydantic validation on untrusted LLM outputs with server-enforced score floors.
   - Graceful local heuristic fallback when AI services are offline or unconfigured.

2. **External Threat Intelligence Integration**:
   - Google Web Risk Lookup API integration with bounded semaphores, TTL caching, SHA-256 cache keys, normalized public schemas, and +30 deterministic score contribution cap.
   - VirusTotal URL submission/report retrieval with normalized, sanitized contracts.
   - URLhaus malware domain lookups with automated reputation scoring.
   - Bounded provider queue semaphores, TTL caching, and hard execution timeouts.

3. **Backend Persistence & Data Isolation**:
   - SQLAlchemy 2.x ORM with user and guest session isolation; SQLite in development/test, PostgreSQL (psycopg2) in production with fail-closed `DATABASE_URL` validation (Task 3.3, see `docs/deployment.md`).
   - IDOR-protected scan history retrieval and deletion endpoints.
   - Preview sanitization for persisted `ScanHistory` records (masking tokens, credentials, API keys, card numbers).

4. **Multi-Tier Rate Limiting & Abuse Prevention**:
   - SlowAPI fixed-window rate limiting on auth endpoints (5/min).
   - Independent burst protection (10/min) and stable account-level daily quotas (100/day) on `/api/analyze`.
   - Fail-closed quota semantics ensuring invalid sessions never downgrade to anonymous IP buckets.

---

## 🚀 Active Roadmap & Future Enhancements

### Phase 1: Dynamic Threat Feeds & Rule Updates
- [x] Bounded Google Web Risk Threat-Intelligence Provider (`webrisk_service.py`, schema, pipeline, UI) with upstream-aware expiration and TTL=0 on expired records.
- [x] Standards-aware email authentication parsing (RFC 8601, RFC 7601, RFC 7208, RFC 6376, RFC 7489, alignment via `email_auth_service.py`) with trusted authserv-id boundaries and zero raw header persistence.
- [x] Normalized threat intelligence feed foundation (`ThreatIndicator`, indexed hash lookup, deduplication, URL normalization, UTC parsing, classification precedence, and invariant tests via `threat_feed_service.py`).
- [x] Production threat feed connector layer (streaming bounded PhishTank & OpenPhish connectors, configurable MISP adapter).
- [x] Feed state lifecycle tracking (`ThreatFeedState`), freshness calculation, conditional HTTP caching (`ETag`, `Last-Modified`, 304 handling), and atomic refresh (staging -> commit, retaining healthy generations on failure).
- [x] Multi-source threat intelligence evidence fusion (`ThreatEvidence`), deterministic severity precedence, and bounded single-boost invariants.
- [x] Authoritative Alembic database migrations (`alembic upgrade head`, `alembic downgrade base`), legacy constraint replacement (`uq_source_gen_type_indicator`), `generation_id` NOT NULL enforcement, fail-closed unsafe downgrade refusal on cross-generation duplicates, bounded BZ2 decompression with EOF & trailing data rejection, and non-mutating startup validation.
- [x] Admin threat feed control plane (`GET /api/admin/threat-feeds`, `POST /api/admin/threat-feeds/{source}/refresh`) with CSRF, rate-limiting, and strict source allowlisting.
- [x] Production persistence & deployment contract (Task 3.3): fail-closed `DATABASE_URL` validation, legacy `postgres://` normalization pinned to psycopg2, dialect-aware engine pooling, SQLAlchemy-inspection read-only schema verification portable across SQLite/PostgreSQL, PostgreSQL-portable Alembic migrations, real `postgres:16-alpine` CI integration, Render pre-deploy migration + dynamic `$PORT` contract, and a cookie/CSRF-native live verification harness (`docs/deployment.md`).
- [ ] Automated scheduled background cron/worker feed crawler sync.

### Phase 2: Platform Observability & Telemetry
- [ ] Granular metrics collection for provider latency, cache hit ratios, and queue saturation.
- [ ] OpenTelemetry distributed tracing across external provider boundaries.

### Phase 3: Frontend Evolution
- [ ] Modular state management for historical telemetry and dashboard reporting.
- [ ] Component-level test coverage using Vitest.

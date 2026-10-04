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
   - VirusTotal URL submission/report retrieval with normalized, sanitized contracts.
   - URLhaus malware domain lookups with automated reputation scoring.
   - Bounded provider queue semaphores, TTL caching, and hard execution timeouts.

3. **Backend Persistence & Data Isolation**:
   - SQLite / SQLAlchemy 2.0 ORM with user and guest session isolation.
   - IDOR-protected scan history retrieval and deletion endpoints.
   - Preview sanitization for persisted `ScanHistory` records (masking tokens, credentials, API keys, card numbers).

4. **Multi-Tier Rate Limiting & Abuse Prevention**:
   - SlowAPI fixed-window rate limiting on auth endpoints (5/min).
   - Independent burst protection (10/min) and stable account-level daily quotas (100/day) on `/api/analyze`.
   - Fail-closed quota semantics ensuring invalid sessions never downgrade to anonymous IP buckets.

---

## 🚀 Active Roadmap & Future Enhancements

### Phase 1: Dynamic Threat Feeds & Rule Updates
- [ ] Scheduled background feed updates for brand databases and high-risk TLD tracking.
- [ ] Integration with additional threat feeds (e.g. Google Safe Browsing, PhishTank, MISP).
- [ ] Structured email authentication parsing via standardized MIME/auth libraries.

### Phase 2: Platform Observability & Telemetry
- [ ] Granular metrics collection for provider latency, cache hit ratios, and queue saturation.
- [ ] OpenTelemetry distributed tracing across external provider boundaries.

### Phase 3: Frontend Evolution
- [ ] Modular state management for historical telemetry and dashboard reporting.
- [ ] Component-level test coverage using Vitest.

# SENTINEL AI — Deployment & Persistence Contract

This document is the authoritative description of how SENTINEL AI is
configured, migrated, verified, and deployed across environments.

---

## 1. Environment matrix

| Environment   | Database                | `DATABASE_URL` required | Fallback |
| ------------- | ----------------------- | ----------------------- | -------- |
| `development` | SQLite (default) or PostgreSQL | No               | `backend/phishing_detector.db` (absolute, deterministic) |
| `test`        | SQLite (default) or PostgreSQL | No               | `backend/phishing_detector.db` (absolute, deterministic) |
| `staging`     | PostgreSQL only         | **Yes — fail closed**   | None |
| `production`  | PostgreSQL only         | **Yes — fail closed**   | None |

The environment is selected with `ENVIRONMENT`
(`development` | `test` | `staging` | `production`).

## 2. DATABASE_URL behavior

`backend/app/config.py` implements the configuration contract:

- **`normalize_database_url()`** — deterministic normalization:
  - legacy `postgres://…` and generic `postgresql://…` are rewritten to the
    project's single deliberate driver spelling `postgresql+psycopg2://…`
    (the installed DBAPI is psycopg2 via `psycopg2-binary`);
  - username, password (including percent-encoded characters), hostname,
    port, database name, and all query/SSL parameters (`sslmode`,
    `sslrootcert`, `connect_timeout`, …) are preserved verbatim — only the
    scheme token before `://` is ever rewritten;
  - normalized URLs may contain credentials and are **never logged**.
- **`validate_database_url(url, environment)`** — fail-closed validation:
  - in `production`/`staging` the application **refuses to start** when
    `DATABASE_URL` is missing, blank, points to SQLite, uses an unsupported
    scheme/driver (e.g. `mysql://`, `postgresql+asyncpg://`), is malformed,
    or lacks a hostname or database name;
  - in `development`/`test` an absent `DATABASE_URL` resolves to the
    deterministic local SQLite fallback;
  - validation error messages never echo the raw URL or credentials.
- Validation runs **at import time** (`app.config`), so a misconfigured
  production process dies immediately — there is no code path that silently
  substitutes SQLite in production.

## 3. Migration lifecycle (schema is migration-driven only)

Schema creation and mutation happen **exclusively** through Alembic:

```bash
cd backend
alembic upgrade head        # applies a1b2c3d4e5f6 -> b4a49925f0e5
```

- Authoritative Alembic head: **`b4a49925f0e5`**.
- `backend/alembic/env.py` resolves the migration URL from a single source
  of truth, in priority order:
  1. a programmatic override (test harnesses calling
     `Config.set_main_option("sqlalchemy.url", …)`),
  2. the `DATABASE_URL` environment variable (normalized exactly like the
     application),
  3. the application's resolved URL from `app.db` (which applies the
     environment contract above).
  Alembic therefore always migrates the same database the application
  connects to.
- Migrations are portable across SQLite and PostgreSQL: boolean server
  defaults use dialect-correct rendering, data backfills bind timestamps/
  booleans as parameters instead of SQLite-only SQL functions, and
  constraint rewrites use a table recreate only on SQLite (native `ALTER`
  on PostgreSQL).

## 4. Runtime schema verification (strictly read-only)

At startup (FastAPI lifespan) the application calls
`verify_schema_invariants()` (`backend/app/db.py`), which:

- is **dialect-aware** — implemented with SQLAlchemy inspection (no
  `sqlite3`/`PRAGMA`/`sqlite_master` internals), so the same invariants are
  enforced on SQLite and PostgreSQL;
- is **strictly read-only and enforced at the database layer**: SQLite
  targets are opened via a `mode=ro` URI and PostgreSQL sessions run with
  `default_transaction_read_only=on`; the verifier performs only inspector
  operations and `SELECT`s — never `CREATE`/`ALTER`/`DROP`/`INSERT`/
  `UPDATE`/`DELETE`, never `Base.metadata.create_all()`, never implicit
  repair, never migration execution;
- fails closed with an actionable `RuntimeError` ("run `alembic upgrade
  head`") when any invariant is violated:
  - required tables: `users`, `user_sessions`, `scan_history`,
    `threat_indicators`, `threat_feed_states`, `alembic_version`;
  - exactly one `alembic_version` row equal to `b4a49925f0e5` (empty,
    multiple, or wrong revisions fail closed);
  - required columns on `users`, `user_sessions`, `scan_history`,
    `threat_feed_states`;
  - ownership indexes `ix_scan_history_user_id`,
    `ix_scan_history_guest_session_hash`;
  - `threat_indicators.generation_id` present and `NOT NULL`;
  - `uq_source_gen_type_indicator` present and legacy
    `uq_source_type_indicator` absent;
  - all six required `threat_indicators` indexes.

Test fixtures that build throwaway schemas (e.g. `Base.metadata.create_all`
inside `backend/tests/…`) are test-only and are never executed by
application startup.

## 5. Render deployment contract (`render.yaml`)

| Contract item     | Value |
| ----------------- | ----- |
| `preDeployCommand`| `cd backend && alembic upgrade head` — migrations run **before** the new version starts (requires a paid instance type, hence `plan: starter`) |
| `startCommand`    | `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT` — binds `0.0.0.0` and Render's dynamic `$PORT` |
| `healthCheckPath` | `/api/health` — public, requires no authenticated session state |
| `DATABASE_URL`    | `sync: false` — supplied externally by the infrastructure operator |

**PostgreSQL provisioning responsibility:** the repository defines the
application contract only. The operator provisions the production
PostgreSQL instance (e.g. a Render PostgreSQL resource) and supplies its
connection string as `DATABASE_URL` (either `postgres://…` or
`postgresql://…` — both are normalized). No database resource is declared
in the Blueprint and no credentials are committed to the repository.

Runtime startup never performs migrations; if the pre-deploy migration did
not run, startup fails closed via the read-only verifier.

## 6. Local development setup

```bash
cd backend
python -m venv venv && source venv/bin/activate   # or venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head                               # creates/updates the SQLite dev DB
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

No `DATABASE_URL` is needed locally; the deterministic SQLite fallback
(`backend/phishing_detector.db`) is used. To develop against PostgreSQL,
export `DATABASE_URL=postgresql://user:pass@localhost:5432/sentinel` before
running the commands above.

## 7. Test commands

```bash
cd backend
PYTHONPATH=. pytest -q                 # full suite (SQLite fixtures)

# Real-PostgreSQL integration (used by CI; any reachable PG works locally):
export SENTINEL_TEST_POSTGRES_URL=postgresql://user:pass@localhost:5432/sentinel_test
PYTHONPATH=. pytest -q tests/test_database.py
```

CI (`.github/workflows/security.yml`) runs:

- `backend` — full regression suite on SQLite + Bandit + pip-audit;
- `backend-postgres` — a real `postgres:16-alpine` service container:
  `alembic upgrade head` against PostgreSQL, read-only schema invariant
  verification against PostgreSQL, then the database tests and the full
  backend regression suite with the PostgreSQL integration tests enabled;
- `frontend` — type-check/build + `npm audit`;
- `secret-scan` — Gitleaks.

## 8. Live verification

`backend/tests/verify_live.py` verifies a running deployment using the
actual authentication architecture (HttpOnly session cookie + double-submit
CSRF via `X-CSRF-Token`; no JWT/Bearer anywhere):

```bash
BASE_URL=https://your-deployment python tests/verify_live.py
# optional admin RBAC check (operator-supplied, never hardcoded):
ADMIN_EMAIL=… ADMIN_PASSWORD=… BASE_URL=… python tests/verify_live.py
```

The harness bootstraps CSRF state from `/api/health`, registers throwaway
users, exercises authenticated analysis/history/IDOR/admin-lock paths, and
never prints cookies, tokens, passwords, or secrets.

## 9. Operational intelligence (Task 3.4)

### Liveness versus readiness

- `GET /api/health` is cheap **liveness**, HTTP 200 with the unchanged
  `status`, `api_active`, `version`, and `message` fields. It performs no DB
  query or external-provider request, even when a session cookie is supplied.
  CSRF bootstrap cookies and security/CORS middleware remain in place.
- `GET /api/ready` is public **database connectivity readiness**. A short-lived
  connection from the existing engine executes `SELECT 1` and closes. HTTP 200:
  `{"status":"ready","database":"available"}`; HTTP 503:
  `{"status":"not_ready","database":"unavailable"}`. Driver messages, hostnames
  and credentials are never returned. No provider checks, schema repair or migrations.
  This is not a deep schema/permissions/replica-lag check. Configure a bounded
  PostgreSQL `connect_timeout` in the externally supplied URL; existing engine
  pool/driver timeout semantics still apply.
- Render **continues to use `/api/health`**. The `starter` web service,
  pre-deploy migration and external PostgreSQL contracts are unchanged.
  Reference: https://render.com/docs/health-checks.

### Optional OpenTelemetry export

`app/telemetry.py` uses the OTel Python API/SDK and explicit ASGI/provider spans,
not automatic request/header/outbound HTTP/SQL instrumentation. No public scrape
endpoint exists. With no explicit endpoint configured, no SDK workers or exporters
are started; scans still work. Operators must supply a collector/backend separately:

```bash
# Set these externally; do not commit collector addresses or authentication values.
OTEL_EXPORTER_OTLP_ENDPOINT=https://your-collector.example
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
# Optional credentials: OTEL_EXPORTER_OTLP_HEADERS (operator secret configuration)
OTEL_TRACES_EXPORTER=otlp
OTEL_METRICS_EXPORTER=otlp
OTEL_TRACES_SAMPLER=parentbased_traceidratio
OTEL_TRACES_SAMPLER_ARG=0.1
```

Supported SDK/HTTP-exporter settings include signal-specific
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` / `METRICS_ENDPOINT` (full signal URLs),
`OTEL_EXPORTER_OTLP_TRACES_HEADERS` / `METRICS_HEADERS`, and TLS certificate
settings supported by the HTTP exporter. The generic endpoint appends `/v1/traces`
and `/v1/metrics`. A signal without an endpoint is not exported. `none` disables
that signal; `OTEL_SDK_DISABLED=true` disables both. Only `otlp`/`none` exporters
and `http/protobuf` are supported here; unsupported configuration fails open with
sanitized diagnostics, **not** a console exporter. Export destination/TLS validity
must be checked by the operator; a running API does not prove telemetry delivery.

Service identity is fixed to `sentinel-ai-api` (web) or `sentinel-ai-feed-job`
(job), plus validated `deployment.environment.name`. Arbitrary `OTEL_RESOURCE_ATTRIBUTES`
and resource detectors are deliberately not imported. Providers are lifecycle-owned,
not installed repeatedly into OTel's write-once global registry. Lifespan shutdown
and one-shot job completion flush/shutdown their own providers. Do not also launch
this service with automatic instrumentation/provider bootstrap.

Spans use a bounded batch queue (512 spans, batches of 128, 5-second interval).
Metric export occurs every 60 seconds; HTTP histogram boundaries follow the stable
HTTP convention (0.005 through 10 seconds). HTTP exporter network timeout is fixed
at 3 seconds, reader/export budgets at 4 seconds, rather than trusting unbounded
operator timeout settings. A full queue drops telemetry rather than blocking a scan.
Exporter failures do not change scan results. SDK/exporter diagnostic records are
replaced by `event=telemetry_export_failed`, without raw exception or response text.
No logs exporter, collector, vendor account or Render resource is provisioned.

### Privacy, correlation and spans

Allowed dimensions are finite input type, verdict, provider/source, outcome, error
category, cache result, feed freshness, HTTP method/scheme, registered route template,
and bounded HTTP status/status class. Unknown providers/sources collapse to `unknown`;
unexpected provider outcomes collapse to `error`. Unmatched/rejected-before-routing
requests use `unmatched`, never their raw path. HTTP method names outside the standard
finite set become `_OTHER`.

**Excluded:** payloads, raw submitted URLs/domains, email bodies/headers, query strings,
cookies, Authorization, passwords, API keys, session/user IDs, database URLs,
exception messages/stacks, provider responses, cache keys and generation IDs.
Only a validated W3C `traceparent` is accepted for correlation; baggage and tracestate
are ignored. Generated trace/span IDs appear in structured operational logs, not
metric dimensions (SDK trace exemplars may link a measurement to a trace).
Do not attach user data via collector enrichment. Configure infrastructure/access
logging separately to avoid raw query strings; this module does not sanitize an
operator's reverse-proxy or Uvicorn access logs.

Spans: `HTTP` renamed to `METHOD route-template`, `analysis`, `analysis.heuristic`,
`threat_intelligence.local_lookup`, `provider.lookup` (VT/URLhaus/Web Risk),
`provider.gemini`, `analysis.persistence`, and `threat_feed.refresh`.
No automatic exception recording. Stable structured events include
`analysis_completed`, `provider_call_completed`, `llm_fallback`,
`feed_refresh_completed`, `scan_persistence_failed`, `readiness_failed`,
`feed_job_started`, `feed_job_source_completed`, `feed_job_completed`,
`feed_job_failed`, and telemetry initialization/export/shutdown failures.
Completion events carry bounded outcomes and monotonic `duration_ms` where applicable.
Scan completion no longer logs user IDs.

References consulted: [OTel Python instrumentation](https://opentelemetry.io/docs/languages/python/instrumentation/),
[HTTP metrics conventions](https://opentelemetry.io/docs/specs/semconv/http/http-metrics/),
and [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
(official GitHub source mirrors used where direct outbound access is restricted).

### Metric catalog

All `*.duration` and `*.queue_wait` histograms use **seconds**, not milliseconds.
Counts are monotonic counters; `last_success` is a gauge. No dimension contains
an identifier or arbitrary exception string.

| Instrument | Unit | Dimensions | Interpretation |
|---|---|---|---|
| `http.server.request.duration` | s | `http.request.method`, `url.scheme`, `http.route`, `http.response.status_code`, `status_class`, bounded `error.type` on server errors | Full ASGI request lifetime, including rejection/security middleware |
| `sentinel.http.requests` | `{request}` | Same as HTTP duration | Completed HTTP requests |
| `sentinel.analysis.count` | `{analysis}` | `input_type`, `verdict` | Started analysis that reaches completion/error; validation/rate-limit rejection belongs to HTTP metrics |
| `sentinel.analysis.duration` | s | `input_type`, `verdict` | Analysis function, including heuristics/providers/persistence, excluding auth/rate-limit/serialization |
| `sentinel.provider.calls` | `{call}` | `provider`, `outcome` | Guarded lookup attempts, including queue exhaustion; outer cache hits do not call a provider |
| `sentinel.provider.duration` | s | `provider`, `outcome` | Guarded operation including queue wait; Gemini includes cache recheck/write |
| `sentinel.provider.execution.duration` | s | `provider` | Time holding acquired provider capacity; Gemini includes cache recheck/write, no sample if acquisition failed |
| `sentinel.provider.queue_wait` | s | `provider` | Time waiting for provider semaphore, including failed acquisition; no private semaphore state |
| `sentinel.provider.errors` | `{error}` | `provider`, `outcome` | Non-success excluding intentional skipped/disabled/not_modified |
| `sentinel.provider.exhaustion` | `{error}` | `provider`, `outcome` | `timeout` or `queue_exhausted` subset of errors |
| `sentinel.llm.fallbacks` | `{fallback}` | `reason` | `unconfigured`, `queue_exhausted`, `timeout`, `provider_error`, `invalid_output` |
| `sentinel.cache.accesses` | `{access}` | `provider`, `cache.result` | `hit`/`miss` per existing cache access, including Gemini's existing double-checks, not per HTTP request |
| `sentinel.cache.removals` | `{entry}` | `provider`, `cache.result` | Lazy `expired` removals or capacity `evicted` entries; no cache key |
| `sentinel.feed.attempts` | `{refresh}` | `source` | Refresh entry, including disabled sources |
| `sentinel.feed.outcomes` | `{refresh}` | `source`, `outcome`, `error.type`, `freshness` | Normalized existing refresh result or unexpected failure |
| `sentinel.feed.duration` | s | Same as feed outcomes | Whole refresh, including local lock/queue/fetch/DB phases |
| `sentinel.feed.records` | `{record}` | `source`, `record.type` | `processed`/`inserted` from refresh results |
| `sentinel.feed.last_success` | s | `source` | Unix epoch at observed successful completion/304 in this process; not emitted until success |

LLM fallback counters record newly generated fallbacks consumed by the awaiting
analysis service, once per attempt. Invalid JSON/schema output is `invalid_output`,
not provider success. Cached fallback replay does not increment this counter.
A synchronous worker finishing after its caller times out does not add an
`invalid_output` fallback on top of the already recorded `timeout`.

`input_type`: `url`, `email_text`, `email_header`. `verdict`: `safe`, `warning`,
`danger`, `error`. Providers: `gemini`, `virustotal`, `urlhaus`, `webrisk`,
`threat_feed`, `unknown`. Sources: `phishtank`, `openphish`, `misp`, `unknown`.
Outcomes: `success`, `error`, `failed`, `timeout`, `queue_exhausted`, `skipped`,
`disabled`, `not_modified`, `rate_limited`, `provider_unavailable`, `cancelled`.
Error categories reuse the finite feed validation/network/auth/timeout/DB codes
in `telemetry.ERRORS`; unmapped errors become `unexpected`. Freshness uses the
existing `fresh`, `stale`, `expired`, `never_synced`, `failed`, `disabled` states.
Metric data is process-local and resets on restart. Persistent authoritative feed
freshness/last-success remains in `ThreatFeedState` and the admin feed-state API;
telemetry adds no tables or polling DB callbacks.

### One-shot feed runner — scheduling is NOT deployed

From `backend/`, with the same externally supplied configuration as the web service:

```bash
python -m app.jobs.refresh_threat_feeds
```

The job performs read-only schema verification, opens/closes the existing session
factory, obtains registered providers, and calls the existing sequential refresh-all
orchestrator. Bounded fetch, validation, conditional caching, generation activation
and previous-generation preservation remain unchanged. Manual admin refresh remains
available with the same auth/CSRF/RBAC/rate limit.

Exit **0** means all source results were `success`, `not_modified`, or intentionally
`disabled` (e.g. unconfigured MISP). Exit **1** means any material source failure,
unexpected result, invalid configuration/schema or unreliable overall completion.
An unexpected source error rolls back the session and permits later sources to run;
a failed rollback aborts rather than reusing a broken session. Per-source and final
structured events contain no indicators, URLs or raw exceptions. Shutdown exports
are best effort and do not turn a successful refresh into a data-plane failure.

The refresh-all command attempts **every registered provider on every invocation**
(disabled providers report `disabled`); it has no per-source due-time policy.
Current provider defaults and age-based freshness boundaries are:

| Source | Refresh interval | Fresh through | Stale through | Expired after |
|---|---:|---:|---:|---:|
| PhishTank | 2h | 4h | 8h | 8h |
| OpenPhish | 6h | 12h | 24h | 24h |
| MISP | 24h | 48h | 96h | 96h |

Age is measured since the last successful refresh (including `not_modified`).
`compute_freshness()` reports fresh at age <= 2× interval, stale at
2× interval < age <= 4× interval, and expired above 4× interval. Feed-state reporting
uses the persisted interval when present, otherwise the provider default. Disabled
sources report `disabled`. Enabled sources without a successful sync report
`never_synced`, or `failed` when an error exists. A later error does not reset the age of an earlier success.

**There is no universally suitable source-specific cadence in this runner.** A daily
refresh lets PhishTank expire and OpenPhish become stale; it is not guidance for
keeping all sources fresh. Running refresh-all every two hours instead attempts
OpenPhish and MISP more frequently than their configured intervals. Operators must
explicitly accept that freshness-versus-provider-load tradeoff and verify provider
limits, or defer automated scheduling until source-aware due-time orchestration is
implemented and tested. That orchestration is **not** implemented here.

Existing locks/semaphores are **in-process only**, not distributed locks. Any later
operator-managed scheduling must avoid overlapping web/manual/job refreshes for a
source and separately approve cost, credentials, retention and failure alerts.
**No scheduler or Cron service is configured or provisioned in `render.yaml`.**

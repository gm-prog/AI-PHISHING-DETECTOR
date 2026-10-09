# Task 3.4 — implementation and verification evidence

Date: 2026-10-09. Repository: `gm-prog/AI-PHISHING-DETECTOR`.
Base and verified `origin/main`: `ab173e69b553baf1a38d01ec70b575e9ed951566`.
Workspace was clean on `arena/3256c875-ai-phishing-detector`; no branch switch,
reset, force-push, migration, deployment or production database operation.

## Local checks

Commands below run from `backend/` unless specified. Python tools were installed
in the ignored repository `.venv`; no test/exporter credentials are required.

| Check / command | Exit | Actual result |
|---|---:|---|
| Baseline `PYTHONPATH=. ../.venv/bin/pytest -q` (before editing) | 0 | 169 passed, 12 skipped, 3 warnings |
| Focused `PYTHONPATH=. ../.venv/bin/pytest -q tests/test_operations.py` | 0 | 42 passed, 2 warnings |
| Full SQLite `PYTHONPATH=. ../.venv/bin/pytest -q` | 0 | 211 passed, 12 skipped, 3 warnings |
| PostgreSQL `alembic upgrade head` | 0 | Both existing migrations applied to isolated local PostgreSQL 16.2 |
| PostgreSQL `python -c 'from app.db import verify_schema_invariants; verify_schema_invariants()'` | 0 | Read-only schema verification succeeded |
| Full PostgreSQL-enabled `PYTHONPATH=. ../.venv/bin/pytest -q` | 0 | 223 passed, 3 warnings |
| `../.venv/bin/alembic heads` | 0 | `b4a49925f0e5 (head)` unchanged |
| Root `.venv/bin/bandit -q -r backend/app` | 0 | No findings |
| Root `.venv/bin/pip-audit -r backend/requirements.txt` | 0 | No known vulnerabilities found |
| Frontend `npm ci`, then `npm run build` | 0 | TypeScript and Vite production build succeeded |
| Frontend `npm audit --audit-level=high` | 1 | Existing `source-map-js@1.2.1` high-severity advisory (see blocker below) |
| Root `git diff --check` | 0 | No whitespace errors |

The PostgreSQL run used both `DATABASE_URL` and `SENTINEL_TEST_POSTGRES_URL`:
`postgresql://postgres@localhost/sentinel_test?host=/home/user/.cache/sentinel-pg`.
This is a sandbox-only Unix socket, no listening TCP port, no production connection.
The PostgreSQL binary was supplied by a local-only `pgserver` test utility, **not**
added to application requirements. CI independently uses the existing real
`postgres:16-alpine` service and TCP configuration.

Existing warnings remain: Starlette TestClient/httpx deprecation, Python `crypt`
deprecation, and the legacy HTTP 413 constant. The first exploratory pytest command
from the repository root lacked `PYTHONPATH` and failed collection; the corrected
baseline command above was run successfully before implementation. A first local
PostgreSQL URL omitted the hostname and failed the intentional production-contract
test; the corrected socket URL above satisfies that contract without altering code.

Gitleaks v8.24.3 local installation was attempted through both the GitHub release
URL and asset API. Both redirect to `release-assets.githubusercontent.com`, blocked
by the sandbox outbound allowlist. Do not interpret this as a successful local
secret scan: the unchanged **Repository secret scan** CI job is the authoritative
verification. Exact-head CI results and head/remote SHA matching are recorded in
the PR and delivery report after pushing; no stale run is accepted.

## Known baseline blocker — separate dependency task

The unchanged frontend lockfile pins `source-map-js@1.2.1` (present at the base SHA).
`npm audit` reports **GHSA-68fv-2mgg-jv7q**, high severity: indexed source-map section
offsets can cause event-loop denial of service. npm reports a fix is available.
This is unrelated to telemetry, health or feed jobs. Per the task's explicit rule
not to fix unrelated baseline defects, frontend dependencies/lockfile and CI policy
were not changed or suppressed. A separate narrowly scoped dependency-update task
should validate the patched version with build and audit. Until resolved, do not
claim all four CI gates are green or the full definition of done is satisfied.

## Targeted review

- Explicit attribute allowlists, normalized outcomes and trusted route templates;
  no raw IDs, bodies, query strings, headers, exceptions, credentials or URLs.
  Traceparent only; no baggage/tracestate; trace IDs are not metric dimensions.
- No automatic HTTP/SQL instrumentation or global SDK provider replacement.
  Disabled initialization is inert; enabled providers are idempotent and shut down
  at lifecycle completion. Export failures are sanitized and fail open.
- Bounded SDK span queue and export deadlines; finite metric dimensions. Tests use
  in-memory sinks and throwing exporters, never a real collector/provider.
- Provider ordering, scores, TTLs/keys, queue timeout values, semaphore capacities,
  auth/CSRF/RBAC/rate limits and body limits remain unchanged.
- Existing Gemini `asyncio.to_thread` work cannot forcibly cancel the underlying
  synchronous SDK thread on timeout. That pre-existing resource-control limitation
  is not redesigned here; duration metrics describe the awaited execution window.
- Refresh-all continues after recoverable per-source exceptions, but fails closed
  if rollback fails. Session closure, disabled/304/partial failure and CLI startup
  sanitization are tested. No claim of distributed locking.
- No changes to database models, migrations, `render.yaml`, CI job definitions or
  frontend dependencies. Runtime schema verification remains read-only.
- Collector/backend configuration, actual telemetry delivery, scheduling, alerting,
  and cross-process refresh coordination remain operator/follow-up work. No Cron
  service has been configured or deployed.

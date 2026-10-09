# Task 3.4 — implementation and verification evidence

Date: 2026-10-09. Repository: `gm-prog/AI-PHISHING-DETECTOR`.
Base and verified `origin/main`: `ab173e69b553baf1a38d01ec70b575e9ed951566`.
Workspace was clean on `arena/3256c875-ai-phishing-detector`; no branch switch,
reset, force-push, schema change, deployment or production database operation.

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


## Corrective pass — 2026-10-09

### Verified starting state and preservation

Live PR #4 remained open at `14a1f7d0047971d142644f0b4871ef2072633da4`,
based on unchanged `main` (`ab173e69b553baf1a38d01ec70b575e9ed951566`).
The restored workspace initially had HEAD at that main SHA and Task 3.4 files as
uncommitted changes, with no upstream set on the required Arena branch. Hashing
**every remote-tracked file** against PR head found no differences or extra files.
After staging those exact files, `git diff --cached origin/arena/3256c875-ai-phishing-detector
--exit-code` succeeded and `git merge --ff-only origin/arena/3256c875-ai-phishing-detector`
fast-forwarded to the live head without changing/discarding file content. No reset,
stash, clean, rebase, force-push or branch switch was used. No unexplained remote
commits were overwritten.

### Root cause and correction

The real `_execute_gemini_call()` catches JSON/schema/output extraction failures
inside its validation boundary and returns a heuristic fallback dictionary.
Previously `analyze_with_llm()` treated that as provider success without recording
`invalid_output`. The old mocked-worker ValidationError test bypassed this catch.

The worker now returns a private dict-compatible marker on that existing path.
Only the awaiting service records `invalid_output`, marks the provider outcome
`error`, and strips the marker before the existing cache/write/return path. Public
keys, fallback contents, score floors, verdicts and cache behavior are unchanged.
No worker-side fallback metric is emitted: if a timeout wins and the worker later
finishes with invalid output, the attempt remains one `timeout`, not two fallbacks.
Unconfigured, queue, timeout and provider-error paths keep their categories.

SDK-boundary tests now exercise both Interactions text accessors, direct Generate
Content, and Generate Content compatibility fallback. Across those four paths,
successful, malformed-JSON, schema-invalid and empty outputs verify exact counts,
plain public dictionaries, score floors, provider outcomes, cache replay and privacy.
An additional synchronized late-worker test protects timeout accounting. The SDK
is mocked; the actual worker, parser, validation catch and async service execute.

Scheduling guidance no longer recommends daily refresh-all as universally suitable.
It documents verified 2h/6h/24h source intervals, fresh <=2× / stale <=4× / expired
>4× boundaries, and the explicit freshness-versus-provider-load tradeoff. Twelve
frozen-clock boundary cases protect these existing semantics. No scheduler, feed
implementation, generation logic, locking, database schema or infrastructure changed.

### Fresh verification results

Environment: Python 3.11.2, Node 22.22.3, npm 10.9.8, npm lockfile v3. CI specifies
Python 3.11 and Node 22; npm has no separate repository version pin. Commands use
`PYTHONPATH=.` and `../.venv/bin/pytest` from `backend/`.

| Command/check | Exit | Actual result |
|---|---:|---|
| Pre-correction full `pytest -q` | 0 | 211 passed, 12 PostgreSQL skips, 3 warnings |
| New SDK-boundary tests before fix: `pytest -q tests/test_operations.py -k llm` | 1 | **12 failed**, 9 passed, 37 deselected; reproduced missing accounting |
| Same focused LLM command after fix | 0 | **21 passed**, 37 deselected, 2 warnings |
| `pytest -q tests/test_security_hardening.py -k 'llm or gemini or prompt or provider_queue'` | 0 | **5 passed**, 40 deselected, 2 warnings |
| `pytest -q tests/test_operations.py tests/test_threat_feeds.py` | 0 | **99 passed**, 2 warnings; no skips |
| Full SQLite `pytest -q` | 0 | **239 passed, 12 skipped**, 3 existing warnings |
| Local PostgreSQL 16.2 migrations + read-only verifier | 0 | Passed on isolated Unix-socket test database |
| Full PostgreSQL-enabled `pytest -q` | 0 | **251 passed**, 3 existing warnings; no skips |
| `alembic heads` | 0 | Unchanged `b4a49925f0e5` |
| Root `.venv/bin/bandit -q -r backend/app` | 0 | No findings |
| Root `.venv/bin/pip-audit -r backend/requirements.txt` | 0 | No known vulnerabilities |
| PR #4 frontend `npm audit --audit-level=high` | 1 | Existing `source-map-js@1.2.1` high advisory remains |
| Separate main-derived candidate: `npm ci`, `npm audit --audit-level=high`, `npm run build` | 0 | Clean install, **0 vulnerabilities**, TypeScript/Vite build passed |
| `npm run lint`, both unchanged frontend and candidate | 1 | Same **9 errors, 3 warnings**; pre-existing, not enforced in CI, not fixed here |
| `git diff --check`; dependency patch `git apply --check` | 0 | Passed; dependency change not applied to PR #4 |

PostgreSQL used both `DATABASE_URL` and `SENTINEL_TEST_POSTGRES_URL` set to
`postgresql://postgres@localhost/sentinel_test?host=/home/user/.cache/sentinel-pg-corrective`.
This sandbox-only database has no listening TCP port and is not production.
The preserved four-job GitHub Actions workflow is rerun on the final pushed head;
exact-head conclusions are recorded in the PR/report, not inferred from earlier runs.
Secret scanning is verified through the configured Gitleaks CI job.

### Separate frontend security delivery limitation

The advisory was reverified through GitHub's advisory API and npm registry metadata:
GHSA-68fv-2mgg-jv7q affects >=1.0.0, <1.2.2; first patched version is 1.2.2.
Both `@tailwindcss/vite -> @tailwindcss/node` and `vite -> postcss` require
`source-map-js ^1.2.1`, which accepts 1.2.2. The vulnerable lock entry is identical
to current main, not introduced by Task 3.4.

A main-derived, separate working snapshot was updated with
`npm update source-map-js --package-lock-only --ignore-scripts`. Only the package's
version, tarball URL and integrity hash changed; manifest and all other entries
were verified unchanged. Clean install resolves both chains to **1.2.2**; audit
and build pass. This is supplied as a standalone patch, **not** mixed into PR #4.

The Arena session permits work/pushes only on the existing Task 3.4 branch. Creating
or pushing the requested separate security branch/PR is unavailable in this session.
That deliverable remains **blocked**, requires another session based on verified
main, and has no commit SHA, PR URL or CI run yet. PR #4's frontend audit therefore
remains failing until an independently delivered security fix is integrated into
its test base and checks rerun. No gate has been weakened and no merge is authorized.

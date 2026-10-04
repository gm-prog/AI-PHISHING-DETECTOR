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

"""
Task 3.3 — Production persistence, PostgreSQL portability & deployment contract.

Covers:
  - DATABASE_URL configuration contract (fail-closed production behavior)
  - URL normalization (postgres:// -> postgresql://, parameter preservation)
  - dialect-aware engine creation (SQLite vs PostgreSQL pooling)
  - strictly read-only runtime schema invariant verification on SQLite
  - the same invariant verification against a REAL PostgreSQL server
    (enabled when SENTINEL_TEST_POSTGRES_URL is set, as in CI)

NOTE: any CREATE/INSERT statements in this module are TEST-ONLY fixture
construction against throwaway databases. The runtime verifier itself is
read-only and is proven so by test_startup_schema_verification_immutability
in tests/test_threat_feeds.py.
"""

import os
import sqlite3

import pytest
from alembic import command
from alembic.config import Config as AlembicConfig
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from app.config import (
    DEFAULT_SQLITE_PATH,
    DEFAULT_SQLITE_URL,
    normalize_database_url,
    resolve_database_url,
    validate_database_url,
)
from app.db import (
    ALEMBIC_HEAD_REVISION,
    create_database_engine,
    verify_schema_invariants,
)

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Normalized once so every raw create_engine() helper below uses the
# project's pinned psycopg2 driver spelling.
POSTGRES_URL = normalize_database_url(os.getenv("SENTINEL_TEST_POSTGRES_URL", "").strip())
requires_postgres = pytest.mark.skipif(
    not POSTGRES_URL,
    reason="SENTINEL_TEST_POSTGRES_URL not set; real-PostgreSQL tests run in CI",
)

SECRET_PASSWORD = "sup3r-s3cret-pw"  # test-only marker used to assert non-leakage


def _alembic_upgrade(url: str) -> None:
    cfg = AlembicConfig(os.path.join(BACKEND_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BACKEND_DIR, "alembic"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    command.upgrade(cfg, "head")


# =====================================================================
# Configuration contract
# =====================================================================

class TestDatabaseUrlValidation:
    def test_development_sqlite_fallback(self):
        assert validate_database_url("", "development") == DEFAULT_SQLITE_URL
        assert validate_database_url(None, "development") == DEFAULT_SQLITE_URL

    def test_test_sqlite_fallback(self):
        assert validate_database_url("", "test") == DEFAULT_SQLITE_URL

    def test_fallback_path_is_deterministic_and_absolute(self):
        assert os.path.isabs(DEFAULT_SQLITE_PATH)
        assert DEFAULT_SQLITE_PATH.endswith("phishing_detector.db")

    def test_production_missing_database_url_fails(self):
        with pytest.raises(RuntimeError, match="must be explicitly configured"):
            validate_database_url("", "production")

    def test_production_blank_database_url_fails(self):
        with pytest.raises(RuntimeError, match="must be explicitly configured"):
            validate_database_url("   ", "production")

    def test_production_never_falls_back_to_sqlite(self):
        with pytest.raises(RuntimeError, match="Refusing to fall back to SQLite"):
            validate_database_url("", "production")

    def test_production_sqlite_url_fails(self):
        with pytest.raises(RuntimeError, match="must not point to SQLite"):
            validate_database_url("sqlite:////var/data/prod.db", "production")

    def test_staging_sqlite_url_fails(self):
        with pytest.raises(RuntimeError, match="must not point to SQLite"):
            validate_database_url("sqlite:///staging.db", "staging")

    def test_production_postgresql_url_succeeds(self):
        url = "postgresql://user:pass@db.internal:5432/sentinel"
        assert (
            validate_database_url(url, "production")
            == "postgresql+psycopg2://user:pass@db.internal:5432/sentinel"
        )

    def test_production_explicit_psycopg2_driver_succeeds(self):
        url = "postgresql+psycopg2://user:pass@db.internal:5432/sentinel"
        assert validate_database_url(url, "production") == url

    def test_production_unsupported_scheme_fails(self):
        with pytest.raises(RuntimeError, match="not supported"):
            validate_database_url("mysql://user:pass@host:3306/db", "production")

    def test_production_unsupported_postgres_driver_fails(self):
        # One deliberate driver architecture: asyncpg is not installed.
        with pytest.raises(RuntimeError, match="not supported"):
            validate_database_url("postgresql+asyncpg://u:p@h:5432/db", "production")

    def test_production_malformed_url_fails(self):
        with pytest.raises(RuntimeError, match="malformed"):
            validate_database_url(
                f"postgresql://user:{SECRET_PASSWORD}@host:not_a_port/db", "production"
            )

    def test_production_missing_host_fails(self):
        with pytest.raises(RuntimeError, match="missing a hostname"):
            validate_database_url("postgresql:///dbname", "production")

    def test_production_missing_database_name_fails(self):
        with pytest.raises(RuntimeError, match="missing a database name"):
            validate_database_url("postgresql://user:pass@host:5432", "production")

    def test_development_explicit_postgres_url_is_allowed(self):
        url = "postgresql://user:pass@localhost:5432/dev"
        assert validate_database_url(url, "development") == normalize_database_url(url)

    def test_development_unsupported_scheme_fails(self):
        with pytest.raises(RuntimeError, match="not supported"):
            validate_database_url("mysql://u:p@h/db", "development")

    def test_validation_errors_never_leak_credentials(self):
        failing_urls = [
            (f"mysql://user:{SECRET_PASSWORD}@host:3306/db", "production"),
            (f"postgresql://user:{SECRET_PASSWORD}@host:not_a_port/db", "production"),
            (f"postgresql+asyncpg://user:{SECRET_PASSWORD}@host:5432/db", "production"),
            (f"sqlite:///{SECRET_PASSWORD}.db", "production"),
        ]
        for url, env in failing_urls:
            with pytest.raises(RuntimeError) as excinfo:
                validate_database_url(url, env)
            assert SECRET_PASSWORD not in str(excinfo.value), (
                "validation error must not leak database credentials"
            )

    def test_resolve_database_url_explicit_arguments(self):
        assert resolve_database_url("development", "") == DEFAULT_SQLITE_URL
        assert resolve_database_url("test", "") == DEFAULT_SQLITE_URL
        url = "postgresql://u:p@h:5432/prod"
        assert resolve_database_url("production", url) == normalize_database_url(url)
        with pytest.raises(RuntimeError):
            resolve_database_url("production", "")


class TestProductionImportFailClosed:
    """Prove that application *startup* (module import) fails closed."""

    def _run_config_import(self, extra_env):
        import subprocess
        import sys

        env = os.environ.copy()
        env.update({
            "ENVIRONMENT": "production",
            "ALLOWED_ORIGINS": "https://app.example.com",
            "RATE_LIMIT_STORAGE_URI": "rediss://redis.example.com:6379/0",
        })
        env.pop("DATABASE_URL", None)
        env.update(extra_env)
        return subprocess.run(
            [sys.executable, "-c", "import app.config"],
            cwd=BACKEND_DIR,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_import_fails_without_database_url(self):
        result = self._run_config_import({})
        assert result.returncode != 0
        assert "DATABASE_URL must be explicitly configured" in (result.stderr + result.stdout)

    def test_import_fails_with_sqlite_database_url(self):
        result = self._run_config_import({"DATABASE_URL": "sqlite:///prod.db"})
        assert result.returncode != 0
        assert "must not point to SQLite" in (result.stderr + result.stdout)

    def test_import_succeeds_with_postgresql_database_url(self):
        result = self._run_config_import(
            {"DATABASE_URL": "postgresql://user:pass@db.internal:5432/sentinel"}
        )
        assert result.returncode == 0, result.stderr


# =====================================================================
# Alembic URL resolution (env.py) — corrective-patch regression
# =====================================================================

def _load_resolve_alembic_url(fake_config, env_database_url=None, app_fallback="sqlite:///app-fallback.db"):
    """
    Execute the REAL `_resolve_alembic_url()` function from
    backend/alembic/env.py (extracted via AST so importing env.py does not
    trigger migration execution) against a stub Alembic config object.
    No database connection is required or made.
    """
    import ast

    env_path = os.path.join(BACKEND_DIR, "alembic", "env.py")
    with open(env_path, "r", encoding="utf-8") as f:
        tree = ast.parse(f.read(), filename=env_path)

    func = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "_resolve_alembic_url"
    )
    module = ast.Module(body=[func], type_ignores=[])

    class _FakeEnviron:
        def __init__(self, database_url):
            self._database_url = database_url

        def getenv(self, key, default=""):
            if key == "DATABASE_URL" and self._database_url is not None:
                return self._database_url
            return default if key == "DATABASE_URL" else os.getenv(key, default)

    namespace = {
        "os": _FakeEnviron(env_database_url),
        "config": fake_config,
        "normalize_database_url": normalize_database_url,
        "SQLALCHEMY_DATABASE_URL": app_fallback,
    }
    exec(compile(module, env_path, "exec"), namespace)  # noqa: S102 — test-only, fixed local file
    return namespace["_resolve_alembic_url"]


class _FakeAlembicConfig:
    """Mimics alembic.config.Config for URL-resolution purposes."""

    def __init__(self, override=None):
        self.config_file_name = os.path.join(BACKEND_DIR, "alembic.ini")
        self._override = override

    def get_main_option(self, name):
        assert name == "sqlalchemy.url"
        if self._override is not None:
            return self._override
        # No programmatic override: return the pristine ini value.
        import configparser

        parser = configparser.ConfigParser()
        parser.read(self.config_file_name)
        return parser.get("alembic", "sqlalchemy.url", raw=True)


class TestResolveAlembicUrl:
    def test_programmatic_legacy_postgres_override_is_normalized(self):
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override="postgres://u:p@host:5432/db")
        )
        assert resolve() == "postgresql+psycopg2://u:p@host:5432/db"

    def test_programmatic_generic_postgresql_override_is_normalized(self):
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override="postgresql://u:p@host:5432/db")
        )
        assert resolve() == "postgresql+psycopg2://u:p@host:5432/db"

    def test_programmatic_override_takes_precedence_over_database_url_env(self):
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override="postgres://u:p@override-host:5432/override_db"),
            env_database_url="postgresql://ignored:ignored@env-host:5432/env_db",
        )
        assert resolve() == "postgresql+psycopg2://u:p@override-host:5432/override_db"

    def test_database_url_env_used_and_normalized_without_override(self):
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override=None),
            env_database_url="postgres://u:p@env-host:5432/env_db",
        )
        assert resolve() == "postgresql+psycopg2://u:p@env-host:5432/env_db"

    def test_application_fallback_without_override_or_env(self):
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override=None),
            env_database_url=None,
            app_fallback="sqlite:///app-fallback.db",
        )
        assert resolve() == "sqlite:///app-fallback.db"

    def test_sqlite_programmatic_override_passes_through_unchanged(self):
        # Existing test harnesses override with temp SQLite files; the
        # normalization contract must not disturb them.
        resolve = _load_resolve_alembic_url(
            _FakeAlembicConfig(override="sqlite:////tmp/some-test.db")
        )
        assert resolve() == "sqlite:////tmp/some-test.db"

    def test_normalized_override_preserves_every_url_component(self):
        raw = (
            "postgres://alice:p%40ss%2Fw%25rd@db.internal:6543/sentinel"
            "?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fca.pem&connect_timeout=5"
        )
        resolve = _load_resolve_alembic_url(_FakeAlembicConfig(override=raw))
        resolved = resolve()
        # Scheme-only rewrite: everything after '://' is byte-identical.
        assert resolved.split("://", 1)[1] == raw.split("://", 1)[1]
        parsed = make_url(resolved)
        assert parsed.drivername == "postgresql+psycopg2"
        assert parsed.username == "alice"
        assert parsed.password == "p@ss/w%rd"  # percent-encoding preserved
        assert parsed.host == "db.internal"
        assert parsed.port == 6543
        assert parsed.database == "sentinel"
        assert parsed.query["sslmode"] == "verify-full"
        assert parsed.query["sslrootcert"] == "/etc/ssl/ca.pem"
        assert parsed.query["connect_timeout"] == "5"


# =====================================================================
# URL normalization
# =====================================================================

class TestNormalizeDatabaseUrl:
    def test_legacy_postgres_scheme_is_translated(self):
        assert (
            normalize_database_url("postgres://u:p@h:5432/db")
            == "postgresql+psycopg2://u:p@h:5432/db"
        )

    def test_modern_postgresql_scheme_remains_valid(self):
        # "postgresql://" stays a valid input; it is pinned to the project's
        # single deliberate driver (psycopg2) so the installed DBAPI always
        # matches the SQLAlchemy URL scheme.
        url = "postgresql://u:p@h:5432/db"
        normalized = normalize_database_url(url)
        assert normalized == "postgresql+psycopg2://u:p@h:5432/db"
        assert make_url(normalized).get_backend_name() == "postgresql"

    def test_explicit_psycopg2_scheme_is_unchanged(self):
        url = "postgresql+psycopg2://u:p@h:5432/db"
        assert normalize_database_url(url) == url

    def test_sqlite_url_is_unchanged(self):
        url = "sqlite:///some/local.db"
        assert normalize_database_url(url) == url

    def test_query_parameters_are_preserved(self):
        raw = "postgres://u:p@h:5432/db?sslmode=require&connect_timeout=5"
        normalized = normalize_database_url(raw)
        assert normalized == "postgresql+psycopg2://u:p@h:5432/db?sslmode=require&connect_timeout=5"
        parsed = make_url(normalized)
        assert parsed.query["sslmode"] == "require"
        assert parsed.query["connect_timeout"] == "5"

    def test_ssl_parameters_survive_round_trip(self):
        raw = "postgres://u:p@h/db?sslmode=verify-full&sslrootcert=%2Fetc%2Fssl%2Fca.pem"
        parsed = make_url(normalize_database_url(raw))
        assert parsed.query["sslmode"] == "verify-full"

    def test_encoded_password_characters_remain_safe(self):
        raw = "postgres://user:p%40ss%2Fw%25rd@h:5432/db"
        normalized = normalize_database_url(raw)
        assert normalized.startswith("postgresql+psycopg2://")
        # Only the scheme token may change; everything after '://' is intact.
        assert normalized.split("://", 1)[1] == raw.split("://", 1)[1]
        assert make_url(normalized).password == "p@ss/w%rd"

    def test_whitespace_is_stripped(self):
        assert normalize_database_url("  postgresql://u:p@h/db \n") == "postgresql+psycopg2://u:p@h/db"

    def test_empty_and_none_inputs(self):
        assert normalize_database_url("") == ""
        assert normalize_database_url(None) == ""


# =====================================================================
# Engine behavior
# =====================================================================

class TestCreateDatabaseEngine:
    def test_sqlite_engine_creation_and_dialect(self, tmp_path):
        engine = create_database_engine(f"sqlite:///{tmp_path / 'engine_test.db'}")
        try:
            assert engine.dialect.name == "sqlite"
            with engine.connect() as conn:
                assert conn.execute(text("SELECT 1")).scalar() == 1
        finally:
            engine.dispose()

    def test_sqlite_engine_does_not_receive_postgres_pool_settings(self, tmp_path):
        engine = create_database_engine(f"sqlite:///{tmp_path / 'engine_pool.db'}")
        try:
            # pool_pre_ping / pool_size / max_overflow / pool_recycle must NOT
            # be applied to the SQLite engine.
            assert getattr(engine.pool, "_pre_ping", False) is False
            assert engine.pool._recycle == -1
        finally:
            engine.dispose()

    def test_sqlite_engine_allows_cross_thread_usage(self, tmp_path):
        # check_same_thread=False is preserved for SQLite.
        engine = create_database_engine(f"sqlite:///{tmp_path / 'engine_thread.db'}")
        try:
            import threading

            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            errors = []

            def use_from_thread():
                try:
                    with engine.connect() as conn:
                        conn.execute(text("SELECT 1"))
                except Exception as exc:  # pragma: no cover
                    errors.append(exc)

            t = threading.Thread(target=use_from_thread)
            t.start()
            t.join()
            assert not errors
        finally:
            engine.dispose()

    def test_postgresql_engine_creation_pooling_and_dialect(self):
        # Engine construction is lazy: no server connection is made here.
        engine = create_database_engine("postgresql://u:p@localhost:5432/nonexistent")
        try:
            assert engine.dialect.name == "postgresql"
            assert engine.dialect.driver == "psycopg2"
            assert engine.pool._pre_ping is True
            assert engine.pool.size() == 10
            assert engine.pool._max_overflow == 20
            assert engine.pool._recycle == 1800
        finally:
            engine.dispose()

    def test_correct_dialect_detection_for_both_backends(self, tmp_path):
        sqlite_engine = create_database_engine(f"sqlite:///{tmp_path / 'd.db'}")
        pg_engine = create_database_engine("postgresql://u:p@localhost:5432/x")
        try:
            assert sqlite_engine.dialect.name == "sqlite"
            assert pg_engine.dialect.name == "postgresql"
        finally:
            sqlite_engine.dispose()
            pg_engine.dispose()


# =====================================================================
# Runtime schema invariant verification — SQLite
# =====================================================================

@pytest.fixture()
def migrated_sqlite_db(tmp_path):
    """A real Alembic-migrated SQLite database at head revision."""
    db_file = str(tmp_path / "task33_sqlite.db")
    _alembic_upgrade(f"sqlite:///{db_file}")
    return db_file


class TestSchemaVerificationSqlite:
    def test_migrated_database_passes(self, migrated_sqlite_db):
        verify_schema_invariants(migrated_sqlite_db)

    def test_accepts_sqlalchemy_url_target(self, migrated_sqlite_db):
        verify_schema_invariants(f"sqlite:///{migrated_sqlite_db}")

    def test_missing_table_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("DROP TABLE threat_feed_states")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="missing required table.*threat_feed_states"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_wrong_alembic_revision_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("UPDATE alembic_version SET version_num = 'deadbeef0000'")
        conn.commit()
        conn.close()
        with pytest.raises(
            RuntimeError,
            match=f"revision 'deadbeef0000', expected head revision '{ALEMBIC_HEAD_REVISION}'",
        ):
            verify_schema_invariants(migrated_sqlite_db)

    def test_zero_version_rows_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("DELETE FROM alembic_version")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="'alembic_version' table is empty"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_multiple_version_rows_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("INSERT INTO alembic_version (version_num) VALUES ('ffffffffffff')")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="expected exactly one Alembic migration revision"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_missing_required_index_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("DROP INDEX ix_threat_indicators_generation_id")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="missing index.*ix_threat_indicators_generation_id"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_missing_ownership_index_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.execute("DROP INDEX ix_scan_history_user_id")
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="required ownership index missing on 'scan_history'"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_nullable_generation_id_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.executescript(
            """
            DROP TABLE threat_indicators;
            CREATE TABLE threat_indicators (
                id VARCHAR(36) PRIMARY KEY, source VARCHAR(64) NOT NULL,
                indicator_type VARCHAR(32) NOT NULL, indicator VARCHAR(2048) NOT NULL,
                indicator_hash VARCHAR(64) NOT NULL, classification VARCHAR(64) NOT NULL,
                confidence FLOAT NOT NULL, observed_at VARCHAR(32) NOT NULL,
                expires_at VARCHAR(32), generation_id VARCHAR(36),
                created_at VARCHAR(32) NOT NULL, updated_at VARCHAR(32) NOT NULL,
                CONSTRAINT uq_source_gen_type_indicator UNIQUE (source, generation_id, indicator_type, indicator_hash)
            );
            CREATE INDEX ix_threat_indicators_source ON threat_indicators (source);
            CREATE INDEX ix_threat_indicators_indicator_type ON threat_indicators (indicator_type);
            CREATE INDEX ix_threat_indicators_indicator_hash ON threat_indicators (indicator_hash);
            CREATE INDEX ix_threat_indicators_classification ON threat_indicators (classification);
            CREATE INDEX ix_threat_indicators_expires_at ON threat_indicators (expires_at);
            CREATE INDEX ix_threat_indicators_generation_id ON threat_indicators (generation_id);
            """
        )
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="'generation_id' must be NOT NULL"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_legacy_unique_constraint_state_fails(self, migrated_sqlite_db):
        conn = sqlite3.connect(migrated_sqlite_db)
        conn.executescript(
            """
            DROP TABLE threat_indicators;
            CREATE TABLE threat_indicators (
                id VARCHAR(36) PRIMARY KEY, source VARCHAR(64) NOT NULL,
                indicator_type VARCHAR(32) NOT NULL, indicator VARCHAR(2048) NOT NULL,
                indicator_hash VARCHAR(64) NOT NULL, classification VARCHAR(64) NOT NULL,
                confidence FLOAT NOT NULL, observed_at VARCHAR(32) NOT NULL,
                expires_at VARCHAR(32), generation_id VARCHAR(36) NOT NULL,
                created_at VARCHAR(32) NOT NULL, updated_at VARCHAR(32) NOT NULL,
                CONSTRAINT uq_source_type_indicator UNIQUE (source, indicator_type, indicator_hash)
            );
            CREATE INDEX ix_threat_indicators_source ON threat_indicators (source);
            CREATE INDEX ix_threat_indicators_indicator_type ON threat_indicators (indicator_type);
            CREATE INDEX ix_threat_indicators_indicator_hash ON threat_indicators (indicator_hash);
            CREATE INDEX ix_threat_indicators_classification ON threat_indicators (classification);
            CREATE INDEX ix_threat_indicators_expires_at ON threat_indicators (expires_at);
            CREATE INDEX ix_threat_indicators_generation_id ON threat_indicators (generation_id);
            """
        )
        conn.commit()
        conn.close()
        with pytest.raises(RuntimeError, match="uq_source_gen_type_indicator' constraint missing"):
            verify_schema_invariants(migrated_sqlite_db)

    def test_nonexistent_database_fails(self, tmp_path):
        with pytest.raises(RuntimeError, match="does not exist or is uninitialized"):
            verify_schema_invariants(str(tmp_path / "missing.db"))

    def test_verifier_cannot_write_to_database(self, migrated_sqlite_db):
        """The verification connection is opened read-only at the DB layer."""
        from app.db import _read_only_verification_engine

        engine, _ = _read_only_verification_engine(f"sqlite:///{migrated_sqlite_db}")
        try:
            with engine.connect() as conn:
                with pytest.raises(Exception, match="readonly|attempt to write"):
                    conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('x')"))
                    conn.commit()
        finally:
            engine.dispose()


# =====================================================================
# Runtime schema invariant verification — real PostgreSQL
# =====================================================================

def _reset_postgres_schema(url: str) -> None:
    """TEST-ONLY: wipe the throwaway CI/test PostgreSQL schema."""
    engine = create_engine(url, poolclass=NullPool, isolation_level="AUTOCOMMIT")
    try:
        with engine.connect() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE"))
            conn.execute(text("CREATE SCHEMA public"))
    finally:
        engine.dispose()


@pytest.fixture()
def migrated_postgres():
    """A real PostgreSQL database migrated to the Alembic head revision."""
    _reset_postgres_schema(POSTGRES_URL)
    _alembic_upgrade(POSTGRES_URL)
    yield POSTGRES_URL
    # Leave the schema migrated so subsequent consumers see a valid state.
    _reset_postgres_schema(POSTGRES_URL)
    _alembic_upgrade(POSTGRES_URL)


@requires_postgres
class TestSchemaVerificationPostgres:
    def test_alembic_migration_and_verification_pass(self, migrated_postgres):
        verify_schema_invariants(migrated_postgres)

    def test_alembic_head_recorded(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.connect() as conn:
                rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
            assert rows == [(ALEMBIC_HEAD_REVISION,)]
        finally:
            engine.dispose()

    def test_schema_invariants_present_via_inspection(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())
            assert {
                "users", "user_sessions", "scan_history",
                "threat_indicators", "threat_feed_states", "alembic_version",
            } <= tables

            ti_cols = {c["name"]: c for c in inspector.get_columns("threat_indicators")}
            assert ti_cols["generation_id"]["nullable"] is False

            uq_names = {u["name"] for u in inspector.get_unique_constraints("threat_indicators")}
            assert "uq_source_gen_type_indicator" in uq_names
            assert "uq_source_type_indicator" not in uq_names

            idx_names = {i["name"] for i in inspector.get_indexes("threat_indicators")}
            assert {
                "ix_threat_indicators_source",
                "ix_threat_indicators_indicator_type",
                "ix_threat_indicators_indicator_hash",
                "ix_threat_indicators_classification",
                "ix_threat_indicators_expires_at",
                "ix_threat_indicators_generation_id",
            } <= idx_names
        finally:
            engine.dispose()

    def test_wrong_alembic_revision_fails(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.begin() as conn:
                conn.execute(text("UPDATE alembic_version SET version_num = 'deadbeef0000'"))
            with pytest.raises(RuntimeError, match="expected head revision"):
                verify_schema_invariants(migrated_postgres)
        finally:
            engine.dispose()

    def test_zero_version_rows_fails(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.begin() as conn:
                conn.execute(text("DELETE FROM alembic_version"))
            with pytest.raises(RuntimeError, match="'alembic_version' table is empty"):
                verify_schema_invariants(migrated_postgres)
        finally:
            engine.dispose()

    def test_multiple_version_rows_fails(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.begin() as conn:
                conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('ffffffffffff')"))
            with pytest.raises(RuntimeError, match="expected exactly one Alembic migration revision"):
                verify_schema_invariants(migrated_postgres)
        finally:
            engine.dispose()

    def test_missing_table_fails(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.begin() as conn:
                conn.execute(text("DROP TABLE threat_feed_states"))
            with pytest.raises(RuntimeError, match="missing required table.*threat_feed_states"):
                verify_schema_invariants(migrated_postgres)
        finally:
            engine.dispose()

    def test_missing_required_index_fails(self, migrated_postgres):
        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with engine.begin() as conn:
                conn.execute(text("DROP INDEX ix_threat_indicators_generation_id"))
            with pytest.raises(RuntimeError, match="missing index.*ix_threat_indicators_generation_id"):
                verify_schema_invariants(migrated_postgres)
        finally:
            engine.dispose()

    def test_verifier_is_read_only_against_postgres(self, migrated_postgres):
        """The PG verification session runs with default_transaction_read_only=on."""
        from app.db import _read_only_verification_engine

        engine, _ = _read_only_verification_engine(migrated_postgres)
        try:
            with engine.connect() as conn:
                with pytest.raises(Exception, match="read-only"):
                    conn.execute(text("INSERT INTO alembic_version (version_num) VALUES ('x')"))
        finally:
            engine.dispose()

    def test_generation_id_not_null_enforced_by_database(self, migrated_postgres):
        from sqlalchemy.exc import IntegrityError

        engine = create_engine(migrated_postgres, poolclass=NullPool)
        try:
            with pytest.raises(IntegrityError):
                with engine.begin() as conn:
                    conn.execute(text(
                        "INSERT INTO threat_indicators "
                        "(id, source, indicator_type, indicator, indicator_hash, classification, "
                        " confidence, observed_at, generation_id, created_at, updated_at) "
                        "VALUES ('x1', 's', 'url', 'https://x', 'h', 'phishing', 1.0, 't', NULL, 't', 't')"
                    ))
        finally:
            engine.dispose()

    def test_production_contract_accepts_this_real_url(self):
        assert validate_database_url(POSTGRES_URL, "production") == normalize_database_url(POSTGRES_URL)

    def test_engine_connects_to_real_postgres(self):
        engine = create_database_engine(POSTGRES_URL)
        try:
            assert engine.dialect.name == "postgresql"
            with engine.connect() as conn:
                value = conn.execute(text("SELECT 1")).scalar()
            assert value == 1
        finally:
            engine.dispose()

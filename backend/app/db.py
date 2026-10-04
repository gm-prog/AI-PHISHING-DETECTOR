import os
from typing import Optional

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

from app.config import (
    DATABASE_URL_RESOLVED,
    DEFAULT_SQLITE_PATH,
    normalize_database_url,
)

# Backwards-compatible module constants.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = DEFAULT_SQLITE_PATH

# The effective database URL is resolved (and fail-closed validated) by the
# configuration contract in app.config:
#   development/test -> DATABASE_URL if supplied, else deterministic SQLite
#   staging/production -> explicit PostgreSQL DATABASE_URL (never SQLite)
SQLALCHEMY_DATABASE_URL = DATABASE_URL_RESOLVED

ALEMBIC_HEAD_REVISION = "b4a49925f0e5"

REQUIRED_TABLES = {
    "users",
    "user_sessions",
    "scan_history",
    "threat_indicators",
    "threat_feed_states",
    "alembic_version",
}

REQUIRED_THREAT_INDICATOR_INDEXES = {
    "ix_threat_indicators_source",
    "ix_threat_indicators_indicator_type",
    "ix_threat_indicators_indicator_hash",
    "ix_threat_indicators_classification",
    "ix_threat_indicators_expires_at",
    "ix_threat_indicators_generation_id",
}


def create_database_engine(database_url: str, **overrides) -> Engine:
    """
    Dialect-aware SQLAlchemy engine factory.

    - SQLite (development/test): keeps the historical check_same_thread=False
      behavior; PostgreSQL-only pool arguments are never passed to SQLite.
    - PostgreSQL (staging/production): connection health and pooling settings
      appropriate for a long-lived web service.
    """
    database_url = normalize_database_url(database_url)
    url = make_url(database_url)
    if url.get_backend_name() == "sqlite":
        connect_args = dict(overrides.pop("connect_args", {}))
        connect_args.setdefault("check_same_thread", False)
        return create_engine(database_url, connect_args=connect_args, **overrides)

    kwargs = {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 20,
        "pool_recycle": 1800,
    }
    kwargs.update(overrides)
    return create_engine(database_url, **kwargs)


def _read_only_verification_engine(url_str: str):
    """
    Build a short-lived engine whose connections are read-only wherever the
    backend can enforce it:

    - SQLite: opened via a 'mode=ro' URI, so any write attempt fails at the
      database layer.
    - PostgreSQL: the session is started with
      default_transaction_read_only=on, so any write attempt fails at the
      database layer.

    Returns (engine, display_target) where display_target never contains
    credentials.
    """
    url_str = normalize_database_url(url_str)
    url = make_url(url_str)
    backend = url.get_backend_name()

    if backend == "sqlite":
        db_file = url.database or ""
        display = db_file or url.render_as_string(hide_password=True)
        if db_file and db_file != ":memory:":
            if not os.path.exists(db_file) or os.path.getsize(db_file) == 0:
                raise RuntimeError(
                    f"Database file '{db_file}' does not exist or is uninitialized. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            ro_url = f"sqlite:///file:{db_file}?mode=ro&uri=true"
        else:
            ro_url = url_str
        engine = create_engine(
            ro_url,
            poolclass=NullPool,
            connect_args={"check_same_thread": False},
        )
        return engine, display

    display = url.render_as_string(hide_password=True)
    if backend == "postgresql":
        engine = create_engine(
            url_str,
            poolclass=NullPool,
            connect_args={"options": "-c default_transaction_read_only=on"},
        )
        return engine, display

    # Any other dialect: still verify strictly via inspection-only queries.
    engine = create_engine(url_str, poolclass=NullPool)
    return engine, display


def verify_schema_invariants(database_target: Optional[str] = None) -> None:
    """
    Validates required schema invariants and the Alembic head revision at
    application startup without mutating the database.

    database_target may be:
      - None: verify the application's configured database
      - a SQLAlchemy database URL (SQLite or PostgreSQL)
      - a plain SQLite file path (backwards compatible)

    Strictly read-only and database-dialect-aware: all checks use SQLAlchemy
    inspection facilities plus plain SELECTs. Fails closed with a clear
    RuntimeError if tables, columns, constraints, indexes, or NOT NULL
    requirements are uninitialized or incompatible, instructing the operator
    to execute 'alembic upgrade head'. It never executes CREATE/ALTER/DROP/
    INSERT/UPDATE/DELETE and never performs implicit schema repair.
    """
    if database_target is None:
        url_str = SQLALCHEMY_DATABASE_URL
    elif "://" in database_target:
        url_str = database_target
    else:
        # Backwards-compatible: a bare SQLite file path.
        url_str = f"sqlite:///{database_target}"

    engine, target_db = _read_only_verification_engine(url_str)

    try:
        with engine.connect() as conn:
            inspector = inspect(conn)

            # 1. Verify all required application tables exist
            existing_tables = set(inspector.get_table_names())
            missing_tables = REQUIRED_TABLES - existing_tables
            if missing_tables:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing required table(s): {sorted(missing_tables)}. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 2. Verify Alembic migration head revision
            version_rows = conn.execute(text("SELECT version_num FROM alembic_version")).fetchall()
            if len(version_rows) == 0:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: 'alembic_version' table is empty. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            if len(version_rows) != 1:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: expected exactly one Alembic migration revision in 'alembic_version', found {len(version_rows)}. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            found_revision = version_rows[0][0]
            if not found_revision:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: 'alembic_version' table is empty. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            if found_revision != ALEMBIC_HEAD_REVISION:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: database is at migration revision '{found_revision}', "
                    f"expected head revision '{ALEMBIC_HEAD_REVISION}'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 3. Verify 'users' table columns
            user_cols = {col["name"] for col in inspector.get_columns("users")}
            required_user_cols = {"id", "email", "hashed_password", "role", "is_active"}
            if not required_user_cols.issubset(user_cols):
                missing = required_user_cols - user_cols
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'users'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 3b. Verify 'user_sessions' table columns
            session_cols = {col["name"] for col in inspector.get_columns("user_sessions")}
            required_session_cols = {"id", "user_id", "session_id_hash", "expires_at"}
            if not required_session_cols.issubset(session_cols):
                missing = required_session_cols - session_cols
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'user_sessions'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 4. Verify 'scan_history' table columns and ownership indexes
            scan_cols = {col["name"] for col in inspector.get_columns("scan_history")}
            required_scan_cols = {"id", "user_id", "guest_session_hash", "timestamp", "input_type", "content", "risk_score", "status"}
            if not required_scan_cols.issubset(scan_cols):
                missing = required_scan_cols - scan_cols
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'scan_history'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            scan_indexes = {idx["name"] for idx in inspector.get_indexes("scan_history")}
            if "ix_scan_history_user_id" not in scan_indexes or "ix_scan_history_guest_session_hash" not in scan_indexes:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: required ownership index missing on 'scan_history'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 5. Verify 'threat_indicators' columns, NOT NULL invariants, constraints, and indexes
            ti_columns = {col["name"]: col for col in inspector.get_columns("threat_indicators")}
            if "generation_id" not in ti_columns:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: 'generation_id' column is missing from 'threat_indicators'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            if ti_columns["generation_id"].get("nullable", True):
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: 'generation_id' must be NOT NULL in 'threat_indicators'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            unique_constraint_names = {
                uc.get("name")
                for uc in inspector.get_unique_constraints("threat_indicators")
                if uc.get("name")
            }
            # Unique constraints may surface as unique indexes on some backends.
            ti_index_info = inspector.get_indexes("threat_indicators")
            unique_index_names = {idx["name"] for idx in ti_index_info if idx.get("unique")}
            if "uq_source_gen_type_indicator" not in (unique_constraint_names | unique_index_names):
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: 'uq_source_gen_type_indicator' constraint missing on 'threat_indicators'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )
            if "uq_source_type_indicator" in (unique_constraint_names | unique_index_names):
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: legacy 'uq_source_type_indicator' constraint still present on 'threat_indicators'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            ti_indexes = {idx["name"] for idx in ti_index_info}
            missing_ti_indexes = REQUIRED_THREAT_INDICATOR_INDEXES - ti_indexes
            if missing_ti_indexes:
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing index(es) {sorted(missing_ti_indexes)} on 'threat_indicators'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

            # 6. Verify 'threat_feed_states' table columns
            state_cols = {col["name"] for col in inspector.get_columns("threat_feed_states")}
            required_state_cols = {"source", "enabled", "status", "freshness", "current_generation_id", "refresh_interval_seconds", "updated_at"}
            if not required_state_cols.issubset(state_cols):
                missing = required_state_cols - state_cols
                raise RuntimeError(
                    f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'threat_feed_states'. "
                    "Please run 'alembic upgrade head' before starting the application."
                )

    except SQLAlchemyError as e:
        raise RuntimeError(f"Database schema verification failed on {target_db}: {e}") from e
    finally:
        engine.dispose()


# Compatibility alias
ensure_schema_migrations = verify_schema_invariants

engine = create_database_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

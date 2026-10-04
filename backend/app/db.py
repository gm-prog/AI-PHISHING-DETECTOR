import os
import sqlite3
from typing import Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Always use an absolute path for the SQLite database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "phishing_detector.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

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


def verify_schema_invariants(db_path: Optional[str] = None) -> None:
    """
    Validates required schema invariants and Alembic head revision at application startup without mutating the database.
    Strictly read-only: fails closed with a clear RuntimeError if tables, columns, constraints,
    or NOT NULL requirements are uninitialized or incompatible.
    Instructs the operator to execute 'alembic upgrade head'.
    """
    target_db = db_path if db_path is not None else DB_PATH

    if not os.path.exists(target_db) or os.path.getsize(target_db) == 0:
        raise RuntimeError(
            f"Database file '{target_db}' does not exist or is uninitialized. "
            "Please run 'alembic upgrade head' before starting the application."
        )

    conn = None
    try:
        conn = sqlite3.connect(f"file:{target_db}?mode=ro", uri=True)
        cursor = conn.cursor()

        # 1. Verify all required application tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = set(r[0] for r in cursor.fetchall())
        missing_tables = REQUIRED_TABLES - existing_tables
        if missing_tables:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing required table(s): {sorted(missing_tables)}. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        # 2. Verify Alembic migration head revision
        cursor.execute("SELECT version_num FROM alembic_version")
        version_rows = cursor.fetchall()
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
        cursor.execute("PRAGMA table_info(users)")
        user_cols = {row[1] for row in cursor.fetchall()}
        required_user_cols = {"id", "email", "hashed_password", "role", "is_active"}
        if not required_user_cols.issubset(user_cols):
            missing = required_user_cols - user_cols
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'users'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        # 3. Verify 'user_sessions' table columns and indexes
        cursor.execute("PRAGMA table_info(user_sessions)")
        session_cols = {row[1] for row in cursor.fetchall()}
        required_session_cols = {"id", "user_id", "session_id_hash", "expires_at"}
        if not required_session_cols.issubset(session_cols):
            missing = required_session_cols - session_cols
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'user_sessions'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        # 4. Verify 'scan_history' table columns and ownership indexes
        cursor.execute("PRAGMA table_info(scan_history)")
        scan_cols = {row[1] for row in cursor.fetchall()}
        required_scan_cols = {"id", "user_id", "guest_session_hash", "timestamp", "input_type", "content", "risk_score", "status"}
        if not required_scan_cols.issubset(scan_cols):
            missing = required_scan_cols - scan_cols
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'scan_history'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        cursor.execute("PRAGMA index_list(scan_history)")
        scan_indexes = {row[1] for row in cursor.fetchall()}
        if "ix_scan_history_user_id" not in scan_indexes or "ix_scan_history_guest_session_hash" not in scan_indexes:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: required ownership index missing on 'scan_history'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        # 5. Verify 'threat_indicators' table columns, NOT NULL invariants, constraints, and indexes
        cursor.execute("PRAGMA table_info(threat_indicators)")
        cols_info = {row[1]: row for row in cursor.fetchall()}
        if "generation_id" not in cols_info:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: 'generation_id' column is missing from 'threat_indicators'. "
                "Please run 'alembic upgrade head' before starting the application."
            )
        if cols_info["generation_id"][3] != 1:  # notnull == 1
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: 'generation_id' must be NOT NULL in 'threat_indicators'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
        tbl_sql_row = cursor.fetchone()
        tbl_sql = tbl_sql_row[0] if tbl_sql_row else ""
        if "uq_source_gen_type_indicator" not in tbl_sql:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: 'uq_source_gen_type_indicator' constraint missing on 'threat_indicators'. "
                "Please run 'alembic upgrade head' before starting the application."
            )
        if "uq_source_type_indicator" in tbl_sql:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: legacy 'uq_source_type_indicator' constraint still present on 'threat_indicators'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        cursor.execute("PRAGMA index_list(threat_indicators)")
        ti_indexes = {row[1] for row in cursor.fetchall()}
        missing_ti_indexes = REQUIRED_THREAT_INDICATOR_INDEXES - ti_indexes
        if missing_ti_indexes:
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing index(es) {sorted(missing_ti_indexes)} on 'threat_indicators'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

        # 6. Verify 'threat_feed_states' table columns
        cursor.execute("PRAGMA table_info(threat_feed_states)")
        state_cols = {row[1] for row in cursor.fetchall()}
        required_state_cols = {"source", "enabled", "status", "freshness", "current_generation_id", "refresh_interval_seconds", "updated_at"}
        if not required_state_cols.issubset(state_cols):
            missing = required_state_cols - state_cols
            raise RuntimeError(
                f"Database schema incompatible on {target_db}: missing column(s) {sorted(missing)} in 'threat_feed_states'. "
                "Please run 'alembic upgrade head' before starting the application."
            )

    except sqlite3.Error as e:
        raise RuntimeError(f"Database schema verification failed on {target_db}: {e}") from e
    finally:
        if conn:
            conn.close()


# Compatibility alias
ensure_schema_migrations = verify_schema_invariants

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

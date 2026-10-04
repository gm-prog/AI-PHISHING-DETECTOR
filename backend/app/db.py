import os
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Always use an absolute path for the SQLite database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "phishing_detector.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# Authoritative database evolution is managed via Alembic.
# Runtime startup strictly verifies schema compatibility and fails closed if unmigrated.
def verify_schema_invariants(db_path: str = DB_PATH):
    """
    Validates required schema invariants at startup without mutating the database.
    Fails closed with a clear RuntimeError if tables, columns, constraints, or NOT NULL requirements are violated.
    """
    if not os.path.exists(db_path):
        return

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = set(r[0] for r in cursor.fetchall())

        # If database has existing application tables, verify schema invariants
        if "threat_indicators" in existing_tables:
            cursor.execute("PRAGMA table_info(threat_indicators)")
            cols_info = {row[1]: row for row in cursor.fetchall()}

            # 1. generation_id column must exist and be NOT NULL (row[3] == 1 in table_info)
            if "generation_id" not in cols_info:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: 'generation_id' column is missing from 'threat_indicators'. "
                    "Run 'alembic upgrade head' before starting the application."
                )
            if cols_info["generation_id"][3] != 1:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: 'generation_id' must be NOT NULL in 'threat_indicators'. "
                    "Run 'alembic upgrade head' before starting the application."
                )

            # 2. Check table SQL for generation-aware uniqueness and absence of legacy uniqueness
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
            tbl_sql = cursor.fetchone()[0] or ""
            if "uq_source_gen_type_indicator" not in tbl_sql:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: 'uq_source_gen_type_indicator' constraint missing. "
                    "Run 'alembic upgrade head' before starting the application."
                )
            if "uq_source_type_indicator" in tbl_sql:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: legacy 'uq_source_type_indicator' constraint still present. "
                    "Run 'alembic upgrade head' before starting the application."
                )

            # 3. threat_feed_states table must exist
            if "threat_feed_states" not in existing_tables:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: 'threat_feed_states' table is missing. "
                    "Run 'alembic upgrade head' before starting the application."
                )

        if "scan_history" in existing_tables:
            cursor.execute("PRAGMA table_info(scan_history)")
            scan_cols = set(row[1] for row in cursor.fetchall())
            if "user_id" not in scan_cols or "guest_session_hash" not in scan_cols:
                raise RuntimeError(
                    f"Database schema incompatible on {db_path}: required columns missing from 'scan_history'. "
                    "Run 'alembic upgrade head' before starting the application."
                )

    except Exception as e:
        raise RuntimeError(f"Database schema verification failed on {db_path}: {e}") from e
    finally:
        if conn:
            conn.close()


# Compatibility alias
ensure_schema_migrations = verify_schema_invariants

verify_schema_invariants()

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

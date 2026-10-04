import os
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Always use an absolute path for the SQLite database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "phishing_detector.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# Auto-migrate schema for security-sensitive ownership fields and threat feed generation lifecycle.
def ensure_schema_migrations(db_path: str = DB_PATH):
    if os.path.exists(db_path):
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            # 1. scan_history table migrations
            cursor.execute("PRAGMA table_info(scan_history)")
            scan_columns = [row[1] for row in cursor.fetchall()]
            if scan_columns and "user_id" not in scan_columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id VARCHAR")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history (user_id)")
            if scan_columns and "guest_session_hash" not in scan_columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN guest_session_hash VARCHAR")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS ix_scan_history_guest_session_hash "
                    "ON scan_history (guest_session_hash)"
                )

            # 2. threat_indicators table migrations
            cursor.execute("PRAGMA table_info(threat_indicators)")
            threat_columns = [row[1] for row in cursor.fetchall()]
            if threat_columns and "generation_id" not in threat_columns:
                cursor.execute("ALTER TABLE threat_indicators ADD COLUMN generation_id VARCHAR(36)")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_generation_id ON threat_indicators (generation_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_indicator_hash ON threat_indicators (indicator_hash)")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_source ON threat_indicators (source)")

            # 3. threat_feed_states table creation if missing
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_feed_states'")
            if not cursor.fetchone():
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS threat_feed_states (
                        source VARCHAR(64) PRIMARY KEY,
                        enabled BOOLEAN NOT NULL DEFAULT 1,
                        status VARCHAR(32) NOT NULL DEFAULT 'idle',
                        freshness VARCHAR(32) NOT NULL DEFAULT 'never_synced',
                        last_success_at VARCHAR(32),
                        last_attempt_at VARCHAR(32),
                        last_success_count INTEGER NOT NULL DEFAULT 0,
                        last_error VARCHAR(256),
                        etag VARCHAR(128),
                        last_modified VARCHAR(128),
                        current_generation_id VARCHAR(36),
                        refresh_interval_seconds INTEGER NOT NULL DEFAULT 86400,
                        updated_at VARCHAR(32) NOT NULL
                    )
                """)

            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
        finally:
            if conn:
                conn.close()

ensure_schema_migrations()

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

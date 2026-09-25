import os
import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Always use an absolute path for the SQLite database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "phishing_detector.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

# Auto-migrate schema for security-sensitive ownership fields.
def ensure_schema_migrations():
    if os.path.exists(DB_PATH):
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scan_history)")
            columns = [row[1] for row in cursor.fetchall()]
            if columns and "user_id" not in columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id VARCHAR")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history (user_id)")
            if columns and "guest_session_hash" not in columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN guest_session_hash VARCHAR")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS ix_scan_history_guest_session_hash "
                    "ON scan_history (guest_session_hash)"
                )
            conn.commit()
        except Exception as e:
            print(f"Migration warning: {e}")
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

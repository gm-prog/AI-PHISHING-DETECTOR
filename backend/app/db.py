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
    if not os.path.exists(db_path):
        return

    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # 1. scan_history table migrations
        cursor.execute("PRAGMA table_info(scan_history)")
        scan_columns = [row[1] for row in cursor.fetchall()]
        if scan_columns:
            if "user_id" not in scan_columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN user_id VARCHAR")
                cursor.execute("CREATE INDEX IF NOT EXISTS ix_scan_history_user_id ON scan_history (user_id)")
            if "guest_session_hash" not in scan_columns:
                cursor.execute("ALTER TABLE scan_history ADD COLUMN guest_session_hash VARCHAR")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS ix_scan_history_guest_session_hash "
                    "ON scan_history (guest_session_hash)"
                )

        # 2. threat_feed_states table creation if missing
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

        # 3. threat_indicators table migrations
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
        if cursor.fetchone():
            cursor.execute("PRAGMA table_info(threat_indicators)")
            threat_columns = [row[1] for row in cursor.fetchall()]

            # Add generation_id if absent
            if "generation_id" not in threat_columns:
                cursor.execute("ALTER TABLE threat_indicators ADD COLUMN generation_id VARCHAR(36)")

            # Assign legacy generation IDs to rows where generation_id IS NULL
            cursor.execute("SELECT DISTINCT source FROM threat_indicators WHERE generation_id IS NULL OR generation_id = ''")
            legacy_sources = [r[0] for r in cursor.fetchall() if r[0]]
            for src in legacy_sources:
                legacy_gen = f"legacy-gen-{src}"
                cursor.execute(
                    "UPDATE threat_indicators SET generation_id = ? WHERE source = ? AND (generation_id IS NULL OR generation_id = '')",
                    (legacy_gen, src),
                )

            # Reconcile ThreatFeedState for every source in threat_indicators
            cursor.execute("SELECT DISTINCT source FROM threat_indicators")
            all_sources = [r[0] for r in cursor.fetchall() if r[0]]
            for src in all_sources:
                legacy_gen = f"legacy-gen-{src}"
                cursor.execute(
                    "SELECT COUNT(*) FROM threat_indicators WHERE source = ? AND generation_id = ?",
                    (src, legacy_gen),
                )
                cnt = cursor.fetchone()[0] or 0

                cursor.execute("SELECT source, current_generation_id FROM threat_feed_states WHERE source = ?", (src,))
                st = cursor.fetchone()
                if not st:
                    cursor.execute("""
                        INSERT INTO threat_feed_states (source, enabled, status, freshness, last_success_count, current_generation_id, refresh_interval_seconds, updated_at)
                        VALUES (?, 1, 'idle', 'stale', ?, ?, 86400, datetime('now'))
                    """, (src, cnt, legacy_gen))
                else:
                    curr_gen = st[1]
                    if not curr_gen:
                        cursor.execute("""
                            UPDATE threat_feed_states
                            SET current_generation_id = ?, freshness = 'stale', status = 'idle', last_success_at = NULL, last_success_count = ?, updated_at = datetime('now')
                            WHERE source = ?
                        """, (legacy_gen, cnt, src))
                    else:
                        cursor.execute(
                            "SELECT COUNT(*) FROM threat_indicators WHERE source = ? AND generation_id = ?",
                            (src, curr_gen),
                        )
                        active_cnt = cursor.fetchone()[0] or 0
                        if active_cnt == 0:
                            cursor.execute("""
                                UPDATE threat_feed_states
                                SET current_generation_id = ?, freshness = 'stale', status = 'idle', last_success_at = NULL, last_success_count = ?, updated_at = datetime('now')
                                WHERE source = ?
                            """, (legacy_gen, cnt, src))

            # Inspect table SQL to determine if unique constraint needs migration
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
            tbl_sql = cursor.fetchone()[0] or ""
            needs_constraint_migration = (
                "generation_id" not in tbl_sql
                or "uq_source_gen_type_indicator" not in tbl_sql
                or "UNIQUE (source, indicator_type, indicator_hash)" in tbl_sql
                or "UNIQUE(source, indicator_type, indicator_hash)" in tbl_sql
                or "uq_source_type_indicator" in tbl_sql
            )

            if needs_constraint_migration:
                # Recreate table with new unique constraint
                cursor.execute("""
                    CREATE TABLE threat_indicators_migrated (
                        id VARCHAR(36) PRIMARY KEY,
                        source VARCHAR(64) NOT NULL,
                        indicator_type VARCHAR(32) NOT NULL,
                        indicator VARCHAR(2048) NOT NULL,
                        indicator_hash VARCHAR(64) NOT NULL,
                        classification VARCHAR(64) NOT NULL,
                        confidence FLOAT NOT NULL,
                        observed_at VARCHAR(32) NOT NULL,
                        expires_at VARCHAR(32),
                        generation_id VARCHAR(36),
                        created_at VARCHAR(32) NOT NULL,
                        updated_at VARCHAR(32) NOT NULL,
                        CONSTRAINT uq_source_gen_type_indicator UNIQUE (source, generation_id, indicator_type, indicator_hash)
                    )
                """)
                cursor.execute("""
                    INSERT INTO threat_indicators_migrated (
                        id, source, indicator_type, indicator, indicator_hash,
                        classification, confidence, observed_at, expires_at,
                        generation_id, created_at, updated_at
                    )
                    SELECT
                        id, source, indicator_type, indicator, indicator_hash,
                        classification, confidence, observed_at, expires_at,
                        generation_id, created_at, updated_at
                    FROM threat_indicators
                """)
                cursor.execute("DROP TABLE threat_indicators")
                cursor.execute("ALTER TABLE threat_indicators_migrated RENAME TO threat_indicators")

            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_source ON threat_indicators (source)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_indicator_type ON threat_indicators (indicator_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_indicator_hash ON threat_indicators (indicator_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_classification ON threat_indicators (classification)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_expires_at ON threat_indicators (expires_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS ix_threat_indicators_generation_id ON threat_indicators (generation_id)")

        conn.commit()
    except Exception as e:
        if conn:
            conn.rollback()
        raise RuntimeError(f"Database schema migration failed on {db_path}: {e}") from e
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

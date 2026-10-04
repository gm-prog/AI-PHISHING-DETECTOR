from sqlalchemy import Column, Integer, Float, String, JSON, Boolean, ForeignKey, UniqueConstraint
from app.db import Base
from datetime import datetime, timezone
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())

class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    session_id_hash = Column(String, unique=True, index=True, nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    expires_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=True)
    # Anonymous scans are owned by a random server-issued guest cookie.
    # Only the hash is persisted; the raw guest token is never stored.
    guest_session_hash = Column(String, index=True, nullable=True)
    timestamp = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    input_type = Column(String, index=True)
    content = Column(String)
    risk_score = Column(Integer)
    status = Column(String)
    phishing_signals = Column(JSON)
    ai_explanation = Column(String)
    details = Column(JSON)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    source = Column(String(64), nullable=False, index=True)
    indicator_type = Column(String(32), nullable=False, index=True)
    indicator = Column(String(2048), nullable=False)
    indicator_hash = Column(String(64), nullable=False, index=True)
    classification = Column(String(64), nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    observed_at = Column(String(32), nullable=False)
    expires_at = Column(String(32), nullable=True, index=True)
    generation_id = Column(String(36), nullable=True, index=True)
    created_at = Column(String(32), default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)
    updated_at = Column(String(32), default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)

    __table_args__ = (
        UniqueConstraint("source", "indicator_type", "indicator_hash", name="uq_source_type_indicator"),
    )


class ThreatFeedState(Base):
    __tablename__ = "threat_feed_states"

    source = Column(String(64), primary_key=True)
    enabled = Column(Boolean, default=True, nullable=False)
    status = Column(String(32), default="idle", nullable=False)  # "idle", "fetching", "success", "failed", "disabled"
    freshness = Column(String(32), default="never_synced", nullable=False)  # "fresh", "stale", "expired", "never_synced", "failed", "disabled"
    last_success_at = Column(String(32), nullable=True)
    last_attempt_at = Column(String(32), nullable=True)
    last_success_count = Column(Integer, default=0, nullable=False)
    last_error = Column(String(256), nullable=True)
    etag = Column(String(128), nullable=True)
    last_modified = Column(String(128), nullable=True)
    current_generation_id = Column(String(36), nullable=True)
    refresh_interval_seconds = Column(Integer, default=86400, nullable=False)
    updated_at = Column(String(32), default=lambda: datetime.now(timezone.utc).isoformat(), nullable=False)

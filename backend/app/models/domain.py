from sqlalchemy import Column, Integer, String, JSON, Boolean, ForeignKey
from app.db import Base
from datetime import datetime, timezone

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

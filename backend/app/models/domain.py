from sqlalchemy import Column, Integer, String, JSON, Boolean, ForeignKey
from app.db import Base
from datetime import datetime, timezone

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="user", nullable=False) # "user" or "admin"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=True) # Nullable for guest/public scans
    timestamp = Column(String, default=lambda: datetime.now(timezone.utc).isoformat())
    input_type = Column(String, index=True)
    content = Column(String)
    risk_score = Column(Integer)
    status = Column(String)
    phishing_signals = Column(JSON)
    ai_explanation = Column(String)
    details = Column(JSON)


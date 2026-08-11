from sqlalchemy import Column, Integer, String, JSON
from app.db import Base
from datetime import datetime

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(String, primary_key=True, index=True)
    timestamp = Column(String, default=lambda: datetime.utcnow().isoformat())
    input_type = Column(String, index=True)
    content = Column(String)
    risk_score = Column(Integer)
    status = Column(String)
    phishing_signals = Column(JSON)
    ai_explanation = Column(String)
    details = Column(JSON)

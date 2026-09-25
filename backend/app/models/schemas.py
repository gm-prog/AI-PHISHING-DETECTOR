from pydantic import BaseModel, Field, field_validator
from typing import List, Dict, Optional, Any, Literal
import re

# ================= AUTH SCHEMAS =================
class UserCreate(BaseModel):
    email: str = Field(..., description="Valid user email address", min_length=5, max_length=254)
    password: str = Field(..., min_length=8, max_length=128, description="Strong password (at least 8 characters)")

    @field_validator("email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", clean):
            raise ValueError("Invalid email format.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must contain at least 8 characters.")
        return v

class UserLogin(BaseModel):
    email: str = Field(..., description="User email", min_length=5, max_length=254)
    password: str = Field(..., min_length=1, max_length=128, description="Account password")

    @field_validator("email")
    @classmethod
    def clean_email(cls, v: str) -> str:
        return v.strip().lower()

class UserOut(BaseModel):
    id: str
    email: str
    role: str
    is_active: bool
    created_at: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

# ================= SCAN & ANALYSIS SCHEMAS =================
class AnalysisRequest(BaseModel):
    input_type: Literal["url", "email_text", "email_header"] = Field(
        ..., description="Type of input: 'url', 'email_text', or 'email_header'"
    )
    content: str = Field(
        ..., min_length=1, max_length=50000, description="The content to analyze (URL string, email body, or raw email headers)"
    )

    @field_validator("content")
    @classmethod
    def sanitize_content(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Content cannot be blank or contain only whitespace.")
        return cleaned

class PhishingSignal(BaseModel):
    id: str = Field(..., description="A unique identifier for the specific heuristic or signal matched")
    severity: str = Field(..., description="Severity level: 'low', 'medium', or 'high'")
    title: str = Field(..., description="Short descriptive title of the warning sign")
    description: str = Field(..., description="Detailed explanation of what this warning means in this context")

class AnalysisResponse(BaseModel):
    input_type: str = Field(..., description="Echoed input type")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk rating from 0 (Safe) to 100 (Critical Danger)")
    status: str = Field(..., description="Status classification: 'safe', 'warning', or 'danger'")
    phishing_signals: List[PhishingSignal] = Field(default=[], description="List of suspicious features or indicators identified")
    ai_explanation: str = Field(..., description="Detailed narrative breakdown summarizing why this is or isn't phishing")
    details: Dict[str, Any] = Field(default={}, description="Technical metadata (domain info, headers parsed, etc.)")

    # VirusTotal Integration Fields
    virustotal_findings: Optional[Dict[str, Any]] = Field(None, description="Raw VirusTotal scan results")
    vt_status: Optional[str] = Field(None, description="VT call status: 'success', 'rate_limited', 'timeout', 'error', 'skipped'")
    vt_malicious_vendors: Optional[int] = Field(None, description="Number of VT vendors that flagged this URL as malicious")
    vt_reputation: Optional[int] = Field(None, description="VT reputation score 0-100 (100 = clean)")

    # URLhaus Integration Fields
    urlhaus_findings: Optional[Dict[str, Any]] = Field(None, description="Raw URLhaus lookup results")
    urlhaus_status: Optional[str] = Field(None, description="URLhaus lookup status: 'success', 'timeout', 'error'")
    urlhaus_threat_type: Optional[str] = Field(None, description="URLhaus threat type (e.g. malware, phishing)")
    urlhaus_in_database: Optional[bool] = Field(None, description="Whether URL is listed in URLhaus malware/phishing database")

class VerifyKeyRequest(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=256, description="The Gemini API key to verify")

class ScanHistoryItem(BaseModel):
    id: str
    user_id: Optional[str] = None
    timestamp: str
    input_type: str
    content: str
    risk_score: int
    status: str
    response: Dict[str, Any]

class AdminMetricsOut(BaseModel):
    total_users: int
    total_scans: int
    high_risk_scans: int
    clean_scans: int
    threat_signals_flagged: int

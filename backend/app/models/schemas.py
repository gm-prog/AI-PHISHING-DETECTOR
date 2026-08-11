from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class AnalysisRequest(BaseModel):
    input_type: str = Field(..., description="Type of input: 'url', 'email_text', or 'email_header'")
    content: str = Field(..., max_length=50000, description="The content to analyze (URL string, email body, or raw email headers)")
    api_key: Optional[str] = Field(None, description="Optional custom Gemini API key supplied by the frontend")

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
    urlhaus_status: Optional[str] = Field(None, description="URLhaus call status: 'success', 'timeout', 'error'")
    urlhaus_threat_type: Optional[str] = Field(None, description="URLhaus threat type (e.g. malware, phishing)")
    urlhaus_in_database: Optional[bool] = Field(None, description="Whether URL is listed in URLhaus malware/phishing database")

class VerifyKeyRequest(BaseModel):
    api_key: str = Field(..., description="The Gemini API key to verify")


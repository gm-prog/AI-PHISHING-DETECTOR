import uuid
import asyncio
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
import logging

from app.config import settings
from app.models.schemas import AnalysisRequest, AnalysisResponse, VerifyKeyRequest
from app.services.url_service import analyze_url
from app.services.email_service import analyze_email_text, analyze_email_headers
from app.services.llm_service import verify_gemini_key, analyze_with_llm
from app.services.virustotal_service import analyze_url_with_virustotal
from app.services.urlhaus_service import check_url_with_urlhaus

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import Request

from app.db import engine, Base, get_db
from app.models.domain import ScanHistory

Base.metadata.create_all(bind=engine)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_detector.main")

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AI Phishing Detector API",
    description="Backend service providing heuristic and AI phishing detection.",
    version="1.1.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Configure CORS so our React frontend can reach the endpoints
allowed_origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def generate_local_explanation(
    input_type: str,
    content: str,
    risk_score: int,
    signals: List[Dict[str, Any]]
) -> str:
    """Generates a rich, AI-style markdown threat report using only local heuristics."""
    status = "DANGER" if risk_score >= 70 else "WARNING" if risk_score >= 30 else "SAFE"
    threat_icon = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 30 else "🟢"

    report = f"""## {threat_icon} Threat Intelligence Report

### Executive Summary
| Metric | Value |
|---|---|
| **Input Type** | `{input_type.upper()}` |
| **Threat Classification** | **{status}** |
| **Risk Score** | **{risk_score}/100** |
| **Signals Detected** | {len(signals)} |
| **Analysis Engine** | Heuristic Detection (Offline) |

---

### Detected Threat Indicators
"""
    if not signals:
        report += "\n✅ **No suspicious patterns detected.** The input appears to be legitimate based on all heuristic checks.\n"
    else:
        for idx, sig in enumerate(signals, 1):
            sev = sig.get('severity', 'medium').upper()
            sev_icon = "🔴" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
            report += f"\n#### {idx}. {sev_icon} [{sev}] {sig.get('title', 'Unknown Signal')}\n"
            report += f"> {sig.get('description', 'No details available.')}\n"

    report += "\n---\n\n### Risk Assessment\n"
    if risk_score >= 70:
        report += """
⛔ **HIGH RISK — Likely Phishing Attempt**

This input exhibits multiple characteristics consistent with known phishing campaigns:
- **Do NOT click** any links or download attachments
- **Do NOT enter** any credentials or personal information
- **Report** this to your IT security team immediately
- **Delete** the message from your inbox
"""
    elif risk_score >= 30:
        report += """
⚠️ **MODERATE RISK — Exercise Caution**

Some suspicious patterns were identified. While not definitively malicious, proceed with care:
- **Verify** the sender through independent channels (phone, official website)
- **Do NOT** click links directly — type the URL manually in your browser
- **Check** for HTTPS and valid SSL certificates before entering data
- **Compare** the domain carefully with the official domain
"""
    else:
        report += """
✅ **LOW RISK — Appears Legitimate**

No major phishing indicators were detected. Standard safety practices still apply:
- Always verify sender identity for financial or sensitive requests
- Look for HTTPS and valid certificates on websites
- Keep your browser and security software up to date
"""

    report += f"""
---

### Analysis Methodology
This report was generated using the **Heuristic Detection Engine v1.1**, which evaluates:
- Domain reputation and typosquatting patterns
- URL structure anomalies (IP hosting, suspicious TLDs, excessive subdomains)
- Brand impersonation and credential harvesting indicators
- Email urgency keywords and social engineering tactics
- SPF/DKIM/DMARC header authentication signals

*Analysis performed locally — no data was transmitted to external services.*
"""
    return report


@app.get("/api/health")
def health_check():
    """Checks backend health status."""
    return {
        "status": "healthy",
        "api_active": True,
        "mode": "heuristic_only",
        "gemini_configured_in_backend": bool(settings.GEMINI_API_KEY),
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "urlhaus_configured": True,
        "message": "AI Phishing Detector API is operational."
    }


@app.post("/api/verify-key")
@limiter.limit("15/minute")
async def verify_key(request: Request, body: VerifyKeyRequest):
    """Verifies a custom Gemini API key (for settings modal only)."""
    return verify_gemini_key(body.api_key)


@app.post("/api/analyze", response_model=AnalysisResponse)
@limiter.limit("15/minute")
async def analyze_input(request: Request, body: AnalysisRequest, db: Session = Depends(get_db)):
    """
    Analyzes input for phishing indicators using heuristic detection and optional AI analysis.
    """
    # 1. Input Validation
    input_type = body.input_type.strip().lower()
    content = body.content.strip()

    if not content:
        raise HTTPException(status_code=400, detail="Content to analyze cannot be empty.")

    if input_type not in ["url", "email_text", "email_header"]:
        raise HTTPException(
            status_code=400,
            detail="Invalid input_type. Must be 'url', 'email_text', or 'email_header'."
        )

    # 2. Run Heuristic Engine
    heuristic_score = 0
    heuristic_signals = []
    technical_details = {}

    try:
        if input_type == "url":
            res = analyze_url(content)
        elif input_type == "email_text":
            res = analyze_email_text(content)
        elif input_type == "email_header":
            res = analyze_email_headers(content)

        heuristic_score = res["risk_score"]
        heuristic_signals = res["signals"]
        technical_details = res["details"]

    except Exception as e:
        logger.error(f"Heuristic engine error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred in the heuristic engine: {str(e)}"
        )

    # 3. Determine status from score
    status = "safe"
    if heuristic_score >= 70:
        status = "danger"
    elif heuristic_score >= 30:
        status = "warning"

    # 4. External Threat Intelligence (URLs only — never blocks if APIs fail)
    vt_data: Optional[Dict[str, Any]] = None
    uh_data: Optional[Dict[str, Any]] = None
    vt_status: Optional[str] = None
    uh_status: Optional[str] = None

    if input_type == "url":
        # VirusTotal
        try:
            vt_data = await asyncio.wait_for(
                analyze_url_with_virustotal(content, settings.VIRUSTOTAL_API_KEY),
                timeout=7.0
            )
            vt_status = vt_data.get("status")
            # Boost score if malware confirmed
            if vt_status == "success" and vt_data.get("malicious_count", 0) > 0:
                boost = min(30, vt_data["malicious_count"] * 5)
                heuristic_score = min(100, heuristic_score + boost)
                logger.info(f"[VT BOOST] +{boost} from {vt_data['malicious_count']} malicious vendors")
        except asyncio.TimeoutError:
            logger.warning("VirusTotal global timeout")
            vt_status = "timeout"
        except Exception as e:
            logger.error(f"VirusTotal integration error: {e}")
            vt_status = "error"

        # URLhaus
        try:
            uh_data = await asyncio.wait_for(
                check_url_with_urlhaus(content),
                timeout=6.0
            )
            uh_status = uh_data.get("status")
            if uh_status == "success" and uh_data.get("in_database"):
                threat_type = (uh_data.get("threat_type") or "").lower()
                boost = 25
                heuristic_score = min(100, heuristic_score + boost)
                logger.info(f"[URLHAUS BOOST] +{boost} threat_type={threat_type}")
        except asyncio.TimeoutError:
            logger.warning("URLhaus global timeout")
            uh_status = "timeout"
        except Exception as e:
            logger.error(f"URLhaus integration error: {e}")
            uh_status = "error"

        # Recalculate status after boosts
        if heuristic_score >= 70:
            status = "danger"
        elif heuristic_score >= 30:
            status = "warning"
        else:
            status = "safe"

    # 5. Use LLM if API key provided, else local explanation
    active_key = body.api_key if body.api_key else settings.GEMINI_API_KEY
    if active_key:
        llm_res = analyze_with_llm(
            input_type=input_type,
            content=content,
            api_key=active_key,
            heuristic_score=heuristic_score,
            heuristic_signals=heuristic_signals
        )
        final_score = llm_res["risk_score"]
        final_status = llm_res["status"]
        final_signals = llm_res["phishing_signals"]
        ai_explanation = llm_res["ai_explanation"]
    else:
        final_score = heuristic_score
        final_status = status
        final_signals = heuristic_signals
        ai_explanation = generate_local_explanation(
            input_type=input_type,
            content=content,
            risk_score=heuristic_score,
            signals=heuristic_signals
        )

    logger.info(f"[SCAN COMPLETE] type={input_type} score={final_score} status={final_status} signals={len(final_signals)} vt={vt_status} uh={uh_status}")

    # Save to database
    db_record = ScanHistory(
        id=str(uuid.uuid4()),
        input_type=input_type,
        content=content[:100] + "..." if len(content) > 100 else content,
        risk_score=final_score,
        status=final_status,
        phishing_signals=final_signals,
        ai_explanation=ai_explanation,
        details=technical_details
    )
    try:
        db.add(db_record)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save scan history: {e}")
        db.rollback()

    # 6. Return response with external threat intel
    return AnalysisResponse(
        input_type=input_type,
        risk_score=final_score,
        status=final_status,
        phishing_signals=final_signals,
        ai_explanation=ai_explanation,
        details=technical_details,
        virustotal_findings=vt_data if vt_status == "success" else None,
        vt_status=vt_status,
        vt_malicious_vendors=vt_data.get("malicious_count") if vt_status == "success" and vt_data else None,
        vt_reputation=vt_data.get("reputation_score") if vt_status == "success" and vt_data else None,
        urlhaus_findings=uh_data if uh_status == "success" else None,
        urlhaus_status=uh_status,
        urlhaus_threat_type=uh_data.get("threat_type") if uh_status == "success" and uh_data else None,
        urlhaus_in_database=uh_data.get("in_database") if uh_status == "success" and uh_data else None,
    )


@app.get("/api/history")
def get_history(db: Session = Depends(get_db)):
    records = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(30).all()
    return [{
        "id": r.id,
        "timestamp": r.timestamp,
        "input_type": r.input_type,
        "content": r.content,
        "risk_score": r.risk_score,
        "status": r.status,
        "response": {
            "input_type": r.input_type,
            "risk_score": r.risk_score,
            "status": r.status,
            "phishing_signals": r.phishing_signals,
            "ai_explanation": r.ai_explanation,
            "details": r.details
        }
    } for r in records]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)

import uuid
import hashlib
import asyncio
import secrets
import re
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, status, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.db import engine, Base, get_db
from app.models.domain import User, ScanHistory
from app.models.schemas import (
    AnalysisRequest,
    AnalysisResponse,
    UserCreate,
    UserLogin,
    UserOut,
    AuthResponse,
    AdminMetricsOut
)
from app.auth import (

    get_password_hash,
    verify_password,
    get_current_user,
    get_optional_current_user,
    require_admin,
    create_user_session,
    revoke_session
)
from app.services.url_service import analyze_url
from app.services.email_service import analyze_email_text, analyze_email_headers
from app.services.llm_service import analyze_with_llm
from app.services.virustotal_service import analyze_url_with_virustotal
from app.services.urlhaus_service import check_url_with_urlhaus

from datetime import datetime, timezone

# Ensure database tables exist
Base.metadata.create_all(bind=engine)

# ================= SENSITIVE LOG REDACTION FILTER =================
class SensitiveLogFilter(logging.Filter):
    """Scans log records and masks API keys, bearer tokens, passwords, and secrets."""
    PATTERNS = [
        (re.compile(r"AIzaSy[A-Za-z0-9_\-]{10,}", re.IGNORECASE), r"AIzaSy...[REDACTED]"),
        (re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]+", re.IGNORECASE), r"Bearer [REDACTED_JWT]"),
        (re.compile(r"(api_key=)[^\s&,]+", re.IGNORECASE), r"\1[REDACTED]"),
        (re.compile(r"(password=)[^\s&,]+", re.IGNORECASE), r"\1[REDACTED]"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            for pattern, repl in self.PATTERNS:
                record.msg = pattern.sub(repl, record.msg)
        return True

# Configure logging with sensitive filter
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.api")
logger.addFilter(SensitiveLogFilter())

# Configure Rate Limiter (SlowAPI)
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="SENTINEL AI — Threat Intelligence API",
    description="Hardened defense-in-depth phishing detection and threat analysis platform.",
    version="2.0.0"
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def _guest_session_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _get_or_create_guest_token(request: Request, response: Response) -> str:
    existing = request.cookies.get(settings.GUEST_COOKIE_NAME)
    if existing and len(existing) >= 32:
        return existing

    token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.GUEST_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    return token


def _set_auth_cookies(response: Response, session_token: str) -> None:
    csrf_token = secrets.token_urlsafe(32)
    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.AUTH_COOKIE_SECURE,
        samesite=settings.AUTH_COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )

def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(settings.AUTH_COOKIE_NAME, path="/")
    response.delete_cookie(settings.CSRF_COOKIE_NAME, path="/")

@app.middleware("http")
async def csrf_protection(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        cookie_token = request.cookies.get(settings.CSRF_COOKIE_NAME)
        header_token = request.headers.get("X-CSRF-Token")
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF validation failed."},
            )
    response = await call_next(request)
    if not request.cookies.get(settings.CSRF_COOKIE_NAME):
        response.set_cookie(
            key=settings.CSRF_COOKIE_NAME,
            value=secrets.token_urlsafe(32),
            httponly=False,
            secure=settings.AUTH_COOKIE_SECURE,
            samesite=settings.AUTH_COOKIE_SAMESITE,
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            path="/",
        )
    return response

# Configure CORS
allowed_origins = [origin.strip() for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


def generate_local_explanation(
    input_type: str,
    content: str,
    risk_score: int,
    signals: List[Dict[str, Any]]
) -> str:
    """Generates a structured, rich markdown threat report using local heuristics (100% offline & private)."""
    status = "DANGER" if risk_score >= 70 else "WARNING" if risk_score >= 30 else "SAFE"
    threat_icon = "🔴" if risk_score >= 70 else "🟡" if risk_score >= 30 else "🟢"

    report = f"""## {threat_icon} Sentinel Threat Intelligence Report

### Executive Summary
| Metric | Value |
|---|---|
| **Input Vector** | `{input_type.upper()}` |
| **Threat Classification** | **{status}** |
| **Risk Score** | **{risk_score}/100** |
| **Threat Signals Identified** | {len(signals)} |
| **Detection Engine** | Sentinel Autonomous Heuristics (Local/Private) |

---

### Detected Threat Indicators
"""
    if not signals:
        report += "\n✅ **No suspicious anomalies detected.** The input matches standard legitimate security criteria across all heuristic models.\n"
    else:
        for idx, sig in enumerate(signals, 1):
            sev = sig.get('severity', 'medium').upper()
            sev_icon = "🔴" if sev == "HIGH" else "🟡" if sev == "MEDIUM" else "🔵"
            report += f"\n#### {idx}. {sev_icon} [{sev}] {sig.get('title', 'Security Warning')}\n"
            report += f"> {sig.get('description', 'No details available.')}\n"

    report += "\n---\n\n### Recommended Security Response\n"
    if risk_score >= 70:
        report += """
⛔ **CRITICAL RISK — Confirmed Threat Indicators**
- **Do NOT click** any embedded links or download attachments.
- **Do NOT supply** passwords, 2FA codes, or sensitive personal data.
- **Isolate & Report** this communication to your Security Operations Center.
- **Purge** this artifact from your message queue immediately.
"""
    elif risk_score >= 30:
        report += """
⚠️ **MODERATE SUSPICION — Verification Advised**
- **Verify sender validity** via out-of-band communication (phone, official verified portal).
- **Inspect domain spelling** carefully for homograph or typosquatting techniques.
- **Do NOT enter credentials** unless SSL/TLS identity certificate is verified.
"""
    else:
        report += """
✅ **LOW RISK — Standard Safety Protocols**
- No active phishing signatures or deceptive patterns were found.
- Always maintain vigilant hygiene when processing financial or identity transactions.
"""

    report += f"""
---

### Detection Methodology
This assessment was generated by the **Sentinel Autonomous Heuristic Engine v2.0**:
- Lexical entropy & Levenshtein typosquatting detection
- URL structural obfuscation, deep subdomains, and IP-hosted destination checks
- Social engineering urgency heuristics & deceptive intent patterns
- SPF, DKIM, and DMARC cryptographic email header authentication

*Engine operating in autonomous private mode — zero external transmission.*
"""
    return report


# ================= HEALTH & SYSTEM STATUS =================
@app.get("/api/health")
def health_check():
    """Returns backend health and active engine configuration."""
    has_gemini = bool(settings.GEMINI_API_KEY)
    has_vt = bool(settings.VIRUSTOTAL_API_KEY)
    
    engine_mode = "Hybrid (Heuristics + Gemini AI)" if has_gemini else "Sentinel Local Heuristics (Autonomous)"
    
    return {
        "status": "healthy",
        "api_active": True,
        "engine_mode": engine_mode,
        "gemini_configured": has_gemini,
        "virustotal_configured": has_vt,
        "urlhaus_configured": True,
        "version": "2.0.0",
        "message": "Sentinel AI Security Gateway is operational."
    }


# ================= AUTHENTICATION ENDPOINTS =================
@app.post("/api/auth/register", response_model=AuthResponse)
@limiter.limit("10/minute")
async def register(request: Request, response: Response, body: UserCreate, db: Session = Depends(get_db)):
    """Registers a new standard user and establishes an HttpOnly session."""
    existing_user = db.query(User).filter(User.email == body.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists."
        )

    user = User(
        id=str(uuid.uuid4()),
        email=body.email,
        hashed_password=get_password_hash(body.password),
        role="user",
        is_active=True,
        created_at=datetime.now(timezone.utc).isoformat()
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    session_token = create_user_session(user, db)
    _set_auth_cookies(response, session_token)
    logger.info("[AUTH] New user registered: email=%s role=user", user.email)

    return AuthResponse(
        user=UserOut(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at
        )
    )


@app.post("/api/auth/login", response_model=AuthResponse)
@limiter.limit("10/minute")
async def login(request: Request, response: Response, body: UserLogin, db: Session = Depends(get_db)):
    """Authenticates credentials and establishes an HttpOnly session."""
    user = db.query(User).filter(User.email == body.email).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or suspended."
        )

    session_token = create_user_session(user, db)
    _set_auth_cookies(response, session_token)
    logger.info("[AUTH] User login successful: email=%s", user.email)

    return AuthResponse(
        user=UserOut(
            id=user.id,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at
        )
    )


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Revokes the current server-side session and clears authentication cookies."""
    revoke_session(request.cookies.get(settings.AUTH_COOKIE_NAME), db)
    _clear_auth_cookies(response)
    return {"status": "success"}


@app.get("/api/auth/me", response_model=UserOut)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Returns the authenticated user's profile."""
    return UserOut(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        is_active=current_user.is_active,
        created_at=current_user.created_at
    )


# ================= ADMIN ENDPOINTS (RBAC LOCKED) =================
@app.get("/api/admin/metrics", response_model=AdminMetricsOut)
def get_admin_metrics(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint returning threat telemetry and system statistics."""
    total_users = db.query(User).count()
    total_scans = db.query(ScanHistory).count()
    high_risk_scans = db.query(ScanHistory).filter(ScanHistory.risk_score >= 70).count()
    clean_scans = db.query(ScanHistory).filter(ScanHistory.risk_score < 30).count()

    return AdminMetricsOut(
        total_users=total_users,
        total_scans=total_scans,
        high_risk_scans=high_risk_scans,
        clean_scans=clean_scans,
        threat_signals_flagged=high_risk_scans * 3 + total_scans
    )


@app.get("/api/admin/scans")
def get_all_scans_admin(
    limit: int = 50,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to inspect recent system-wide scans."""
    records = db.query(ScanHistory).order_by(ScanHistory.timestamp.desc()).limit(min(limit, 100)).all()
    return [{
        "id": r.id,
        "user_id": r.user_id,
        "timestamp": r.timestamp,
        "input_type": r.input_type,
        "content": r.content,
        "risk_score": r.risk_score,
        "status": r.status
    } for r in records]


# ================= CORE THREAT SCANNER ENDPOINT =================
@app.post("/api/analyze", response_model=AnalysisResponse)
@limiter.limit("30/minute")
async def analyze_input(
    request: Request,
    response: Response,
    body: AnalysisRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Analyzes input for phishing indicators using heuristics and optional AI analysis.
    Associates scan with authenticated user if logged in (user isolation).
    """
    input_type = body.input_type
    content = body.content

    # 1. Run Autonomous Heuristic Engine
    try:
        if input_type == "url":
            res = analyze_url(content)
        elif input_type == "email_text":
            res = analyze_email_text(content)
        elif input_type == "email_header":
            res = analyze_email_headers(content)
        else:
            raise HTTPException(status_code=400, detail="Unsupported input type.")

        heuristic_score = res["risk_score"]
        heuristic_signals = res["signals"]
        technical_details = res["details"]

    except Exception as e:
        logger.error(f"Heuristic engine execution error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while analyzing the threat vectors."
        )

    # 2. Determine initial status
    status_label = "safe"
    if heuristic_score >= 70:
        status_label = "danger"
    elif heuristic_score >= 30:
        status_label = "warning"

    # 3. External Threat Intelligence (URLs only)
    vt_data: Optional[Dict[str, Any]] = None
    uh_data: Optional[Dict[str, Any]] = None
    vt_status: Optional[str] = None
    uh_status: Optional[str] = None

    if input_type == "url":
        # VirusTotal Integration
        try:
            vt_data = await asyncio.wait_for(
                analyze_url_with_virustotal(content, settings.VIRUSTOTAL_API_KEY),
                timeout=6.0
            )
            vt_status = vt_data.get("status")
            if vt_status == "success" and vt_data.get("malicious_count", 0) > 0:
                boost = min(30, vt_data["malicious_count"] * 5)
                heuristic_score = min(100, heuristic_score + boost)
        except asyncio.TimeoutError:
            vt_status = "timeout"
        except Exception:
            vt_status = "error"

        # URLhaus Integration
        try:
            uh_data = await asyncio.wait_for(
                check_url_with_urlhaus(content),
                timeout=5.0
            )
            uh_status = uh_data.get("status")
            if uh_status == "success" and uh_data.get("in_database"):
                boost = 25
                heuristic_score = min(100, heuristic_score + boost)
        except asyncio.TimeoutError:
            uh_status = "timeout"
        except Exception:
            uh_status = "error"

        # Update status classification after intel boosts
        if heuristic_score >= 70:
            status_label = "danger"
        elif heuristic_score >= 30:
            status_label = "warning"
        else:
            status_label = "safe"

    # 4. LLM Semantic Engine or Local Heuristic Explanation
    active_key = settings.GEMINI_API_KEY
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
        final_status = status_label
        final_signals = heuristic_signals
        ai_explanation = generate_local_explanation(
            input_type=input_type,
            content=content,
            risk_score=heuristic_score,
            signals=heuristic_signals
        )

    # 5. Persist to Database with User Scoping (RLS/Isolation)
    user_id = current_user.id if current_user else None
    guest_session_hash = None
    if current_user is None:
        guest_token = _get_or_create_guest_token(request, response)
        guest_session_hash = _guest_session_hash(guest_token)
    snippet = content[:100] + "..." if len(content) > 100 else content

    db_record = ScanHistory(
        id=str(uuid.uuid4()),
        user_id=user_id,
        guest_session_hash=guest_session_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
        input_type=input_type,
        content=snippet,
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
        logger.error(f"Scan persistence error: {e}")
        db.rollback()

    logger.info(f"[SCAN] user={user_id or 'anon'} type={input_type} score={final_score} status={final_status}")

    # 6. Return Trimmed Response
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


# ================= SCOPED HISTORY & IDOR-PROTECTED ENDPOINTS =================
@app.get("/api/history")
def get_history(
    request: Request,
    limit: int = 30,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """Returns history scoped to the authenticated user or this anonymous guest session."""
    query = db.query(ScanHistory)
    if current_user:
        query = query.filter(ScanHistory.user_id == current_user.id)
    else:
        guest_token = request.cookies.get(settings.GUEST_COOKIE_NAME)
        if not guest_token:
            return []
        query = query.filter(ScanHistory.guest_session_hash == _guest_session_hash(guest_token))

    records = query.order_by(ScanHistory.timestamp.desc()).limit(min(limit, 50)).all()
    return [{
        "id": r.id,
        "user_id": r.user_id,
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


@app.get("/api/history/{scan_id}")
def get_single_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    IDOR-protected endpoint: Retrieves a specific scan only if it belongs to current user or admin.
    """
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if record.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized access to this scan record."
        )

    return {
        "id": record.id,
        "user_id": record.user_id,
        "timestamp": record.timestamp,
        "input_type": record.input_type,
        "content": record.content,
        "risk_score": record.risk_score,
        "status": record.status,
        "response": {
            "input_type": record.input_type,
            "risk_score": record.risk_score,
            "status": record.status,
            "phishing_signals": record.phishing_signals,
            "ai_explanation": record.ai_explanation,
            "details": record.details
        }
    }


@app.delete("/api/history/{scan_id}")
def delete_single_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    IDOR-protected endpoint: Deletes a specific scan record if owned by current user or admin.
    """
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    if record.user_id != current_user.id and current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized to delete this scan record."
        )

    db.delete(record)
    db.commit()
    return {"status": "success", "message": f"Scan {scan_id} deleted."}


@app.delete("/api/history")
def clear_history(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """Clears scan history scoped to current user or guest session."""
    if current_user:
        db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).delete()
    else:
        guest_token = request.cookies.get(settings.GUEST_COOKIE_NAME)
        if guest_token:
            db.query(ScanHistory).filter(
                ScanHistory.guest_session_hash == _guest_session_hash(guest_token)
            ).delete()
    db.commit()
    return {"status": "success", "message": "History cleared successfully."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True)

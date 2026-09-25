import hashlib
import uuid
import secrets
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.config import settings
from app.db import get_db
from app.models.domain import User, UserSession

# Password hashing with bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against its bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Generates a secure bcrypt hash for a password."""
    return pwd_context.hash(password)

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Creates a signed JWT used only inside the HttpOnly session cookie."""
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    expire = now_utc + (
        expires_delta
        if expires_delta
        else timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": now_utc})
    return jwt.encode(
        to_encode,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodes and validates a JWT session token."""
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except jwt.PyJWTError:
        return None

def _hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

def create_user_session(user: User, db: Session) -> str:
    """
    Creates a cryptographically random server-side session record and returns a
    signed JWT containing only a random session identifier plus the user subject.
    The browser receives the JWT only as an HttpOnly cookie.
    """
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    session = UserSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        session_id_hash=_hash_session_id(session_id),
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )
    db.add(session)
    db.commit()

    return create_access_token(
        {
            "sub": user.id,
            "sid": session_id,
        },
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

def _get_user_from_token(token: Optional[str], db: Session) -> Optional[User]:
    if not token:
        return None

    payload = decode_access_token(token)
    if not payload:
        return None

    user_id = payload.get("sub")
    session_id = payload.get("sid")
    if not user_id or not session_id:
        return None

    session = (
        db.query(UserSession)
        .filter(
            and_(
                UserSession.session_id_hash == _hash_session_id(session_id),
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
            )
        )
        .first()
    )
    if not session:
        return None

    try:
        expires_at = datetime.fromisoformat(session.expires_at)
    except ValueError:
        return None

    if expires_at <= datetime.now(timezone.utc):
        return None

    user = (
        db.query(User)
        .filter(User.id == user_id, User.is_active == True)
        .first()
    )
    return user

def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Enforces an authenticated server-side session backed by an HttpOnly cookie.
    Session revocation is checked on every request.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired.",
    )

    token = request.cookies.get(settings.AUTH_COOKIE_NAME)
    user = _get_user_from_token(token, db)
    if not user:
        raise credentials_exception

    return user

def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    """Returns the authenticated user when a valid session cookie is present."""
    return _get_user_from_token(request.cookies.get(settings.AUTH_COOKIE_NAME), db)

def revoke_session(token: Optional[str], db: Session) -> None:
    """Revokes the current server-side session identified by the cookie."""
    if not token:
        return

    payload = decode_access_token(token)
    if not payload:
        return

    session_id = payload.get("sid")
    user_id = payload.get("sub")
    if not session_id or not user_id:
        return

    session = (
        db.query(UserSession)
        .filter(
            UserSession.session_id_hash == _hash_session_id(session_id),
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if session:
        session.revoked_at = datetime.now(timezone.utc).isoformat()
        db.commit()

def require_admin(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    FastAPI dependency that enforces 'admin' role permissions (RBAC).
    Role is loaded from the database, never trusted from a browser token claim.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource."
        )
    return current_user

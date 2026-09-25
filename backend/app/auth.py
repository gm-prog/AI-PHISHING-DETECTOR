import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.config import settings
from app.db import get_db
from app.models.domain import User, UserSession

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def _hash_session_id(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def create_user_session(user: User, db: Session) -> str:
    """Creates a random opaque session ID; only its SHA-256 hash is stored server-side."""
    session_id = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    db.add(UserSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        session_id_hash=_hash_session_id(session_id),
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
    ))
    db.commit()
    return session_id


def _get_user_from_session(session_id: Optional[str], db: Session) -> Optional[User]:
    if not session_id:
        return None

    session = (
        db.query(UserSession)
        .filter(
            and_(
                UserSession.session_id_hash == _hash_session_id(session_id),
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

    return (
        db.query(User)
        .filter(User.id == session.user_id, User.is_active == True)
        .first()
    )


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired.",
    )
    user = _get_user_from_session(
        request.cookies.get(settings.AUTH_COOKIE_NAME),
        db,
    )
    if not user:
        raise credentials_exception
    return user


def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[User]:
    return _get_user_from_session(
        request.cookies.get(settings.AUTH_COOKIE_NAME),
        db,
    )


def revoke_session(session_id: Optional[str], db: Session) -> None:
    if not session_id:
        return

    session = (
        db.query(UserSession)
        .filter(
            UserSession.session_id_hash == _hash_session_id(session_id),
            UserSession.revoked_at.is_(None),
        )
        .first()
    )
    if session:
        session.revoked_at = datetime.now(timezone.utc).isoformat()
        db.commit()


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to access this resource."
        )
    return current_user

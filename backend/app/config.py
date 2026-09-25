import os
from urllib.parse import urlsplit
from dotenv import load_dotenv

load_dotenv()

LOCAL_ORIGINS = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"


def parse_allowed_origins(raw: str, production: bool = False) -> list[str]:
    origins = [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]
    if not origins:
        raise RuntimeError("ALLOWED_ORIGINS must contain at least one explicit origin.")

    for origin in origins:
        if origin == "*":
            raise RuntimeError("Wildcard CORS origins are not permitted.")
        parsed = urlsplit(origin)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise RuntimeError("ALLOWED_ORIGINS entries must be absolute http(s) origins.")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise RuntimeError("ALLOWED_ORIGINS entries must contain only scheme and host/port.")
        if production and parsed.hostname in {"localhost", "127.0.0.1", "::1"}:
            raise RuntimeError("Loopback CORS origins are not permitted in production.")

    return origins


class Settings:
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development").lower()
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ALLOWED_ORIGINS: str = os.getenv("ALLOWED_ORIGINS", LOCAL_ORIGINS)

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

    AUTH_COOKIE_NAME: str = os.getenv("AUTH_COOKIE_NAME", "sentinel_session")
    CSRF_COOKIE_NAME: str = os.getenv("CSRF_COOKIE_NAME", "sentinel_csrf")
    GUEST_COOKIE_NAME: str = os.getenv("GUEST_COOKIE_NAME", "sentinel_guest")
    AUTH_COOKIE_SECURE: bool = os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true"
    AUTH_COOKIE_SAMESITE: str = os.getenv("AUTH_COOKIE_SAMESITE", "lax").lower()

    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))


settings = Settings()

if settings.ENVIRONMENT not in {"development", "test", "staging", "production"}:
    raise RuntimeError("ENVIRONMENT must be one of: development, test, staging, production")

if settings.ENVIRONMENT == "production" and not os.getenv("ALLOWED_ORIGINS", "").strip():
    raise RuntimeError("ALLOWED_ORIGINS must be explicitly configured in production.")

parse_allowed_origins(
    settings.ALLOWED_ORIGINS,
    production=settings.ENVIRONMENT == "production",
)

if settings.AUTH_COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    raise RuntimeError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")

if settings.AUTH_COOKIE_SAMESITE == "none" and not settings.AUTH_COOKIE_SECURE:
    raise RuntimeError("AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAMESITE is none")

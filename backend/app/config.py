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
    GOOGLE_WEB_RISK_API_KEY: str = os.getenv("GOOGLE_WEB_RISK_API_KEY", "")
    ALLOWED_ORIGINS: str = os.getenv("ALLOWED_ORIGINS", LOCAL_ORIGINS)
    LLM_MAX_INPUT_CHARS: int = int(os.getenv("LLM_MAX_INPUT_CHARS", "12000"))
    MAX_REQUEST_BODY_BYTES: int = int(os.getenv("MAX_REQUEST_BODY_BYTES", "65536"))
    MAX_EXTRACTED_URLS: int = int(os.getenv("MAX_EXTRACTED_URLS", "25"))
    RATE_LIMIT_STORAGE_URI: str = os.getenv("RATE_LIMIT_STORAGE_URI", "memory://").strip()

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

    AUTH_COOKIE_NAME: str = os.getenv("AUTH_COOKIE_NAME", "sentinel_session")
    CSRF_COOKIE_NAME: str = os.getenv("CSRF_COOKIE_NAME", "sentinel_csrf")
    GUEST_COOKIE_NAME: str = os.getenv("GUEST_COOKIE_NAME", "sentinel_guest")
    AUTH_COOKIE_SECURE: bool = os.getenv("AUTH_COOKIE_SECURE", "false").lower() == "true"
    AUTH_COOKIE_SAMESITE: str = os.getenv("AUTH_COOKIE_SAMESITE", "lax").lower()

    # Comma-separated list of trusted Authentication-Results authserv-id hostnames/domains
    TRUSTED_AUTHSERV_IDS: str = os.getenv("TRUSTED_AUTHSERV_IDS", "")

    # Threat Intelligence Feed Ingestion Settings
    PHISHTANK_API_KEY: str = os.getenv("PHISHTANK_API_KEY", "")
    PHISHTANK_FEED_URL: str = os.getenv("PHISHTANK_FEED_URL", "http://data.phishtank.com/data/online-valid.json.bz2")
    OPENPHISH_FEED_URL: str = os.getenv("OPENPHISH_FEED_URL", "https://openphish.com/feed.txt")
    MISP_SERVER_URL: str = os.getenv("MISP_SERVER_URL", "")
    MISP_API_KEY: str = os.getenv("MISP_API_KEY", "")
    THREAT_FEED_MAX_RECORDS: int = int(os.getenv("THREAT_FEED_MAX_RECORDS", "10000"))
    THREAT_FEED_MAX_RESPONSE_BYTES: int = int(os.getenv("THREAT_FEED_MAX_RESPONSE_BYTES", "33554432"))  # 32MB max
    THREAT_FEED_MAX_DECOMPRESSED_BYTES: int = int(os.getenv("THREAT_FEED_MAX_DECOMPRESSED_BYTES", "67108864"))  # 64MB max decompressed
    THREAT_FEED_TIMEOUT_SECONDS: float = float(os.getenv("THREAT_FEED_TIMEOUT_SECONDS", "10.0"))
    THREAT_FEED_MAX_CONCURRENT_FETCHES: int = int(os.getenv("THREAT_FEED_MAX_CONCURRENT_FETCHES", "2"))

    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    @property
    def trusted_authserv_ids_set(self) -> set[str]:
        if not self.TRUSTED_AUTHSERV_IDS:
            return set()
        return {x.strip().lower() for x in self.TRUSTED_AUTHSERV_IDS.split(",") if x.strip()}


settings = Settings()

if settings.ENVIRONMENT not in {"development", "test", "staging", "production"}:
    raise RuntimeError("ENVIRONMENT must be one of: development, test, staging, production")

if settings.ENVIRONMENT == "production" and not os.getenv("ALLOWED_ORIGINS", "").strip():
    raise RuntimeError("ALLOWED_ORIGINS must be explicitly configured in production.")

if settings.ENVIRONMENT == "production" and not settings.RATE_LIMIT_STORAGE_URI.startswith(("redis://", "rediss://")):
    raise RuntimeError("RATE_LIMIT_STORAGE_URI must use Redis in production.")

parse_allowed_origins(
    settings.ALLOWED_ORIGINS,
    production=settings.ENVIRONMENT == "production",
)

if settings.AUTH_COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    raise RuntimeError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")

if settings.AUTH_COOKIE_SAMESITE == "none" and not settings.AUTH_COOKIE_SECURE:
    raise RuntimeError("AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAMESITE is none")

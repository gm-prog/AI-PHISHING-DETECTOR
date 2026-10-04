import os
from urllib.parse import urlsplit
from dotenv import load_dotenv
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

load_dotenv()

LOCAL_ORIGINS = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"

# ================= DATABASE CONFIGURATION CONTRACT =================
#
# Environment matrix:
#   development -> SQLite fallback allowed when DATABASE_URL is not supplied
#   test        -> SQLite fallback allowed when DATABASE_URL is not supplied
#   staging     -> explicit PostgreSQL DATABASE_URL required (fail closed)
#   production  -> explicit PostgreSQL DATABASE_URL required (fail closed)
#
# Production/staging MUST NEVER silently fall back to SQLite.

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SQLITE_PATH = os.path.join(BACKEND_DIR, "phishing_detector.db")
DEFAULT_SQLITE_URL = f"sqlite:///{DEFAULT_SQLITE_PATH}"

# One deliberate driver architecture: SQLAlchemy's default "postgresql"
# dialect resolves to psycopg2, which is the single PostgreSQL DBAPI this
# project installs (psycopg2-binary). "postgresql+psycopg2" is the same
# driver spelled explicitly.
SUPPORTED_POSTGRES_DRIVERNAMES = {"postgresql", "postgresql+psycopg2"}
SQLITE_FALLBACK_ENVIRONMENTS = {"development", "test"}


def normalize_database_url(raw_url: str) -> str:
    """
    Deterministically normalize a database URL.

    - Translates the legacy "postgres://" scheme (still emitted by some
      managed-database providers, e.g. Heroku/older Render databases) and
      the generic "postgresql://" scheme into the project's single
      deliberate driver spelling "postgresql+psycopg2://". This pins the
      installed psycopg2 DBAPI regardless of the SQLAlchemy default
      (SQLAlchemy 2.1+ otherwise resolves bare "postgresql://" to the
      uninstalled psycopg 3 driver).
    - Preserves username, password (including percent-encoded characters),
      hostname, port, database name, and every query/SSL parameter, because
      only the scheme token before "://" is ever rewritten.

    The returned value may contain credentials and MUST never be logged.
    """
    if raw_url is None:
        return ""
    url = raw_url.strip()
    if url.startswith("postgres://"):
        url = "postgresql+psycopg2://" + url[len("postgres://"):]
    elif url.startswith("postgresql://"):
        url = "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def validate_database_url(raw_url: str, environment: str) -> str:
    """
    Validate the DATABASE_URL contract for the given environment and return
    the normalized URL. Fails closed with RuntimeError on violations.

    Error messages intentionally never echo the raw URL or its password.
    """
    environment = (environment or "").lower()
    url = normalize_database_url(raw_url)

    if not url:
        if environment in SQLITE_FALLBACK_ENVIRONMENTS:
            # Deterministic local SQLite fallback for development/test only.
            return DEFAULT_SQLITE_URL
        raise RuntimeError(
            "DATABASE_URL must be explicitly configured in "
            f"{environment or 'production'}. Refusing to fall back to SQLite."
        )

    try:
        parsed = make_url(url)
    except (ArgumentError, ValueError) as exc:
        # Never include the raw URL (it may embed credentials).
        raise RuntimeError(
            "DATABASE_URL is malformed and cannot be parsed as a SQLAlchemy "
            "database URL. Check the configured value; it was not echoed "
            "here to avoid leaking credentials."
        ) from exc

    backend = parsed.get_backend_name()

    if environment in SQLITE_FALLBACK_ENVIRONMENTS:
        if backend == "sqlite":
            return url
        if parsed.drivername in SUPPORTED_POSTGRES_DRIVERNAMES:
            return url
        raise RuntimeError(
            f"DATABASE_URL scheme '{parsed.drivername}' is not supported. "
            "Supported schemes: sqlite (development/test only), "
            "postgresql, postgresql+psycopg2."
        )

    # staging / production: PostgreSQL only, fail closed.
    if backend == "sqlite":
        raise RuntimeError(
            f"DATABASE_URL must not point to SQLite in {environment}. "
            "Provision a PostgreSQL database and configure its URL."
        )
    if parsed.drivername not in SUPPORTED_POSTGRES_DRIVERNAMES:
        raise RuntimeError(
            f"DATABASE_URL scheme '{parsed.drivername}' is not supported in "
            f"{environment}. Use 'postgresql://' (psycopg2 driver)."
        )
    if not parsed.host:
        raise RuntimeError(
            f"DATABASE_URL is missing a hostname; it cannot be used to make "
            f"a reliable PostgreSQL connection in {environment}."
        )
    if not parsed.database:
        raise RuntimeError(
            f"DATABASE_URL is missing a database name; it cannot be used to "
            f"make a reliable PostgreSQL connection in {environment}."
        )
    return url


def resolve_database_url(environment: str | None = None, raw_url: str | None = None) -> str:
    """
    Resolve the effective database URL for the application:
    the validated DATABASE_URL when supplied, otherwise the deterministic
    SQLite fallback in development/test, otherwise fail closed.
    """
    env = (environment if environment is not None else os.getenv("ENVIRONMENT", "development")).lower()
    raw = raw_url if raw_url is not None else os.getenv("DATABASE_URL", "")
    return validate_database_url(raw, env)


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
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
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

# Fail closed at import time when the database configuration contract is
# violated (e.g. missing/blank/SQLite/unsupported DATABASE_URL in production).
DATABASE_URL_RESOLVED: str = validate_database_url(settings.DATABASE_URL, settings.ENVIRONMENT)

parse_allowed_origins(
    settings.ALLOWED_ORIGINS,
    production=settings.ENVIRONMENT == "production",
)

if settings.AUTH_COOKIE_SAMESITE not in {"lax", "strict", "none"}:
    raise RuntimeError("AUTH_COOKIE_SAMESITE must be one of: lax, strict, none")

if settings.AUTH_COOKIE_SAMESITE == "none" and not settings.AUTH_COOKIE_SECURE:
    raise RuntimeError("AUTH_COOKIE_SECURE must be true when AUTH_COOKIE_SAMESITE is none")

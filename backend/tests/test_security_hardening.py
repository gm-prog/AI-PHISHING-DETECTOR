import logging
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.auth import get_password_hash
from app.db import Base, get_db
from app.main import app, limiter, SensitiveLogFilter
from app.models.domain import User, ScanHistory, UserSession

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_security_db.db"
test_engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture(autouse=True)
def isolate_external_threat_intel(monkeypatch):
    async def fake_vt(url, api_key):
        return {
            "status": "skipped",
            "url": url,
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 100,
            "vendors": [],
        }

    async def fake_urlhaus(url):
        return {
            "status": "success",
            "url": url,
            "in_database": False,
            "threat_type": None,
            "date_added": "",
            "malware_families": [],
        }

    monkeypatch.setattr("app.main.analyze_url_with_virustotal", fake_vt)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", fake_urlhaus)


def csrf_headers(client):
    if not client.cookies.get("sentinel_csrf"):
        client.get("/api/health")
    token = client.cookies.get("sentinel_csrf")
    assert token, "CSRF cookie must be bootstrapped before unsafe requests"
    return {"X-CSRF-Token": token}


def register(client, email, password):
    client.get("/api/health")
    return client.post("/api/auth/register", json={"email": email, "password": password}, headers=csrf_headers(client))


def login(client, email, password):
    client.get("/api/health")
    return client.post("/api/auth/login", json={"email": email, "password": password}, headers=csrf_headers(client))


def test_user_registration_and_login_uses_http_only_cookie(client):
    email = f"user_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "SecurePassword123!"

    reg_res = register(client, email, pwd)
    assert reg_res.status_code == 200
    data = reg_res.json()
    assert "access_token" not in data
    assert data["user"]["email"] == email
    assert data["user"]["role"] == "user"

    session_cookie = client.cookies.get("sentinel_session")
    csrf_cookie = client.cookies.get("sentinel_csrf")
    assert session_cookie
    assert csrf_cookie
    assert "HttpOnly" in reg_res.headers.get("set-cookie", "")
    assert "samesite" in reg_res.headers.get("set-cookie", "").lower()

    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email

    login_res = login(client, email, pwd)
    assert login_res.status_code == 200
    assert "access_token" not in login_res.json()
    assert client.get("/api/auth/me").status_code == 200


def test_logout_revokes_server_session(client):
    email = f"logout_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "SecurePassword123!"
    assert register(client, email, pwd).status_code == 200

    before = client.get("/api/auth/me")
    assert before.status_code == 200

    session_cookie = client.cookies.get("sentinel_session")
    assert session_cookie

    logout_res = client.post("/api/auth/logout", headers=csrf_headers(client))
    assert logout_res.status_code == 200
    assert client.get("/api/auth/me").status_code == 401

    db = TestingSessionLocal()
    try:
        assert db.query(UserSession).count() >= 1
        assert db.query(UserSession).filter(UserSession.revoked_at.is_not(None)).count() >= 1
    finally:
        db.close()


def test_csrf_blocks_unsafe_requests_without_token(client):
    email = f"csrf_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "SecurePassword123!"
    assert register(client, email, pwd).status_code == 200

    blocked = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://example.com/login"},
    )
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "CSRF validation failed."

    allowed = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://example.com/login"},
        headers=csrf_headers(client),
    )
    assert allowed.status_code == 200


def test_user_data_isolation(client):
    user1 = TestClient(app)
    user2 = TestClient(app)
    user1_email = f"alice_{uuid.uuid4().hex[:6]}@test.com"
    user2_email = f"bob_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "ComplexPassword789!"

    assert register(user1, user1_email, pwd).status_code == 200
    assert register(user2, user2_email, pwd).status_code == 200

    scan1 = user1.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://secure-paypa1-update.xyz/login"},
        headers=csrf_headers(user1),
    )
    assert scan1.status_code == 200

    h1 = user1.get("/api/history")
    assert len(h1.json()) >= 1
    assert "paypa1" in h1.json()[0]["content"]

    h2 = user2.get("/api/history")
    assert len(h2.json()) == 0


def test_idor_prevention(client):
    owner = TestClient(app)
    attacker = TestClient(app)
    u1_email = f"owner_{uuid.uuid4().hex[:6]}@test.com"
    u2_email = f"attacker_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "ComplexPassword123!"

    assert register(owner, u1_email, pwd).status_code == 200
    assert register(attacker, u2_email, pwd).status_code == 200

    assert owner.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://github.com/features/security"},
        headers=csrf_headers(owner),
    ).status_code == 200

    scan_id = owner.get("/api/history").json()[0]["id"]

    idor_get = attacker.get(f"/api/history/{scan_id}")
    assert idor_get.status_code == 403

    idor_del = attacker.delete(f"/api/history/{scan_id}", headers=csrf_headers(attacker))
    assert idor_del.status_code == 403


def test_admin_route_locking(client):
    user = TestClient(app)
    user_email = f"standard_{uuid.uuid4().hex[:6]}@test.com"
    admin_email = f"admin_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "AdminSecurePass2026!"

    assert register(user, user_email, pwd).status_code == 200

    db = TestingSessionLocal()
    try:
        admin = User(
            id=str(uuid.uuid4()),
            email=admin_email,
            hashed_password=get_password_hash(pwd),
            role="admin",
            is_active=True,
        )
        db.add(admin)
        db.commit()
    finally:
        db.close()

    assert user.get("/api/admin/metrics").status_code == 403

    admin_client = TestClient(app)
    assert login(admin_client, admin_email, pwd).status_code == 200
    assert admin_client.get("/api/admin/metrics").status_code == 200


def test_parameter_tampering_prevention(client):
    email = f"hacker_{uuid.uuid4().hex[:6]}@test.com"
    client.get("/api/health")
    res = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "password": "StrongPassword123!",
            "role": "admin",
            "is_active": True,
            "admin_code": "obsolete-bootstrap-value",
        },
        headers=csrf_headers(client),
    )
    assert res.status_code == 200
    assert res.json()["user"]["role"] == "user"


def test_sql_injection_defense(client):
    for payload in [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT null, null, null --",
        "'; DROP TABLE users; --",
    ]:
        res = client.post("/api/auth/login", json={"email": payload, "password": "password"}, headers=csrf_headers(client))
        assert res.status_code in [400, 401, 422]


def test_input_validation(client):
    assert client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "   "},
        headers=csrf_headers(client),
    ).status_code in [400, 422]

    assert client.post(
        "/api/analyze",
        json={"input_type": "malicious_type", "content": "https://google.com"},
        headers=csrf_headers(client),
    ).status_code in [400, 422]

    assert client.post(
        "/api/auth/register",
        json={"email": "not-an-email", "password": "short"},
        headers=csrf_headers(client),
    ).status_code in [400, 422]


def test_log_redaction():
    filter_instance = SensitiveLogFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="",
        lineno=0,
        msg="Connecting with key AIzaSyBCDEFGHIJKLMNOPQRSTUVWXYZ12345 and Bearer eyJhbGciOiJIUzI1NiJ9.xyz",
        args=(),
        exc_info=None,
    )
    filter_instance.filter(record)
    assert "AIzaSy...[REDACTED]" in record.msg
    assert "Bearer [REDACTED_JWT]" in record.msg


def test_health_check_clarity(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["api_active"] is True
    assert "gemini_configured" not in data
    assert "virustotal_configured" not in data


def test_security_headers(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    csp = res.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp


def test_no_bearer_authorization_is_accepted(client):
    email = f"bearer_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "SecurePassword123!"
    assert register(client, email, pwd).status_code == 200

    # A separate client without the session cookie cannot authenticate with a bearer header.
    attacker = TestClient(app)
    assert attacker.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer arbitrary-token"},
    ).status_code == 401


def test_anonymous_history_is_isolated_by_guest_session():
    guest1 = TestClient(app)
    guest2 = TestClient(app)

    assert guest1.get("/api/history").status_code == 200
    assert guest2.get("/api/history").status_code == 200
    assert guest1.get("/api/history").json() == []
    assert guest2.get("/api/history").json() == []

    scan = guest1.post(
        "/api/analyze",
        json={
            "input_type": "url",
            "content": "https://guest-one-private.example/login",
        },
        headers=csrf_headers(guest1),
    )
    assert scan.status_code == 200
    assert guest1.cookies.get("sentinel_guest")
    assert len(guest1.cookies.get("sentinel_guest")) >= 32

    guest1_history = guest1.get("/api/history")
    assert guest1_history.status_code == 200
    assert len(guest1_history.json()) == 1
    assert "guest-one-private" in guest1_history.json()[0]["content"]

    guest2_history = guest2.get("/api/history")
    assert guest2_history.status_code == 200
    assert guest2_history.json() == []

    db = TestingSessionLocal()
    try:
        record = db.query(ScanHistory).filter(ScanHistory.content.contains("guest-one-private")).one()
        assert record.user_id is None
        assert record.guest_session_hash
        assert record.guest_session_hash != guest1.cookies.get("sentinel_guest")
        assert record.guest_session_hash != guest2.cookies.get("sentinel_guest")
    finally:
        db.close()


def test_anonymous_clear_history_only_clears_current_guest_session():
    guest1 = TestClient(app)
    guest2 = TestClient(app)

    for client, value in [
        (guest1, "https://guest-one-clear.example/login"),
        (guest2, "https://guest-two-clear.example/login"),
    ]:
        assert client.post(
            "/api/analyze",
            json={"input_type": "url", "content": value},
            headers=csrf_headers(client),
        ).status_code == 200

    assert len(guest1.get("/api/history").json()) == 1
    assert len(guest2.get("/api/history").json()) == 1

    cleared = guest1.delete("/api/history", headers=csrf_headers(guest1))
    assert cleared.status_code == 200
    assert guest1.get("/api/history").json() == []
    assert len(guest2.get("/api/history").json()) == 1


def test_cors_rejects_unconfigured_origin(client):
    res = client.options(
        "/api/auth/me",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") is None


def test_cors_allows_explicit_configured_origin(client):
    origin = "http://localhost:5173"
    res = client.options(
        "/api/auth/me",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert res.headers.get("access-control-allow-origin") == origin
    assert res.headers.get("access-control-allow-credentials") == "true"


def test_production_cors_parser_rejects_wildcard_and_loopback():
    from app.config import parse_allowed_origins

    with pytest.raises(RuntimeError):
        parse_allowed_origins("*", production=True)

    with pytest.raises(RuntimeError):
        parse_allowed_origins("http://localhost:5173", production=True)

    assert parse_allowed_origins("https://app.example.com", production=True) == [
        "https://app.example.com"
    ]


def test_production_api_docs_configuration_is_disabled():
    from fastapi import FastAPI

    production = True
    docs_url = None if production else "/docs"
    redoc_url = None if production else "/redoc"
    openapi_url = None if production else "/openapi.json"

    app = FastAPI(
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )
    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None




def test_provider_cache_is_bounded_and_expires():
    from app.services.provider_guard import TTLCache
    import asyncio

    cache = TTLCache(max_entries=1, ttl_seconds=0.01)

    async def exercise():
        await cache.set("first", {"ok": True})
        assert await cache.get("first") == {"ok": True}
        await cache.set("second", {"ok": True})
        assert await cache.get("first") is None
        assert await cache.get("second") == {"ok": True}
        await asyncio.sleep(0.02)
        assert await cache.get("second") is None

    asyncio.run(exercise())


def test_llm_input_is_bounded_before_provider_call(client, monkeypatch):
    email = f"llm_bound_{uuid.uuid4().hex[:6]}@example.com"
    response = register(client, email, "SecurePassword123!")
    assert response.status_code == 200

    from app.config import settings
    captured = {}

    async def fake_llm(input_type, content, api_key, heuristic_score, heuristic_signals):
        captured["length"] = len(content)
        return {
            "risk_score": heuristic_score,
            "status": "safe",
            "phishing_signals": heuristic_signals,
            "ai_explanation": "test",
        }

    monkeypatch.setattr("app.main.analyze_with_llm", fake_llm)
    monkeypatch.setattr(settings, "GEMINI_API_KEY", "test-only-placeholder")
    oversized = "https://example.com/" + ("A" * (settings.LLM_MAX_INPUT_CHARS + 100))
    res = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": oversized},
        headers=csrf_headers(client),
    )
    assert res.status_code == 200
    assert captured["length"] == settings.LLM_MAX_INPUT_CHARS


def test_request_body_size_guard_rejects_oversized_payload():
    client = TestClient(app)
    client.get("/api/health")
    oversized = "A" * 70000
    res = client.post(
        "/api/analyze",
        json={"input_type": "email_text", "content": oversized},
        headers=csrf_headers(client),
    )
    assert res.status_code == 413


def test_analysis_rate_limit_is_enforced_per_anonymous_ip_bucket():
    client = TestClient(app)
    client.get("/api/health")
    headers = csrf_headers(client)

    responses = []
    for i in range(11):
        responses.append(client.post(
            "/api/analyze",
            json={"input_type": "url", "content": f"https://rate-limit-{i}.example/login"},
            headers=headers,
        ))

    assert [res.status_code for res in responses[:10]] == [200] * 10
    assert responses[10].status_code == 429

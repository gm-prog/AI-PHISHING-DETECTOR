import pytest
import uuid
import logging
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, get_db
from app.main import app, SensitiveLogFilter
from app.models.domain import User, ScanHistory
from app.auth import get_password_hash

# Use an in-memory SQLite database for isolated test runs
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

# Helper to register and get token
def create_test_user(client, email, password, admin_code=None):
    payload = {"email": email, "password": password}
    if admin_code:
        payload["admin_code"] = admin_code
    res = client.post("/api/auth/register", json=payload)
    return res

# 1. TEST AUTHENTICATION & JWT CREATION
def test_user_registration_and_login(client):
    email = f"user_{uuid.uuid4().hex[:6]}@example.com"
    pwd = "SecurePassword123!"

    # Register
    reg_res = client.post("/api/auth/register", json={"email": email, "password": pwd})
    assert reg_res.status_code == 200
    data = reg_res.json()
    assert "access_token" in data
    assert data["user"]["email"] == email
    assert data["user"]["role"] == "user"

    # Login
    login_res = client.post("/api/auth/login", json={"email": email, "password": pwd})
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()

    # Me profile check
    token = login_res.json()["access_token"]
    me_res = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["email"] == email


# 2. TEST USER ISOLATION & ROW LEVEL DATA SCOPING
def test_user_data_isolation(client):
    user1_email = f"alice_{uuid.uuid4().hex[:6]}@test.com"
    user2_email = f"bob_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "ComplexPassword789!"

    res1 = client.post("/api/auth/register", json={"email": user1_email, "password": pwd})
    token1 = res1.json()["access_token"]

    res2 = client.post("/api/auth/register", json={"email": user2_email, "password": pwd})
    token2 = res2.json()["access_token"]

    # User 1 performs a scan
    scan1 = client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://secure-paypa1-update.xyz/login"},
        headers={"Authorization": f"Bearer {token1}"}
    )
    assert scan1.status_code == 200

    # User 1 fetches history -> should contain 1 scan
    h1 = client.get("/api/history", headers={"Authorization": f"Bearer {token1}"})
    assert len(h1.json()) >= 1
    assert "paypa1" in h1.json()[0]["content"]

    # User 2 fetches history -> MUST be isolated (0 scans)
    h2 = client.get("/api/history", headers={"Authorization": f"Bearer {token2}"})
    assert len(h2.json()) == 0


# 3. TEST IDOR ATTACK PREVENTION
def test_idor_prevention(client):
    u1_email = f"owner_{uuid.uuid4().hex[:6]}@test.com"
    u2_email = f"attacker_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "ComplexPassword123!"

    tok1 = client.post("/api/auth/register", json={"email": u1_email, "password": pwd}).json()["access_token"]
    tok2 = client.post("/api/auth/register", json={"email": u2_email, "password": pwd}).json()["access_token"]

    # Owner creates a scan
    client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://github.com/features/security"},
        headers={"Authorization": f"Bearer {tok1}"}
    )
    owner_history = client.get("/api/history", headers={"Authorization": f"Bearer {tok1}"}).json()
    scan_id = owner_history[0]["id"]

    # Attacker tries to read owner's scan via direct ID
    idor_get = client.get(f"/api/history/{scan_id}", headers={"Authorization": f"Bearer {tok2}"})
    assert idor_get.status_code == 403
    assert "Unauthorized" in idor_get.json()["detail"]

    # Attacker tries to delete owner's scan via direct ID
    idor_del = client.delete(f"/api/history/{scan_id}", headers={"Authorization": f"Bearer {tok2}"})
    assert idor_del.status_code == 403


# 4. TEST ADMIN ROUTE RBAC LOCKING
def test_admin_route_locking(client):
    user_email = f"standard_{uuid.uuid4().hex[:6]}@test.com"
    admin_email = f"admin_{uuid.uuid4().hex[:6]}@test.com"
    pwd = "AdminSecurePass2026!"

    user_tok = client.post("/api/auth/register", json={"email": user_email, "password": pwd}).json()["access_token"]
    admin_tok = client.post(
        "/api/auth/register",
        json={"email": admin_email, "password": pwd, "admin_code": "SENTINEL_ADMIN_SECRET_2026"}
    ).json()["access_token"]

    # Normal user accesses admin metrics -> 403 Forbidden
    res_user = client.get("/api/admin/metrics", headers={"Authorization": f"Bearer {user_tok}"})
    assert res_user.status_code == 403

    # Admin accesses admin metrics -> 200 OK
    res_admin = client.get("/api/admin/metrics", headers={"Authorization": f"Bearer {admin_tok}"})
    assert res_admin.status_code == 200
    assert "total_users" in res_admin.json()
    assert "total_scans" in res_admin.json()


# 5. TEST SQL INJECTION RESISTANCE
def test_sql_injection_defense(client):
    sqli_payloads = [
        "' OR '1'='1",
        "admin' --",
        "' UNION SELECT null, null, null --",
        "'; DROP TABLE users; --"
    ]
    for payload in sqli_payloads:
        # Test in login
        res = client.post("/api/auth/login", json={"email": payload, "password": "password"})
        # Should cleanly return 400 (invalid email format) or 401 (unauthorized) without DB error
        assert res.status_code in [400, 401, 422]

        # Test in analysis content
        scan_res = client.post("/api/analyze", json={"input_type": "url", "content": f"https://example.com/{payload}"})
        assert scan_res.status_code in [200, 400]


# 6. TEST INPUT VALIDATION BOUNDARIES
def test_input_validation(client):
    # Empty content
    r1 = client.post("/api/analyze", json={"input_type": "url", "content": "   "})
    assert r1.status_code in [400, 422]

    # Invalid input_type
    r2 = client.post("/api/analyze", json={"input_type": "malicious_type", "content": "https://google.com"})
    assert r2.status_code in [400, 422]

    # Malformed email during registration
    r3 = client.post("/api/auth/register", json={"email": "not-an-email", "password": "short"})
    assert r3.status_code in [400, 422]


# 7. TEST SENSITIVE LOG REDACTION
def test_log_redaction():
    filter_instance = SensitiveLogFilter()
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="", lineno=0,
        msg="Connecting with key AIzaSyBCDEFGHIJKLMNOPQRSTUVWXYZ12345 and Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
        args=(), exc_info=None
    )
    filter_instance.filter(record)
    assert "AIzaSy...[REDACTED]" in record.msg
    assert "Bearer [REDACTED_JWT]" in record.msg


# 8. TEST HEALTH ENDPOINT WITH DUAL ENGINE CLARITY
def test_health_check_clarity(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert "engine_mode" in data
    assert "Autonomous" in data["engine_mode"] or "Hybrid" in data["engine_mode"]
    assert data["api_active"] is True


# 9. TEST PARAMETER TAMPERING / PRIVILEGE ESCALATION PREVENTION
def test_parameter_tampering_prevention(client):
    # Attempt to self-assign admin role via normal registration payload
    email = f"hacker_{uuid.uuid4().hex[:6]}@test.com"
    tampered_payload = {
        "email": email,
        "password": "StrongPassword123!",
        "role": "admin", # Client tries to force role
        "is_active": True,
        "admin_code": "wrong_code"
    }
    res = client.post("/api/auth/register", json=tampered_payload)
    assert res.status_code == 200
    # Must STILL be assigned 'user' role because server ignores client 'role' field
    assert res.json()["user"]["role"] == "user"


# 10. TEST SCOPED HISTORY DELETION (NO CROSS-USER DELETION)
def test_scoped_history_bulk_clear(client):
    u1 = client.post("/api/auth/register", json={"email": f"u1_{uuid.uuid4().hex[:6]}@test.com", "password": "PassWord123!"}).json()["access_token"]
    u2 = client.post("/api/auth/register", json={"email": f"u2_{uuid.uuid4().hex[:6]}@test.com", "password": "PassWord123!"}).json()["access_token"]

    # Both scan something
    client.post("/api/analyze", json={"input_type": "url", "content": "https://test1.com"}, headers={"Authorization": f"Bearer {u1}"})
    client.post("/api/analyze", json={"input_type": "url", "content": "https://test2.com"}, headers={"Authorization": f"Bearer {u2}"})

    # U1 clears history
    clear_res = client.delete("/api/history", headers={"Authorization": f"Bearer {u1}"})
    assert clear_res.status_code == 200

    # U1 has 0 scans, U2 STILL HAS THEIR 1 SCAN
    assert len(client.get("/api/history", headers={"Authorization": f"Bearer {u1}"}).json()) == 0
    assert len(client.get("/api/history", headers={"Authorization": f"Bearer {u2}"}).json()) == 1


# 11. TEST SECURITY HEADERS ENFORCEMENT
def test_security_headers(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")



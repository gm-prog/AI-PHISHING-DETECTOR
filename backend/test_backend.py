import json
import sys
from fastapi.testclient import TestClient
from app.main import app


def test_health():
    """Verify health endpoint responds with healthy status code and payload."""
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["api_active"] is True
    assert "version" in data


def test_analyze():
    """Verify threat scanner analysis endpoint processes request and returns structured report."""
    client = TestClient(app)
    client.get("/api/health")
    token = client.cookies.get("sentinel_csrf")
    headers = {"X-CSRF-Token": token} if token else {}
    payload = {
        "input_type": "url",
        "content": "http://secure-login-paypa1-update.xyz/signin"
    }
    response = client.post("/api/analyze", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 0
    assert data["status"] in ("safe", "warning", "danger")
    assert "phishing_signals" in data
    assert "ai_explanation" in data


if __name__ == "__main__":
    test_health()
    test_analyze()
    print("\n[OK] All backend standalone tests complete!")

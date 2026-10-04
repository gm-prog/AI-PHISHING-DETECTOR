"""
SENTINEL AI — live deployment verification harness.

Exercises a RUNNING deployment end-to-end using the application's actual
authentication architecture:

  - HttpOnly opaque session cookie (no JWT, no Authorization: Bearer)
  - double-submit CSRF protection (CSRF cookie + X-CSRF-Token header)

Configuration is supplied via environment variables; nothing sensitive is
hardcoded and nothing sensitive is ever printed:

  BASE_URL        target deployment, e.g. https://sentinel.example.com
                  (default: http://127.0.0.1:8000 for local verification)
  ADMIN_EMAIL     optional: existing admin account email for the RBAC check
  ADMIN_PASSWORD  optional: password for ADMIN_EMAIL

Usage:
  BASE_URL=https://your-deployment python tests/verify_live.py
"""

import os
import secrets
import sys

import httpx

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

# The cookie names mirror backend defaults; override via env when customized.
CSRF_COOKIE_NAME = os.environ.get("CSRF_COOKIE_NAME", "sentinel_csrf")
AUTH_COOKIE_NAME = os.environ.get("AUTH_COOKIE_NAME", "sentinel_session")

PASSWORD = "LiveVerify-" + secrets.token_urlsafe(12)  # throwaway, per-run


def fail(message: str) -> None:
    print(f"FAIL: {message}")
    sys.exit(1)


def bootstrap_csrf(client: httpx.Client) -> None:
    """Obtain CSRF state via a harmless unauthenticated GET."""
    response = client.get("/api/health")
    if response.status_code != 200:
        fail(
            f"health check returned HTTP {response.status_code}; "
            "deployment is unreachable or unhealthy"
        )
    if CSRF_COOKIE_NAME not in client.cookies:
        fail("CSRF cookie was not issued by the deployment")


def csrf_headers(client: httpx.Client) -> dict:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    if not token:
        fail("missing CSRF cookie; cannot perform state-changing requests")
    return {"X-CSRF-Token": token}


def register(client: httpx.Client, email: str) -> None:
    response = client.post(
        "/api/auth/register",
        json={"email": email, "password": PASSWORD},
        headers=csrf_headers(client),
    )
    if response.status_code != 200:
        fail(f"registration for a fresh account returned HTTP {response.status_code}")
    if AUTH_COOKIE_NAME not in client.cookies:
        fail("session cookie was not issued on registration")


def main() -> None:
    suffix = secrets.token_hex(4)
    client_a = httpx.Client(base_url=BASE_URL, timeout=30.0)
    client_b = httpx.Client(base_url=BASE_URL, timeout=30.0)

    # 0. Health + CSRF bootstrap (session cookie flows automatically afterwards)
    bootstrap_csrf(client_a)
    bootstrap_csrf(client_b)
    print("0. Health check & CSRF bootstrap: OK")

    # 1. Register two isolated users via the real cookie-session flow
    register(client_a, f"live_a_{suffix}@verify.test")
    register(client_b, f"live_b_{suffix}@verify.test")
    print("1. Cookie-session registration (User A & User B): OK")

    # 2. CSRF enforcement: a state-changing request WITHOUT the header must fail
    no_csrf = client_a.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://github.com"},
    )
    if no_csrf.status_code != 403:
        fail(f"CSRF protection did not reject a missing token (HTTP {no_csrf.status_code})")
    print("2. CSRF enforcement (missing X-CSRF-Token rejected): OK")

    # 3. Authenticated analysis as User A (representative authenticated path)
    scan = client_a.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://github.com"},
        headers=csrf_headers(client_a),
    )
    if scan.status_code != 200:
        fail(f"authenticated /api/analyze returned HTTP {scan.status_code}")
    print("3. Authenticated analysis via session cookie: OK")

    # 4. History ownership & isolation
    hist_a = client_a.get("/api/history")
    if hist_a.status_code != 200 or not hist_a.json():
        fail("User A cannot read their own scan history")
    scan_id = hist_a.json()[0]["id"]

    hist_b = client_b.get("/api/history")
    if hist_b.status_code != 200 or hist_b.json():
        fail("User B history is not isolated (expected 0 scans)")
    print("4. History ownership & isolation: OK")

    # 5. IDOR prevention (read & delete of another user's scan)
    idor_read = client_b.get(f"/api/history/{scan_id}")
    if idor_read.status_code not in (403, 404):
        fail(f"IDOR read not blocked (HTTP {idor_read.status_code})")
    idor_delete = client_b.delete(
        f"/api/history/{scan_id}", headers=csrf_headers(client_b)
    )
    if idor_delete.status_code not in (403, 404):
        fail(f"IDOR delete not blocked (HTTP {idor_delete.status_code})")
    print("5. IDOR prevention (read & delete): OK")

    # 6. Admin route is locked for standard users
    admin_locked = client_b.get("/api/admin/metrics")
    if admin_locked.status_code not in (401, 403):
        fail(f"admin route not locked for standard users (HTTP {admin_locked.status_code})")
    print("6. Admin RBAC lock for standard users: OK")

    # 7. Optional: admin access with operator-supplied credentials (never printed)
    if ADMIN_EMAIL and ADMIN_PASSWORD:
        admin_client = httpx.Client(base_url=BASE_URL, timeout=30.0)
        bootstrap_csrf(admin_client)
        login = admin_client.post(
            "/api/auth/login",
            json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
            headers=csrf_headers(admin_client),
        )
        if login.status_code != 200:
            fail(f"admin login failed (HTTP {login.status_code})")
        metrics = admin_client.get("/api/admin/metrics")
        if metrics.status_code != 200:
            fail(f"admin metrics not accessible to admin (HTTP {metrics.status_code})")
        admin_client.close()
        print("7. Admin RBAC access with operator-supplied credentials: OK")
    else:
        print("7. Admin RBAC access: SKIPPED (set ADMIN_EMAIL / ADMIN_PASSWORD to enable)")

    # 8. Logout revokes the session server-side
    logout = client_a.post("/api/auth/logout", headers=csrf_headers(client_a))
    if logout.status_code != 200:
        fail(f"logout returned HTTP {logout.status_code}")
    me_after = client_a.get("/api/auth/me")
    if me_after.status_code != 401:
        fail(f"session not revoked after logout (HTTP {me_after.status_code})")
    print("8. Logout & server-side session revocation: OK")

    client_a.close()
    client_b.close()
    print("\nALL LIVE END-TO-END SECURITY CHECKS PASSED")


if __name__ == "__main__":
    main()

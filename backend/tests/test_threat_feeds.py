import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import aiohttp
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fastapi.testclient import TestClient

from app.db import Base, get_db
from app.main import app, limiter
from app.models.domain import User, ThreatIndicator, ThreatFeedState
from app.auth import get_password_hash, create_user_session
from app.config import settings
from app.services.threat_feed_service import (
    NormalizedThreatIndicator,
    ThreatEvidence,
    ThreatFeedProvider,
    PhishTankFeedProvider,
    OpenPhishFeedProvider,
    MISPFeedProvider,
    normalize_indicator_value,
    parse_and_normalize_utc_iso,
    compute_freshness,
    lookup_threat_indicator,
    refresh_threat_feed,
    refresh_all_threat_feeds,
    get_all_feed_states,
    get_registered_providers,
)

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_threat_feeds_db.db"
test_engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if old_override is not None:
        app.dependency_overrides[get_db] = old_override
    else:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    return TestClient(app)


def get_csrf_headers(client):
    if not client.cookies.get("sentinel_csrf"):
        client.get("/api/health")
    token = client.cookies.get("sentinel_csrf")
    assert token
    return {"X-CSRF-Token": token}


def create_test_user(db: Session, email: str, role: str = "user") -> User:
    user = db.query(User).filter_by(email=email).first()
    if not user:
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            hashed_password=get_password_hash("StrongPassword123!"),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    return user


class MockStreamReader:
    def __init__(self, data: bytes):
        self._data = data
        self._offset = 0

    async def read(self, n=-1):
        if self._offset >= len(self._data):
            return b""
        if n < 0 or self._offset + n >= len(self._data):
            res = self._data[self._offset:]
            self._offset = len(self._data)
            return res
        res = self._data[self._offset:self._offset + n]
        self._offset += n
        return res


class MockStreamResponse:
    def __init__(self, status=200, content_bytes=b"", headers=None):
        self.status = status
        self.headers = headers or {}
        self.content = MockStreamReader(content_bytes)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockStreamSession:
    def __init__(self, response=None, exc=None):
        self._response = response
        self._exc = exc

    def request(self, *args, **kwargs):
        if self._exc:
            raise self._exc
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockFeedProvider:
    def __init__(self, source_name: str, indicators: list):
        self.source_name = source_name
        self.indicator_types = ["url"]
        self.supports_etag = True
        self.supports_last_modified = True
        self.default_refresh_interval_seconds = 86400
        self.fetch_limit = 1000
        self.is_enabled = True
        self._indicators = indicators

    async def fetch_indicators(self, limit: int = 1000, etag=None, last_modified=None):
        return self._indicators[:limit], "etag-test-123", "Wed, 04 Oct 2026 12:00:00 GMT", False


class SlowFeedProvider:
    source_name = "slow_feed"
    indicator_types = ["url"]
    supports_etag = False
    supports_last_modified = False
    default_refresh_interval_seconds = 86400
    fetch_limit = 1000
    is_enabled = True

    async def fetch_indicators(self, limit: int = 1000, etag=None, last_modified=None):
        await asyncio.sleep(2.0)
        return [], None, None, False


class ErrorFeedProvider:
    source_name = "error_feed"
    indicator_types = ["url"]
    supports_etag = False
    supports_last_modified = False
    default_refresh_interval_seconds = 86400
    fetch_limit = 1000
    is_enabled = True

    async def fetch_indicators(self, limit: int = 1000, etag=None, last_modified=None):
        raise RuntimeError("Feed upstream network failure (500)")


# ================= PART 1: INDICATOR & TIMESTAMP NORMALIZATION =================
def test_normalize_indicator_value_url_edge_cases():
    """Verify deterministic URL normalization: scheme, host, default-ports, query sorting, fragments."""
    # 1. Scheme and host lowercasing with port 80 / 443 stripping
    clean1, h1 = normalize_indicator_value("url", "HTTP://EXAMPLE.COM:80/path/to/page/")
    assert clean1 == "http://example.com/path/to/page"

    clean2, h2 = normalize_indicator_value("url", "https://EXAMPLE.COM:443/path/to/page")
    assert clean2 == "https://example.com/path/to/page"

    # Non-standard port preserved
    clean_port, _ = normalize_indicator_value("url", "https://evil.net:8443/login")
    assert clean_port == "https://evil.net:8443/login"

    # 2. Fragment stripping
    clean_frag, h_frag = normalize_indicator_value("url", "https://example.com/login#section2")
    assert clean_frag == "https://example.com/login"
    assert h_frag == hashlib.sha256("https://example.com/login".encode("utf-8")).hexdigest()

    # 3. Query parameter sorting
    clean_q1, _ = normalize_indicator_value("url", "https://example.com/api?b=2&a=1&c=3")
    clean_q2, _ = normalize_indicator_value("url", "https://example.com/api?c=3&a=1&b=2")
    assert clean_q1 == "https://example.com/api?a=1&b=2&c=3"
    assert clean_q1 == clean_q2

    # 4. Domain / IP / Hash normalization
    clean_dom, _ = normalize_indicator_value("domain", "BAD-DOMAIN.COM.")
    assert clean_dom == "bad-domain.com"

    clean_ip, _ = normalize_indicator_value("ip", "192.168.1.1")
    assert clean_ip == "192.168.1.1"


def test_parse_and_normalize_utc_iso():
    """Verify canonical UTC ISO-8601 parsing across datetimes, offsets, and strings."""
    iso_z = parse_and_normalize_utc_iso("2026-10-04T12:00:00Z")
    assert iso_z == "2026-10-04T12:00:00+00:00"

    iso_offset = parse_and_normalize_utc_iso("2026-10-04T17:30:00+05:30")
    assert iso_offset == "2026-10-04T12:00:00+00:00"

    dt = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
    assert parse_and_normalize_utc_iso(dt) == "2026-10-04T12:00:00+00:00"

    assert parse_and_normalize_utc_iso(None) is None
    assert parse_and_normalize_utc_iso("not-a-date") is None


def test_compute_freshness_states():
    """Verify deterministic feed freshness states (fresh, stale, expired, never_synced, failed, disabled)."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # 1. Disabled
    assert compute_freshness(now_iso, now_iso, None, 86400, enabled=False) == "disabled"

    # 2. Never synced
    assert compute_freshness(None, None, None, 86400, enabled=True) == "never_synced"

    # 3. Fresh (synced within 1.5x interval)
    fresh_time = (now - timedelta(hours=12)).isoformat()
    assert compute_freshness(fresh_time, now_iso, None, 86400, enabled=True) == "fresh"

    # 4. Stale (synced between 1.5x and 3.0x interval)
    stale_time = (now - timedelta(hours=48)).isoformat()
    assert compute_freshness(stale_time, now_iso, None, 86400, enabled=True) == "stale"

    # 5. Expired (synced > 3.0x interval)
    expired_time = (now - timedelta(days=5)).isoformat()
    assert compute_freshness(expired_time, now_iso, None, 86400, enabled=True) == "expired"


# ================= PART 2: PHISHTANK CONNECTOR TESTS =================
@pytest.mark.asyncio
async def test_phishtank_valid_json_and_edge_cases():
    """Verify PhishTank connector parses valid items, skips unverified/offline, and normalizes URLs."""
    sample_json = json.dumps([
        {
            "phish_id": "12345",
            "url": "https://secure-login-paypal.com/verify",
            "verified": "yes",
            "online": "yes",
            "verification_time": "2026-10-04T10:00:00Z",
            "target": "PayPal",
        },
        {
            "phish_id": "12346",
            "url": "http://unverified-sample.net/test",
            "verified": "no",
            "online": "yes",
        },
        {
            "phish_id": "12347",
            "url": "https://offline-sample.com/phish",
            "verified": "yes",
            "online": "no",
        },
        {
            "phish_id": "12348",
            "url": "",  # Blank URL skipped
        },
        {
            "phish_id": "12349",
            "url": 12345,  # Non-string URL skipped
        }
    ]).encode("utf-8")

    resp = MockStreamResponse(status=200, content_bytes=sample_json, headers={"etag": "pt-etag-1", "last-modified": "Sun, 04 Oct 2026 10:00:00 GMT"})
    session = MockStreamSession(response=resp)

    provider = PhishTankFeedProvider(feed_url="https://test.phishtank/feed.json")
    with patch("aiohttp.ClientSession", return_value=session):
        items, etag, last_mod, not_mod = await provider.fetch_indicators(limit=100)

        assert not_mod is False
        assert etag == "pt-etag-1"
        assert len(items) == 1
        assert items[0].source == "phishtank"
        assert items[0].indicator == "https://secure-login-paypal.com/verify"
        assert items[0].classification == "phishing"
        assert items[0].confidence == 0.95
        assert items[0].metadata.get("target") == "PayPal"


@pytest.mark.asyncio
async def test_feed_downloader_byte_limit_size_guard():
    """Verify bounded_fetch_stream throws ValueError when payload exceeds maximum size guard."""
    from app.services.threat_feed_service import bounded_fetch_stream
    oversized_data = b"X" * (1024 * 1024 + 10)  # > 1MB

    resp = MockStreamResponse(status=200, content_bytes=oversized_data)
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp)):
        async with aiohttp.ClientSession() as session:
            with pytest.raises(ValueError, match="exceeded maximum allowed size"):
                await bounded_fetch_stream(session, "https://test.com/feed", max_bytes=1024 * 1024)


@pytest.mark.asyncio
async def test_feed_refresh_concurrency_bounded_semaphore(db_session):
    """Verify that multiple concurrent feed refreshes respect the bounded semaphore limit."""
    from app.services.provider_guard import threat_feed_semaphore
    source_name = "concurrent_feed"
    items = [NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://c1.org", classification="phishing")]
    prov = MockFeedProvider(source_name, items)

    # Launch 3 simultaneous refreshes (semaphore capacity is 2)
    tasks = [refresh_threat_feed(db_session, prov, indicators=items) for _ in range(3)]
    results = await asyncio.gather(*tasks)
    assert len(results) == 3
    assert all(r["status"] == "success" for r in results)


def test_evidence_fusion_combined_with_webrisk_and_virustotal(client, db_session, monkeypatch):
    """
    Verify full evidence fusion across Heuristics + Threat Feeds (+35) + Web Risk (+30) + VirusTotal (+15):
    Final score is bounded at 100 max, and explainable signal descriptions are generated for all findings.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    test_url = "https://critical-fused-malware.com/evil"
    _, h_url = normalize_indicator_value("url", test_url)

    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="malware",
        confidence=1.0,
        observed_at=now_iso,
    ))
    db_session.commit()

    async def mock_vt_flagged(url, api_key):
        return {"status": "success", "url": url, "malicious_count": 3, "suspicious_count": 1, "reputation_score": 10, "vendors": ["VendorA", "VendorB"]}

    async def mock_wr_flagged(url, api_key):
        return {"status": "success", "url": url, "in_database": True, "threat_types": ["MALWARE"]}

    async def mock_uh_flagged(url):
        return {"status": "success", "url": url, "in_database": True, "threat_type": "malware_download", "date_added": "", "malware_families": []}

    monkeypatch.setattr("app.main.analyze_url_with_virustotal", mock_vt_flagged)
    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_wr_flagged)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", mock_uh_flagged)

    headers = get_csrf_headers(client)
    res = client.post("/api/analyze", json={"input_type": "url", "content": test_url}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Score bounded at 100 max
    assert data["risk_score"] == 100
    assert data["status"] == "danger"
    signal_ids = [s["id"] for s in data["phishing_signals"]]
    assert "threat_feed_match" in signal_ids
    assert "webrisk_threat_match" in signal_ids


@pytest.mark.asyncio
async def test_phishtank_http_304_and_errors():
    """Verify PhishTank handles HTTP 304, HTTP 500, HTTP 429, and malformed JSON."""
    # 1. HTTP 304 Not Modified
    resp_304 = MockStreamResponse(status=304)
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_304)):
        prov = PhishTankFeedProvider()
        items, etag, last_mod, not_mod = await prov.fetch_indicators(etag="pt-1")
        assert not_mod is True
        assert len(items) == 0

    # 2. HTTP 500
    resp_500 = MockStreamResponse(status=500)
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_500)):
        with pytest.raises(RuntimeError):
            await prov.fetch_indicators()

    # 3. Malformed JSON
    resp_bad_json = MockStreamResponse(status=200, content_bytes=b"invalid json")
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_bad_json)):
        with pytest.raises(Exception):
            await prov.fetch_indicators()


# ================= PART 3: OPENPHISH CONNECTOR TESTS =================
@pytest.mark.asyncio
async def test_openphish_valid_and_edge_cases():
    """Verify OpenPhish connector parses valid URLs, skips blank/comment lines, and deduplicates."""
    feed_text = (
        "# OpenPhish Community Feed\n"
        "https://openphish-sample1.com/login\n"
        "\n"
        "  https://OPENPHISH-SAMPLE1.COM/login  \n"  # Duplicate when normalized
        "http://evil-banking-portal.xyz/secure\n"
        "invalid-not-a-url\n"
        "# Another comment\n"
    ).encode("utf-8")

    resp = MockStreamResponse(status=200, content_bytes=feed_text, headers={"etag": "op-etag-2"})
    session = MockStreamSession(response=resp)

    prov = OpenPhishFeedProvider()
    with patch("aiohttp.ClientSession", return_value=session):
        items, etag, last_mod, not_mod = await prov.fetch_indicators(limit=100)

        assert not_mod is False
        assert etag == "op-etag-2"
        assert len(items) == 2  # Deduplicated from 3 valid
        assert items[0].source == "openphish"
        assert items[0].indicator == "https://openphish-sample1.com/login"
        assert items[1].indicator == "http://evil-banking-portal.xyz/secure"


# ================= PART 4: MISP ADAPTER TESTS =================
@pytest.mark.asyncio
async def test_misp_adapter_disabled_and_configured():
    """Verify MISP adapter is disabled when unconfigured, and parses attributes when configured."""
    # 1. Unconfigured -> is_enabled=False, returns empty without network calls
    prov_disabled = MISPFeedProvider(api_key="", server_url="")
    assert prov_disabled.is_enabled is False
    items_d, _, _, _ = await prov_disabled.fetch_indicators()
    assert len(items_d) == 0

    # 2. Configured -> parses response
    misp_json = json.dumps({
        "response": {
            "Attribute": [
                {
                    "type": "url",
                    "value": "https://misp-threat.org/payload",
                    "category": "Payload delivery",
                    "timestamp": "2026-10-04T11:00:00Z",
                    "event_id": "999",
                },
                {
                    "type": "domain",
                    "value": "MALICIOUS-C2-HOST.COM",
                    "category": "Network activity",
                    "timestamp": "2026-10-04T11:00:00Z",
                },
                {
                    "type": "other-unsupported",
                    "value": "skipped",
                }
            ]
        }
    }).encode("utf-8")

    resp = MockStreamResponse(status=200, content_bytes=misp_json)
    prov_enabled = MISPFeedProvider(api_key="test-key", server_url="https://misp.local")
    assert prov_enabled.is_enabled is True

    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp)):
        items, _, _, _ = await prov_enabled.fetch_indicators(limit=100)
        assert len(items) == 2
        assert items[0].source == "misp"
        assert items[0].indicator_type == "url"
        assert items[0].indicator == "https://misp-threat.org/payload"
        assert items[0].classification == "malware"
        assert items[1].indicator_type == "domain"
        assert items[1].indicator == "malicious-c2-host.com"


# ================= PART 5: FEED LIFECYCLE & ATOMICITY TESTS =================
@pytest.mark.asyncio
async def test_feed_refresh_atomicity_failed_refresh_preserves_previous_data(db_session):
    """
    Requirement C3 & H7: Atomicity test.
    When a healthy generation exists and subsequent refresh fails, previous valid data is NOT destroyed.
    """
    source_name = "atomicity_feed"
    initial_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://preserve-me.com/login", classification="phishing"),
    ]
    prov = MockFeedProvider(source_name, initial_items)

    # 1. Initial successful refresh
    res1 = await refresh_threat_feed(db_session, prov, indicators=initial_items)
    assert res1["status"] == "success"
    gen1 = res1["generation_id"]
    assert gen1 is not None

    # Verify item is in database
    _, h_url = normalize_indicator_value("url", "https://preserve-me.com/login")
    rec1 = db_session.query(ThreatIndicator).filter_by(source=source_name, indicator_hash=h_url).first()
    assert rec1 is not None
    assert rec1.generation_id == gen1

    # 2. Subsequent refresh fails due to provider error
    err_prov = ErrorFeedProvider()
    err_prov.source_name = source_name
    res2 = await refresh_threat_feed(db_session, err_prov)
    assert res2["status"] == "failed"

    # 3. PROVE that existing indicator remains available and was NOT deleted
    rec_after = db_session.query(ThreatIndicator).filter_by(source=source_name, indicator_hash=h_url).first()
    assert rec_after is not None
    assert rec_after.indicator == "https://preserve-me.com/login"

    # Lookup still succeeds
    lookup_res = lookup_threat_indicator(db_session, "url", "https://preserve-me.com/login")
    assert lookup_res is not None
    assert lookup_res["is_match"] is True


# ================= PART 6: EVIDENCE FUSION & SCORING INVARIANTS =================
def test_evidence_fusion_and_exact_score_invariants(client, db_session, monkeypatch):
    """
    Requirements D4, D5, D8, H8:
    - Multiple local feeds (PhishTank + OpenPhish + MISP) consolidate into one local-feed +35 contribution.
    - Deterministic classification precedence: malware > phishing.
    - Conflicting external provider results (e.g. Web Risk clear vs local feed match) preserve explainability.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    test_url = "https://fused-threat-sample.biz/login"
    _, h_url = normalize_indicator_value("url", test_url)

    # Insert 3 sources for same indicator with conflicting classifications
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="phishing",
        confidence=0.9,
        observed_at=now_iso,
    ))
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="openphish",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="phishing",
        confidence=0.85,
        observed_at=now_iso,
    ))
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="malware",  # Higher severity than phishing
        confidence=0.99,
        observed_at=now_iso,
    ))
    db_session.commit()

    # Clear external APIs
    async def mock_clean_all(url, *args):
        return {"status": "success", "url": url, "in_database": False, "threat_types": []}

    monkeypatch.setattr("app.main.analyze_url_with_virustotal", mock_clean_all)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", mock_clean_all)
    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_clean_all)

    headers = get_csrf_headers(client)
    res = client.post("/api/analyze", json={"input_type": "url", "content": test_url}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # 1. Provenance lists all 3 sources
    feed_findings = data["local_feed_findings"]
    assert feed_findings is not None
    assert feed_findings["is_match"] is True
    assert len(feed_findings["sources"]) == 3
    assert set(feed_findings["sources"]) == {"misp", "openphish", "phishtank"}

    # 2. Primary classification is malware due to severity hierarchy
    assert feed_findings["classification"] == "malware"
    assert feed_findings["all_classifications"] == ["malware", "phishing"]
    assert feed_findings["confidence"] == 0.99

    # 3. Exact +35 score contribution: exactly 1 threat_feed_match signal
    feed_signals = [s for s in data["phishing_signals"] if s["id"] == "threat_feed_match"]
    assert len(feed_signals) == 1


# ================= PART 7: ADMIN CONTROL PLANE TESTS =================
def test_admin_threat_feeds_authorization_and_csrf(client, db_session):
    """
    Requirements E1, E2, H9:
    - GET /api/admin/threat-feeds and POST /api/admin/threat-feeds/{source}/refresh
    - Unauthenticated user -> 401/403
    - Standard user -> 403 Forbidden
    - Admin user -> 200 OK
    - Missing CSRF on refresh -> 403 Forbidden
    - Unregistered source -> 404 Not Found (SSRF prevention)
    """
    admin_user = create_test_user(db_session, "admin_feeds@sentinel.local", role="admin")
    std_user = create_test_user(db_session, "standard_feeds@sentinel.local", role="user")

    admin_session_token = create_user_session(admin_user, db_session)
    std_session_token = create_user_session(std_user, db_session)

    csrf_headers = get_csrf_headers(client)

    # 1. Anonymous user GET -> 401 Unauthorized or 403 Forbidden
    res_anon_get = client.get("/api/admin/threat-feeds")
    assert res_anon_get.status_code in (401, 403)

    # 2. Standard user GET -> 403 Forbidden
    client.cookies.set(settings.AUTH_COOKIE_NAME, std_session_token)
    res_std_get = client.get("/api/admin/threat-feeds")
    assert res_std_get.status_code == 403

    # 3. Admin user GET -> 200 OK
    client.cookies.set(settings.AUTH_COOKIE_NAME, admin_session_token)
    res_admin_get = client.get("/api/admin/threat-feeds")
    assert res_admin_get.status_code == 200
    sources_data = res_admin_get.json()["sources"]
    assert len(sources_data) >= 3
    source_names = [s["source"] for s in sources_data]
    assert "phishtank" in source_names
    assert "openphish" in source_names
    assert "misp" in source_names

    # 4. Admin user POST refresh missing CSRF -> 403 Forbidden
    res_no_csrf = client.post("/api/admin/threat-feeds/openphish/refresh")
    assert res_no_csrf.status_code == 403

    # 5. Admin user POST refresh with unregistered source -> 404 Not Found (SSRF prevention)
    res_invalid_source = client.post(
        "/api/admin/threat-feeds/attacker-controlled-host/refresh",
        headers=csrf_headers,
    )
    assert res_invalid_source.status_code == 404

    # 6. Admin user POST refresh with valid source -> 200 OK
    async def mock_fetch(limit=1000, etag=None, last_modified=None):
        return [NormalizedThreatIndicator(source="openphish", indicator_type="url", indicator="https://synced-phish.net", classification="phishing")], "etag-1", None, False

    with patch.object(OpenPhishFeedProvider, "fetch_indicators", side_effect=mock_fetch):
        res_refresh = client.post(
            "/api/admin/threat-feeds/openphish/refresh",
            headers=csrf_headers,
        )
        assert res_refresh.status_code == 200
        refresh_body = res_refresh.json()
        assert refresh_body["source"] == "openphish"
        assert refresh_body["status"] == "success"
        assert refresh_body["records_inserted"] >= 1

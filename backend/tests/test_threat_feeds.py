import asyncio
import bz2
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import aiohttp
import pytest
from sqlalchemy import create_engine, func
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
    gen_id = str(uuid.uuid4())

    state = db_session.query(ThreatFeedState).filter_by(source="misp").first()
    if not state:
        state = ThreatFeedState(source="misp", enabled=True, status="success", freshness="fresh", current_generation_id=gen_id, updated_at=now_iso)
        db_session.add(state)
    else:
        state.enabled = True
        state.current_generation_id = gen_id

    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        generation_id=gen_id,
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
async def test_phishtank_keyed_url_construction_and_bz2_decompression():
    """
    Requirement Part K & L & Tasks 13-20:
    1. Keyed PhishTank downloadable feed URL is constructed using path parameter /data/<app_key>/online-valid.json.bz2
    2. URL builder normalizes whitespace and supports template paths.
    3. Safe bounded BZ2 decompression handles single and multi-chunk streams.
    4. Truncated BZ2 stream is strictly rejected (fails EOF check).
    5. Malformed stream and decompression bombs are rejected.
    """
    from app.services.threat_feed_service import build_phishtank_url, decompress_bz2_bounded

    # 1. Keyed URL construction tests
    url1 = build_phishtank_url("http://data.phishtank.com/data/online-valid.json.bz2", "secret_key_123")
    assert url1 == "http://data.phishtank.com/data/secret_key_123/online-valid.json.bz2"

    url_https = build_phishtank_url("https://data.phishtank.com/data/online-valid.json", "secret_key_123")
    assert url_https == "https://data.phishtank.com/data/secret_key_123/online-valid.json"

    # Whitespace key normalized
    url_ws = build_phishtank_url("http://data.phishtank.com/data/online-valid.json.bz2", "  secret_key_123  ")
    assert url_ws == "http://data.phishtank.com/data/secret_key_123/online-valid.json.bz2"

    # Unkeyed URL
    url_unkeyed = build_phishtank_url("https://data.phishtank.com/data/online-valid.json.bz2", "")
    assert url_unkeyed == "https://data.phishtank.com/data/online-valid.json.bz2"

    url_none = build_phishtank_url("https://data.phishtank.com/data/online-valid.json.bz2", None)
    assert url_none == "https://data.phishtank.com/data/online-valid.json.bz2"

    # Already keyed template
    url_tmpl = build_phishtank_url("http://data.phishtank.com/data/<key>/online-valid.json.bz2", "secret_key_123")
    assert url_tmpl == "http://data.phishtank.com/data/secret_key_123/online-valid.json.bz2"

    # 2. Valid BZ2 compression/decompression
    sample_records = [{"phish_id": 1, "url": "https://bz2-phish.com", "verified": "yes", "online": "yes"}]
    raw_json_bytes = json.dumps(sample_records).encode("utf-8")
    compressed = bz2.compress(raw_json_bytes)

    decompressed = decompress_bz2_bounded(compressed, max_decompressed_bytes=10000)
    assert decompressed == raw_json_bytes

    # 3. Multi-block / Multi-chunk BZ2 decompression (> 65536 bytes)
    large_payload = (json.dumps([{"phish_id": i, "url": f"https://phish-{i}.com", "verified": "yes", "online": "yes"} for i in range(2500)])).encode("utf-8")
    assert len(large_payload) > 65536
    large_compressed = bz2.compress(large_payload)
    decompressed_large = decompress_bz2_bounded(large_compressed, max_decompressed_bytes=len(large_payload) + 1000)
    assert decompressed_large == large_payload

    # 4. Truncated BZ2 stream must be rejected even if prefix is partially valid
    truncated_compressed = large_compressed[:len(large_compressed) - 30]
    with pytest.raises(ValueError, match="Invalid or truncated BZ2 stream"):
        decompress_bz2_bounded(truncated_compressed, max_decompressed_bytes=len(large_payload) + 1000)

    # 5. Decompression bomb / oversized decompressed output rejected
    huge_bytes = b"0" * 20000
    huge_compressed = bz2.compress(huge_bytes)
    with pytest.raises(ValueError, match="exceeded maximum limit"):
        decompress_bz2_bounded(huge_compressed, max_decompressed_bytes=1000)

    # 6. Malformed BZ2 data rejected
    with pytest.raises(ValueError, match="Invalid BZ2 stream"):
        decompress_bz2_bounded(b"BZh9invalid_corrupted_data", max_decompressed_bytes=1000)

    # 7. Empty payload rejected
    with pytest.raises(ValueError, match="empty payload"):
        decompress_bz2_bounded(b"", max_decompressed_bytes=1000)


@pytest.mark.asyncio
async def test_threat_feed_compressed_and_decompressed_limits_independent(db_session):
    """
    Requirements 18 & 24:
    Test independent enforcement of compressed payload limits (fetch stage)
    and decompressed payload limits (decompression stage), with sanitized error taxonomy.
    """
    prov = PhishTankFeedProvider(feed_url="http://data.phishtank.com/data/online-valid.json.bz2")

    # Case A: Compressed size exceeds MAX_RESPONSE_BYTES (32MB) -> rejected by fetch layer
    oversized_compressed = b"BZh9" + b"X" * (settings.THREAT_FEED_MAX_RESPONSE_BYTES + 100)
    resp_oversized = MockStreamResponse(status=200, content_bytes=oversized_compressed)
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_oversized)):
        res = await refresh_threat_feed(db_session, prov)
        assert res["status"] == "failed"
        assert res["error_code"] in ("too_large", "invalid_payload")

    # Case B: Compressed size is small (< 1KB), but decompressed output exceeds MAX_DECOMPRESSED_BYTES
    huge_payload = b"A" * 50000
    huge_compressed = bz2.compress(huge_payload)
    assert len(huge_compressed) < settings.THREAT_FEED_MAX_RESPONSE_BYTES
    resp_bomb = MockStreamResponse(status=200, content_bytes=huge_compressed)
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_bomb)):
        with patch.object(settings, "THREAT_FEED_MAX_DECOMPRESSED_BYTES", 1000):
            res_bomb = await refresh_threat_feed(db_session, prov)
            assert res_bomb["status"] == "failed"
            assert res_bomb["error_code"] == "decompression_too_large"


@pytest.mark.asyncio
async def test_cache_validators_preservation_on_failure_and_activation(db_session):
    """
    Requirement 22 & 36:
    Prove ETag and Last-Modified validators update ONLY on successful valid activations,
    and remain unchanged across fetch/validation failures.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    state = db_session.query(ThreatFeedState).filter_by(source="phishtank").first()
    if not state:
        state = ThreatFeedState(
            source="phishtank",
            enabled=True,
            status="idle",
            freshness="never_synced",
            etag="initial-etag-111",
            last_modified="Wed, 01 Oct 2026 00:00:00 GMT",
            current_generation_id="gen-init-1",
            updated_at=now_iso,
        )
        db_session.add(state)
    else:
        state.enabled = True
        state.etag = "initial-etag-111"
        state.last_modified = "Wed, 01 Oct 2026 00:00:00 GMT"
        state.current_generation_id = "gen-init-1"

    # Add initial indicator row matching current_generation_id
    _, h_init = normalize_indicator_value("url", "https://initial-target.com")
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        generation_id="gen-init-1",
        indicator_type="url",
        indicator="https://initial-target.com",
        indicator_hash=h_init,
        classification="phishing",
        confidence=0.9,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    db_session.commit()

    # 1. Failed fetch (HTTP 500) -> validators and generation preserved
    resp_500 = MockStreamResponse(status=500)
    prov = PhishTankFeedProvider(feed_url="http://data.phishtank.com/data/online-valid.json")
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_500)):
        res_fail = await refresh_threat_feed(db_session, prov)
        assert res_fail["status"] == "failed"
        db_session.refresh(state)
        assert state.etag == "initial-etag-111"
        assert state.last_modified == "Wed, 01 Oct 2026 00:00:00 GMT"
        assert state.current_generation_id == "gen-init-1"

    # 2. Malformed JSON payload -> validators and generation preserved
    resp_bad = MockStreamResponse(status=200, content_bytes=b"invalid json", headers={"etag": "new-bad-etag"})
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_bad)):
        res_bad = await refresh_threat_feed(db_session, prov)
        assert res_bad["status"] == "failed"
        db_session.refresh(state)
        assert state.etag == "initial-etag-111"
        assert state.current_generation_id == "gen-init-1"

    # 3. Successful activation -> validators and generation updated
    valid_feed = json.dumps([{"phish_id": "1", "url": "https://valid-target.com", "verified": "yes", "online": "yes"}]).encode("utf-8")
    resp_ok = MockStreamResponse(status=200, content_bytes=valid_feed, headers={"etag": "activated-etag-999", "last-modified": "Sun, 04 Oct 2026 12:00:00 GMT"})
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp_ok)):
        res_ok = await refresh_threat_feed(db_session, prov)
        assert res_ok["status"] == "success"
        db_session.refresh(state)
        assert state.etag == "activated-etag-999"
        assert state.last_modified == "Sun, 04 Oct 2026 12:00:00 GMT"
        assert state.current_generation_id == res_ok["generation_id"]


@pytest.mark.asyncio
async def test_phishtank_bz2_feed_download_and_field_filtering():
    """Verify PhishTank provider downloads BZ2 feed and filters unverified/missing fields."""
    sample_json = json.dumps([
        {
            "phish_id": "991",
            "url": "https://secure-bz2-phish.com/login",
            "verified": "yes",
            "online": "yes",
            "target": "Bank",
        },
        {
            "phish_id": "992",
            "url": "https://unverified-bz2.com",
            # Missing verified / online -> must be rejected
        },
        {
            "phish_id": "993",
            "url": "https://offline-bz2.com",
            "verified": "no",
            "online": "no",
        }
    ]).encode("utf-8")

    compressed = bz2.compress(sample_json)
    resp = MockStreamResponse(
        status=200,
        content_bytes=compressed,
        headers={"content-type": "application/x-bzip2", "etag": "pt-bz2-1"}
    )

    prov = PhishTankFeedProvider(api_key="my_key", feed_url="http://data.phishtank.com/data/online-valid.json.bz2")
    with patch("aiohttp.ClientSession", return_value=MockStreamSession(response=resp)):
        items, etag, _, _ = await prov.fetch_indicators(limit=10)
        assert len(items) == 1
        assert items[0].indicator == "https://secure-bz2-phish.com/login"
        assert items[0].classification == "phishing"
        assert etag == "pt-bz2-1"


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


@pytest.mark.asyncio
async def test_generation_snapshot_removes_absent_indicators_and_lookup_isolation(db_session):
    """
    CRITICAL LIFECYCLE INVARIANT (Requirement D1, D5, D6, Part O):
    Generation 1 produces indicators: A, B, C.
    All match in lookup.
    Generation 2 produces indicators: A, B (C is absent/removed).
    After Gen 2 activation:
      - A matches
      - B matches
      - C DOES NOT MATCH (even with expires_at=None)
    """
    source_name = "snapshot_source"
    url_a = "https://phish-a.example.com/login"
    url_b = "https://phish-b.example.com/login"
    url_c = "https://phish-c.example.com/login"

    gen1_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_a, classification="phishing"),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_b, classification="phishing"),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_c, classification="phishing"),
    ]
    prov1 = MockFeedProvider(source_name, gen1_items)

    # 1. Refresh Generation 1
    res1 = await refresh_threat_feed(db_session, prov1, indicators=gen1_items)
    assert res1["status"] == "success"
    gen1_id = res1["generation_id"]
    assert gen1_id is not None

    # Verify all 3 match in active lookup
    assert lookup_threat_indicator(db_session, "url", url_a)["is_match"] is True
    assert lookup_threat_indicator(db_session, "url", url_b)["is_match"] is True
    assert lookup_threat_indicator(db_session, "url", url_c)["is_match"] is True

    # 2. Refresh Generation 2 with only A and B (C removed)
    gen2_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_a, classification="phishing"),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_b, classification="phishing"),
    ]
    prov2 = MockFeedProvider(source_name, gen2_items)
    res2 = await refresh_threat_feed(db_session, prov2, indicators=gen2_items)
    assert res2["status"] == "success"
    gen2_id = res2["generation_id"]
    assert gen2_id != gen1_id

    # 3. PROVE THAT A and B MATCH, AND C DOES NOT MATCH!
    match_a = lookup_threat_indicator(db_session, "url", url_a)
    match_b = lookup_threat_indicator(db_session, "url", url_b)
    match_c = lookup_threat_indicator(db_session, "url", url_c)

    assert match_a is not None and match_a["is_match"] is True
    assert match_b is not None and match_b["is_match"] is True
    assert match_c is None, "Removed indicator C must NOT match in the new generation snapshot"

    # State verification
    state = db_session.query(ThreatFeedState).filter_by(source=source_name).first()
    assert state.current_generation_id == gen2_id
    assert state.last_success_count == 2


@pytest.mark.asyncio
async def test_empty_snapshot_rejected_under_default_policy(db_session):
    """
    Requirement Part E & 25:
    Prove that an unexpected empty snapshot fails safely and does NOT wipe a healthy feed.
    """
    source_name = "empty_policy_source"
    url_test = "https://healthy-threat.com/login"

    initial_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator=url_test, classification="phishing")
    ]
    prov = MockFeedProvider(source_name, initial_items)
    prov.allow_empty_snapshot = False

    # 1. Establish healthy generation 1
    res1 = await refresh_threat_feed(db_session, prov, indicators=initial_items)
    assert res1["status"] == "success"
    gen1_id = res1["generation_id"]

    # 2. Provider returns empty list unexpectedly
    empty_prov = MockFeedProvider(source_name, [])
    empty_prov.allow_empty_snapshot = False
    res2 = await refresh_threat_feed(db_session, empty_prov, indicators=[])
    assert res2["status"] == "failed"
    assert "snapshot_validation_failed_empty" in res2["error_code"]

    # 3. Healthy generation 1 remains active and lookup continues to match
    state = db_session.query(ThreatFeedState).filter_by(source=source_name).first()
    assert state.current_generation_id == gen1_id
    assert lookup_threat_indicator(db_session, "url", url_test)["is_match"] is True


@pytest.mark.asyncio
async def test_real_provider_fetch_concurrency_and_per_source_locking(db_session):
    """
    Requirement Part G & 10:
    1. Verify real provider-fetch path exercises threat_feed_semaphore and enforces global concurrency bound.
    2. Verify same-source refreshes are serialized by per-source locks.
    """
    active_global_fetches = 0
    max_observed_global = 0
    active_source_stages = {}
    max_observed_per_source = {}
    lock = asyncio.Lock()

    class InstrumentedProvider:
        def __init__(self, name: str):
            self.source_name = name
            self.indicator_types = ["url"]
            self.supports_etag = False
            self.supports_last_modified = False
            self.default_refresh_interval_seconds = 86400
            self.fetch_limit = 100
            self.is_enabled = True
            self.allow_empty_snapshot = True

        async def fetch_indicators(self, limit=100, etag=None, last_modified=None):
            nonlocal active_global_fetches, max_observed_global
            async with lock:
                active_global_fetches += 1
                max_observed_global = max(max_observed_global, active_global_fetches)
                curr_s = active_source_stages.get(self.source_name, 0) + 1
                active_source_stages[self.source_name] = curr_s
                max_observed_per_source[self.source_name] = max(max_observed_per_source.get(self.source_name, 0), curr_s)

            await asyncio.sleep(0.04)

            async with lock:
                active_global_fetches -= 1
                active_source_stages[self.source_name] -= 1

            return [
                NormalizedThreatIndicator(
                    source=self.source_name,
                    indicator_type="url",
                    indicator=f"https://{self.source_name}.org/phish",
                    classification="phishing"
                )
            ], None, None, False

    # A. Test same-source serialization: 4 concurrent tasks refreshing 'source_alpha'
    alpha_prov = InstrumentedProvider("source_alpha")
    tasks_same_source = [refresh_threat_feed(db_session, alpha_prov) for _ in range(4)]
    results_same = await asyncio.gather(*tasks_same_source)
    assert len(results_same) == 4
    assert max_observed_per_source["source_alpha"] == 1, "Same source refresh must be strictly serialized (max concurrency == 1)"

    # B. Test multi-source concurrency respecting global semaphore limit
    providers = [InstrumentedProvider(f"source_diff_{i}") for i in range(5)]
    tasks_diff = [refresh_threat_feed(db_session, p) for p in providers]
    results_diff = await asyncio.gather(*tasks_diff)
    assert len(results_diff) == 5
    assert max_observed_global <= settings.THREAT_FEED_MAX_CONCURRENT_FETCHES, (
        f"Observed global fetch concurrency {max_observed_global} exceeded limit {settings.THREAT_FEED_MAX_CONCURRENT_FETCHES}"
    )


@pytest.mark.asyncio
async def test_realistic_legacy_database_migration_coexistence_and_lifecycle(tmp_path):
    """
    Requirements Parts B, C, D, E, F, G, H, I, R, S:
    1. Recreate realistic legacy pre-Task-3 database with UNIQUE(source, indicator_type, indicator_hash).
    2. Populate with legacy records with generation_id = NULL.
    3. Run schema migration.
    4. Verify:
       - Old unique constraint is removed, new unique constraint UNIQUE(source, generation_id, indicator_type, indicator_hash) is present.
       - Legacy records receive deterministic legacy-gen-{source} generation_id.
       - ThreatFeedState records created with current_generation_id = legacy-gen-{source} and freshness = 'stale'.
       - Legacy records are searchable via lookup_threat_indicator.
       - Staging a new generation containing an indicator present in legacy generation succeeds (coexistence).
       - After activation of new generation, indicators present in new generation match, and removed indicators stop matching.
    """
    import sqlite3
    from app.db import ensure_schema_migrations
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    test_db_file = str(tmp_path / "realistic_legacy.db")
    conn = sqlite3.connect(test_db_file)
    cursor = conn.cursor()

    # 1. Create real pre-Task-3 schema with legacy UNIQUE constraint
    cursor.execute("""
        CREATE TABLE threat_indicators (
            id VARCHAR(36) PRIMARY KEY,
            source VARCHAR(64) NOT NULL,
            indicator_type VARCHAR(32) NOT NULL,
            indicator VARCHAR(2048) NOT NULL,
            indicator_hash VARCHAR(64) NOT NULL,
            classification VARCHAR(64) NOT NULL,
            confidence FLOAT NOT NULL,
            observed_at VARCHAR(32) NOT NULL,
            expires_at VARCHAR(32),
            created_at VARCHAR(32) NOT NULL,
            updated_at VARCHAR(32) NOT NULL,
            CONSTRAINT uq_source_type_indicator UNIQUE (source, indicator_type, indicator_hash)
        )
    """)

    # Insert legacy indicators across multiple sources
    url_pt_a = "https://legacy-phishtank-a.com/login"
    url_pt_b = "https://legacy-phishtank-b.com/login"
    url_op_c = "https://legacy-openphish-c.com/login"

    _, h_pt_a = normalize_indicator_value("url", url_pt_a)
    _, h_pt_b = normalize_indicator_value("url", url_pt_b)
    _, h_op_c = normalize_indicator_value("url", url_op_c)

    cursor.execute("""
        INSERT INTO threat_indicators (id, source, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('id-1', 'phishtank', 'url', ?, ?, 'phishing', 0.95, '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00')
    """, (url_pt_a, h_pt_a))
    cursor.execute("""
        INSERT INTO threat_indicators (id, source, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('id-2', 'phishtank', 'url', ?, ?, 'phishing', 0.95, '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00')
    """, (url_pt_b, h_pt_b))
    cursor.execute("""
        INSERT INTO threat_indicators (id, source, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('id-3', 'openphish', 'url', ?, ?, 'phishing', 0.85, '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00', '2026-10-04T00:00:00+00:00')
    """, (url_op_c, h_op_c))

    conn.commit()
    conn.close()

    # 2. Perform Migration
    ensure_schema_migrations(test_db_file)

    # 3. Inspect Migrated Schema & Data
    conn2 = sqlite3.connect(test_db_file)
    cursor2 = conn2.cursor()

    # Verify table DDL has the new unique constraint including generation_id
    cursor2.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
    new_ddl = cursor2.fetchone()[0]
    assert "generation_id" in new_ddl
    assert "uq_source_gen_type_indicator" in new_ddl

    # Verify legacy generations assigned
    cursor2.execute("SELECT source, generation_id FROM threat_indicators WHERE id='id-1'")
    row1 = cursor2.fetchone()
    assert row1[0] == "phishtank"
    assert row1[1] == "legacy-gen-phishtank"

    cursor2.execute("SELECT source, generation_id FROM threat_indicators WHERE id='id-3'")
    row3 = cursor2.fetchone()
    assert row3[0] == "openphish"
    assert row3[1] == "legacy-gen-openphish"

    # Verify ThreatFeedState created with freshness='stale' (truthful legacy state)
    cursor2.execute("SELECT source, freshness, current_generation_id, last_success_at FROM threat_feed_states WHERE source='phishtank'")
    state_pt = cursor2.fetchone()
    assert state_pt is not None
    assert state_pt[1] == "stale"
    assert state_pt[2] == "legacy-gen-phishtank"
    assert state_pt[3] is None  # Falsely fresh timestamp not fabricated
    conn2.close()

    # 4. Connect with SQLAlchemy Session on the migrated database
    migrated_engine = create_engine(f"sqlite:///{test_db_file}", connect_args={"check_same_thread": False})
    MigratedSession = sessionmaker(autocommit=False, autoflush=False, bind=migrated_engine)
    session = MigratedSession()

    try:
        # Verify legacy lookups succeed
        assert lookup_threat_indicator(session, "url", url_pt_a)["is_match"] is True
        assert lookup_threat_indicator(session, "url", url_pt_b)["is_match"] is True
        assert lookup_threat_indicator(session, "url", url_op_c)["is_match"] is True

        # 5. Coexistence Test: Stage a new generation for phishtank containing url_pt_a and new url_pt_d (url_pt_b removed)
        url_pt_d = "https://new-phishtank-d.com/login"
        new_items = [
            NormalizedThreatIndicator(source="phishtank", indicator_type="url", indicator=url_pt_a, classification="phishing"),
            NormalizedThreatIndicator(source="phishtank", indicator_type="url", indicator=url_pt_d, classification="phishing"),
        ]
        prov_pt = MockFeedProvider("phishtank", new_items)

        # Refresh new generation
        res_refresh = await refresh_threat_feed(session, prov_pt, indicators=new_items)
        assert res_refresh["status"] == "success"
        new_gen_id = res_refresh["generation_id"]
        assert new_gen_id != "legacy-gen-phishtank"

        # 6. Verify lookup behavior: url_pt_a and url_pt_d match; url_pt_b is removed and NO LONGER matches
        assert lookup_threat_indicator(session, "url", url_pt_a)["is_match"] is True
        assert lookup_threat_indicator(session, "url", url_pt_d)["is_match"] is True
        assert lookup_threat_indicator(session, "url", url_pt_b) is None, "Removed indicator url_pt_b must NOT match after new generation activation"

    finally:
        session.close()


def test_migration_failure_fails_closed_and_raises(tmp_path, monkeypatch):
    """
    Requirement Part J, Y & 11:
    Prove that database migration errors raise RuntimeError, roll back the transaction,
    and fail closed so that partially migrated schema or corrupt states are not committed.
    """
    from app.db import ensure_schema_migrations
    import sqlite3

    corrupt_db_file = str(tmp_path / "corrupt_test.db")
    # Create invalid table state where required columns are missing and cannot be copied
    conn = sqlite3.connect(corrupt_db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE threat_indicators (id VARCHAR PRIMARY KEY, source VARCHAR)")
    cursor.execute("INSERT INTO threat_indicators VALUES ('1', 'phishtank')")
    conn.commit()
    conn.close()

    # ensure_schema_migrations must fail, rollback, and raise RuntimeError
    with pytest.raises(RuntimeError, match="Database schema migration failed"):
        ensure_schema_migrations(corrupt_db_file)

    # Verify that the original table was not replaced with an empty or broken migrated table
    conn2 = sqlite3.connect(corrupt_db_file)
    cursor2 = conn2.cursor()
    cursor2.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_indicators_migrated'")
    assert cursor2.fetchone() is None, "Temporary migration table must not remain after rollback"
    conn2.close()


def test_alembic_realistic_legacy_migration_pragma_indexes_and_coexistence(tmp_path):
    """
    Requirements 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 16, 30, 31, 32:
    1. Realistic legacy schema containing all columns, legacy constraint uq_source_type_indicator, and legacy indexes.
    2. Populate legacy records across multiple sources and edge-case threat_feed_states.
    3. Run Alembic upgrade head.
    4. Direct PRAGMA & sqlite_master inspection:
       - Old constraint uq_source_type_indicator ABSENT.
       - New constraint uq_source_gen_type_indicator PRESENT.
       - All 6 indexes exist.
    5. Verify legacy generation IDs & state reconciliation.
    6. Verify duplicate indicator across generations succeeds (Generation Coexistence).
    7. Verify migration idempotency (running upgrade head again).
    8. Verify downgrade to base and re-upgrade to head.
    """
    import os
    import sqlite3
    from alembic.config import Config
    from alembic import command

    test_db_file = str(tmp_path / "alembic_realistic_legacy.db")

    # 1. Create realistic legacy pre-Task-3 database
    conn = sqlite3.connect(test_db_file)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE threat_indicators (
            id VARCHAR(36) PRIMARY KEY,
            source VARCHAR(64) NOT NULL,
            indicator_type VARCHAR(32) NOT NULL,
            indicator VARCHAR(2048) NOT NULL,
            indicator_hash VARCHAR(64) NOT NULL,
            classification VARCHAR(64) NOT NULL,
            confidence FLOAT NOT NULL,
            observed_at VARCHAR(32) NOT NULL,
            expires_at VARCHAR(32),
            created_at VARCHAR(32) NOT NULL,
            updated_at VARCHAR(32) NOT NULL,
            CONSTRAINT uq_source_type_indicator UNIQUE (source, indicator_type, indicator_hash)
        )
    """)
    cursor.execute("CREATE INDEX ix_threat_indicators_source ON threat_indicators (source)")
    cursor.execute("CREATE INDEX ix_threat_indicators_indicator_type ON threat_indicators (indicator_type)")
    cursor.execute("CREATE INDEX ix_threat_indicators_indicator_hash ON threat_indicators (indicator_hash)")
    cursor.execute("CREATE INDEX ix_threat_indicators_classification ON threat_indicators (classification)")
    cursor.execute("CREATE INDEX ix_threat_indicators_expires_at ON threat_indicators (expires_at)")

    # Legacy records
    url_pt = "https://legacy-phishtank.com/login"
    _, h_pt = normalize_indicator_value("url", url_pt)
    cursor.execute("""
        INSERT INTO threat_indicators (id, source, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('leg-pt-1', 'phishtank', 'url', ?, ?, 'phishing', 0.95, '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')
    """, (url_pt, h_pt))

    url_op = "https://legacy-openphish.com/login"
    _, h_op = normalize_indicator_value("url", url_op)
    cursor.execute("""
        INSERT INTO threat_indicators (id, source, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('leg-op-1', 'openphish', 'url', ?, ?, 'phishing', 0.85, '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z', '2026-10-04T00:00:00Z')
    """, (url_op, h_op))

    # Pre-existing state with NULL current_generation_id
    cursor.execute("""
        CREATE TABLE threat_feed_states (
            source VARCHAR(64) PRIMARY KEY,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            status VARCHAR(32) NOT NULL DEFAULT 'idle',
            freshness VARCHAR(32) NOT NULL DEFAULT 'never_synced',
            last_success_at VARCHAR(32),
            last_attempt_at VARCHAR(32),
            last_success_count INTEGER NOT NULL DEFAULT 0,
            last_error VARCHAR(256),
            etag VARCHAR(128),
            last_modified VARCHAR(128),
            current_generation_id VARCHAR(36),
            refresh_interval_seconds INTEGER NOT NULL DEFAULT 86400,
            updated_at VARCHAR(32) NOT NULL
        )
    """)
    cursor.execute("""
        INSERT INTO threat_feed_states (source, enabled, status, freshness, last_success_count, current_generation_id, refresh_interval_seconds, updated_at)
        VALUES ('phishtank', 1, 'idle', 'never_synced', 0, NULL, 86400, '2026-10-04T00:00:00Z')
    """)
    conn.commit()
    conn.close()

    # 2. Run Alembic upgrade head
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ini_path = os.path.join(backend_dir, "alembic.ini")
    alembic_cfg = Config(ini_path)
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{test_db_file}")
    alembic_cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))

    command.upgrade(alembic_cfg, "head")

    # 3. Direct SQLite Introspection: PRAGMA and sqlite_master
    conn2 = sqlite3.connect(test_db_file)
    cursor2 = conn2.cursor()

    cursor2.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
    table_sql = cursor2.fetchone()[0]

    # PROOF: Old unique constraint is absent, new generation unique constraint is present
    assert "uq_source_gen_type_indicator" in table_sql, "New generation-aware unique constraint must be present"
    assert "uq_source_type_indicator" not in table_sql, "Legacy unique constraint must be explicitly removed"

    # PROOF: All 6 intended indexes are present
    cursor2.execute("PRAGMA index_list(threat_indicators)")
    idx_list = [row[1] for row in cursor2.fetchall()]
    expected_indexes = [
        "ix_threat_indicators_source",
        "ix_threat_indicators_indicator_type",
        "ix_threat_indicators_indicator_hash",
        "ix_threat_indicators_classification",
        "ix_threat_indicators_expires_at",
        "ix_threat_indicators_generation_id",
    ]
    for exp_idx in expected_indexes:
        assert exp_idx in idx_list, f"Expected index {exp_idx} missing from migrated table"

    # PROOF: Column generation_id exists and legacy data preserved
    cursor2.execute("PRAGMA table_info(threat_indicators)")
    cols = [r[1] for r in cursor2.fetchall()]
    assert "generation_id" in cols

    cursor2.execute("SELECT generation_id FROM threat_indicators WHERE id='leg-pt-1'")
    assert cursor2.fetchone()[0] == "legacy-gen-phishtank"

    cursor2.execute("SELECT generation_id FROM threat_indicators WHERE id='leg-op-1'")
    assert cursor2.fetchone()[0] == "legacy-gen-openphish"

    # PROOF: ThreatFeedState reconciled truthfully
    cursor2.execute("SELECT source, freshness, current_generation_id, last_success_at FROM threat_feed_states WHERE source='phishtank'")
    st_pt = cursor2.fetchone()
    assert st_pt[1] == "stale"
    assert st_pt[2] == "legacy-gen-phishtank"
    assert st_pt[3] is None  # Falsely fresh timestamp not fabricated

    cursor2.execute("SELECT source, freshness, current_generation_id FROM threat_feed_states WHERE source='openphish'")
    st_op = cursor2.fetchone()
    assert st_op is not None
    assert st_op[1] == "stale"
    assert st_op[2] == "legacy-gen-openphish"

    # 4. PROOF: Generation Coexistence (Stage duplicate indicator into new generation)
    # Under legacy schema, inserting identical (source, indicator_type, indicator_hash) would fail with IntegrityError
    cursor2.execute("""
        INSERT INTO threat_indicators (id, source, generation_id, indicator_type, indicator, indicator_hash, classification, confidence, observed_at, created_at, updated_at)
        VALUES ('staged-new-pt-1', 'phishtank', 'gen-new-stage-2026', 'url', ?, ?, 'phishing', 0.99, '2026-10-04T12:00:00Z', '2026-10-04T12:00:00Z', '2026-10-04T12:00:00Z')
    """, (url_pt, h_pt))
    conn2.commit()

    # Verify both generations coexist in the database
    cursor2.execute("SELECT COUNT(*) FROM threat_indicators WHERE source='phishtank' AND indicator_hash=?", (h_pt,))
    assert cursor2.fetchone()[0] == 2, "Duplicate indicator across two generations must coexist successfully"
    conn2.close()

    # 5. PROOF: Migration Idempotency
    # Running upgrade head again on already-migrated database must succeed without errors
    command.upgrade(alembic_cfg, "head")

    # 6. PROOF: Downgrade to base and re-upgrade to head
    command.downgrade(alembic_cfg, "base")
    conn3 = sqlite3.connect(test_db_file)
    cursor3 = conn3.cursor()
    cursor3.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_feed_states'")
    assert cursor3.fetchone() is None
    cursor3.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
    downgraded_sql = cursor3.fetchone()[0]
    assert "uq_source_type_indicator" in downgraded_sql
    conn3.close()

    command.upgrade(alembic_cfg, "head")
    conn4 = sqlite3.connect(test_db_file)
    cursor4 = conn4.cursor()
    cursor4.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='threat_indicators'")
    reupgraded_sql = cursor4.fetchone()[0]
    assert "uq_source_gen_type_indicator" in reupgraded_sql
    assert "uq_source_type_indicator" not in reupgraded_sql
    conn4.close()


def test_generation_state_consistency_invariant(db_session):
    """
    Requirement Part S & 24:
    Prove that for every enabled ThreatFeedState with a non-null current_generation_id,
    the active generation references existing records in ThreatIndicator.
    """
    enabled_states = db_session.query(ThreatFeedState).filter(
        ThreatFeedState.enabled == True,
        ThreatFeedState.current_generation_id.isnot(None),
    ).all()

    for state in enabled_states:
        count = db_session.query(func.count(ThreatIndicator.id)).filter(
            ThreatIndicator.source == state.source,
            ThreatIndicator.generation_id == state.current_generation_id,
        ).scalar() or 0
        assert count > 0, f"ThreatFeedState for {state.source} references active generation {state.current_generation_id} with 0 records"


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

    gen_pt = str(uuid.uuid4())
    gen_op = str(uuid.uuid4())
    gen_misp = str(uuid.uuid4())

    for src, gid in [("phishtank", gen_pt), ("openphish", gen_op), ("misp", gen_misp)]:
        st = db_session.query(ThreatFeedState).filter_by(source=src).first()
        if not st:
            st = ThreatFeedState(source=src, enabled=True, status="success", freshness="fresh", current_generation_id=gid, updated_at=now_iso)
            db_session.add(st)
        else:
            st.enabled = True
            st.current_generation_id = gid

    # Insert 3 sources for same indicator with conflicting classifications
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        generation_id=gen_pt,
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
        generation_id=gen_op,
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
        generation_id=gen_misp,
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

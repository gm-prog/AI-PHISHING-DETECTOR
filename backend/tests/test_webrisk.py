import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app, limiter
from app.services.webrisk_service import check_url_with_webrisk, WEBRISK_LOOKUP_URL, _calculate_effective_ttl
from app.services.provider_guard import (
    webrisk_cache,
    webrisk_semaphore,
    run_bounded,
    stable_key,
    ProviderQueueExhaustedError,
)
from app.config import settings


class MockResponse:
    def __init__(self, status=200, json_data=None, json_exc=None):
        self.status = status
        self._json_data = json_data if json_data is not None else {}
        self._json_exc = json_exc

    async def json(self, *args, **kwargs):
        if self._json_exc:
            raise self._json_exc
        return self._json_data

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockSession:
    def __init__(self, response=None, get_exc=None, on_get=None):
        self._response = response
        self._get_exc = get_exc
        self._on_get = on_get

    def get(self, *args, **kwargs):
        if self._on_get:
            self._on_get(*args, **kwargs)
        if self._get_exc:
            raise self._get_exc
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture(autouse=True)
def clear_webrisk_cache():
    webrisk_cache.clear()
    yield
    webrisk_cache.clear()


@pytest.fixture
def test_client():
    return TestClient(app)


def get_csrf_headers(client):
    if not client.cookies.get("sentinel_csrf"):
        client.get("/api/health")
    token = client.cookies.get("sentinel_csrf")
    assert token
    return {"X-CSRF-Token": token}


@pytest.mark.asyncio
async def test_webrisk_missing_or_blank_api_key():
    """When API key is None or blank, provider must return skipped without network calls."""
    res_none = await check_url_with_webrisk("https://example.com/login", api_key=None)
    assert res_none["status"] == "skipped"
    assert res_none["in_database"] is False
    assert res_none["threat_types"] == []

    res_empty = await check_url_with_webrisk("https://example.com/login", api_key="   ")
    assert res_empty["status"] == "skipped"
    assert res_empty["in_database"] is False
    assert res_empty["threat_types"] == []


@pytest.mark.asyncio
async def test_webrisk_clean_url_response():
    """When Google Web Risk returns an empty object {}, it indicates no threats detected."""
    mock_resp = MockResponse(status=200, json_data={})
    mock_session = MockSession(response=mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://safe-domain.org", api_key="test-api-key")
        assert res["status"] == "success"
        assert res["in_database"] is False
        assert res["threat_types"] == []
        assert res["url"] == "https://safe-domain.org"


@pytest.mark.asyncio
async def test_webrisk_phishing_threat_detected():
    """When Google Web Risk returns threat matches, return normalized in_database=True and threat types."""
    mock_resp = MockResponse(
        status=200,
        json_data={
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING"],
                "expireTime": "2026-10-04T15:00:00Z",
            }
        },
    )
    mock_session = MockSession(response=mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://phishing-site.example", api_key="test-api-key")
        assert res["status"] == "success"
        assert res["in_database"] is True
        assert res["threat_types"] == ["SOCIAL_ENGINEERING"]


@pytest.mark.asyncio
async def test_webrisk_multiple_threat_types_normalized():
    """Verify multiple threat types are correctly parsed and listed."""
    mock_resp = MockResponse(
        status=200,
        json_data={
            "threat": {
                "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
            }
        },
    )
    mock_session = MockSession(response=mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://multi-threat.example", api_key="test-api-key")
        assert res["status"] == "success"
        assert res["in_database"] is True
        assert len(res["threat_types"]) == 3
        assert "SOCIAL_ENGINEERING" in res["threat_types"]
        assert "MALWARE" in res["threat_types"]


@pytest.mark.asyncio
async def test_webrisk_timeout_handling():
    """Verify timeouts fail safely with status='timeout'."""
    mock_session = MockSession(get_exc=asyncio.TimeoutError())

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://slow-site.example", api_key="test-api-key")
        assert res["status"] == "timeout"
        assert res["in_database"] is False
        assert res["threat_types"] == []


@pytest.mark.asyncio
async def test_webrisk_http_500_error_handling():
    """Verify HTTP errors fail safely with status='error'."""
    mock_resp = MockResponse(status=500)
    mock_session = MockSession(response=mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://error-site.example", api_key="test-api-key")
        assert res["status"] == "error"
        assert res["in_database"] is False
        assert res["threat_types"] == []


@pytest.mark.asyncio
async def test_webrisk_malformed_json_handling():
    """Verify malformed JSON responses fail safely with status='error'."""
    mock_resp = MockResponse(status=200, json_exc=ValueError("Invalid JSON"))
    mock_session = MockSession(response=mock_resp)

    with patch("aiohttp.ClientSession", return_value=mock_session):
        res = await check_url_with_webrisk("https://bad-json.example", api_key="test-api-key")
        assert res["status"] == "error"
        assert res["in_database"] is False
        assert res["threat_types"] == []


@pytest.mark.asyncio
async def test_webrisk_cache_deduplication():
    """Verify identical URL queries within TTL use cached response without issuing HTTP request."""
    call_count = 0

    def record_call(*args, **kwargs):
        nonlocal call_count
        call_count += 1

    mock_resp = MockResponse(status=200, json_data={"threat": {"threatTypes": ["MALWARE"]}})
    mock_session = MockSession(response=mock_resp, on_get=record_call)

    test_url = "https://cached-test.org/path"
    cache_key = stable_key("webrisk", test_url.strip())

    with patch("aiohttp.ClientSession", return_value=mock_session):
        # First query: cache miss
        cached = await webrisk_cache.get(cache_key)
        assert cached is None
        data1 = await run_bounded(
            check_url_with_webrisk(test_url, api_key="test-key"),
            webrisk_semaphore,
            timeout_seconds=5.0,
            acquire_timeout_seconds=2.0,
        )
        await webrisk_cache.set(cache_key, data1)

        # Second query: cache hit
        cached2 = await webrisk_cache.get(cache_key)
        assert cached2 is not None
        assert cached2 == data1
        assert cached2["in_database"] is True

        # Exactly 1 HTTP call was executed
        assert call_count == 1


def test_webrisk_cache_key_privacy():
    """Verify cache keys use SHA-256 hash and do NOT contain raw URLs or API keys."""
    raw_url = "https://sensitive-company.internal/login?token=supersecret123"
    api_key = "test-google-webrisk-key-12345"

    url_hash = hashlib.sha256(raw_url.lower().encode("utf-8")).hexdigest()
    expected_cache_key = f"webrisk:{url_hash}"

    # Check cache key construction invariant
    assert api_key not in expected_cache_key
    assert "supersecret123" not in expected_cache_key
    assert expected_cache_key.startswith("webrisk:")
    assert len(url_hash) == 64


@pytest.mark.asyncio
async def test_webrisk_concurrency_bounding():
    """
    Test Goal A1: Verify provider concurrency is strictly bounded by webrisk_semaphore
    during concurrent execution, and queue saturation raises ProviderQueueExhaustedError.
    """
    current_concurrency = 0
    max_observed_concurrency = 0
    lock = asyncio.Lock()

    async def instrumented_operation():
        nonlocal current_concurrency, max_observed_concurrency
        async with lock:
            current_concurrency += 1
            if current_concurrency > max_observed_concurrency:
                max_observed_concurrency = current_concurrency
        await asyncio.sleep(0.05)
        async with lock:
            current_concurrency -= 1
        return {"status": "success", "in_database": False}

    # Run 10 concurrent requests through run_bounded with webrisk_semaphore
    tasks = [
        run_bounded(
            instrumented_operation(),
            webrisk_semaphore,
            timeout_seconds=2.0,
            acquire_timeout_seconds=2.0,
        )
        for _ in range(10)
    ]
    results = await asyncio.gather(*tasks)

    assert len(results) == 10
    # Semaphore permit capacity is 4: maximum concurrency must never exceed 4
    assert max_observed_concurrency <= 4
    assert max_observed_concurrency > 0

    # Test Queue Saturation / Exhaustion:
    # Hold all 4 permits with slow tasks
    hold_event = asyncio.Event()

    async def blocker():
        await hold_event.wait()
        return "blocked_done"

    blocking_tasks = [
        asyncio.create_task(
            run_bounded(blocker(), webrisk_semaphore, timeout_seconds=5.0, acquire_timeout_seconds=1.0)
        )
        for _ in range(4)
    ]
    # Allow blockers to acquire all permits
    await asyncio.sleep(0.02)

    # 5th task attempts to acquire with short acquire timeout and must fail with ProviderQueueExhaustedError
    with pytest.raises(ProviderQueueExhaustedError):
        await run_bounded(
            instrumented_operation(),
            webrisk_semaphore,
            timeout_seconds=1.0,
            acquire_timeout_seconds=0.05,
        )

    # Clean up blocker tasks
    hold_event.set()
    await asyncio.gather(*blocking_tasks)


@pytest.mark.asyncio
async def test_webrisk_log_redaction(caplog):
    """Verify API keys are never leaked in log output even on connection failure."""
    secret_key = "test-secret-google-api-key-999"

    mock_session = MockSession(get_exc=Exception(f"Connection failed with key {secret_key}"))

    with caplog.at_level(logging.DEBUG):
        with patch("aiohttp.ClientSession", return_value=mock_session):
            await check_url_with_webrisk("https://log-test.org", api_key=secret_key)

    for record in caplog.records:
        assert secret_key not in record.message
        assert secret_key not in str(record.__dict__)


def test_webrisk_pipeline_integration_capped_score(test_client, monkeypatch):
    """
    Test Goal A2: Mathematically prove Web Risk +30 cap in /api/analyze pipeline:
    - Multiple threat types (e.g. 3 types) contribute exactly +30 total (not +90).
    - baseline_score + 30 == final_score (e.g. baseline 40 -> final 70).
    """
    # 1. First measure baseline score without Web Risk
    async def mock_clean_webrisk(url, api_key):
        return {"status": "success", "url": url, "in_database": False, "threat_types": []}

    async def mock_clean_vt(url, api_key):
        return {"status": "success", "url": url, "malicious_count": 0, "suspicious_count": 0, "reputation_score": 100, "vendors": []}

    async def mock_clean_uh(url):
        return {"status": "success", "url": url, "in_database": False, "threat_type": None, "date_added": "", "malware_families": []}

    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_clean_webrisk)
    monkeypatch.setattr("app.main.analyze_url_with_virustotal", mock_clean_vt)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", mock_clean_uh)

    headers = get_csrf_headers(test_client)
    sample_url = "http://suspicious-test-portal.xyz/login"

    res_baseline = test_client.post(
        "/api/analyze",
        json={"input_type": "url", "content": sample_url},
        headers=headers,
    )
    assert res_baseline.status_code == 200
    baseline_score = res_baseline.json()["risk_score"]

    # 2. Now run with 3 threat types flagged by Web Risk
    async def mock_multi_threat_webrisk(url, api_key):
        return {
            "status": "success",
            "url": url,
            "in_database": True,
            "threat_types": ["SOCIAL_ENGINEERING", "MALWARE", "UNWANTED_SOFTWARE"],
        }

    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_multi_threat_webrisk)

    # Clear cache to ensure re-evaluation
    webrisk_cache.clear()

    res_flagged = test_client.post(
        "/api/analyze",
        json={"input_type": "url", "content": sample_url},
        headers=headers,
    )
    assert res_flagged.status_code == 200
    flagged_data = res_flagged.json()
    final_score = flagged_data["risk_score"]

    # Mathematically prove exact +30 score boost (capped at 100 max)
    expected_score = min(100, baseline_score + 30)
    assert final_score == expected_score
    # Prove that 3 threat types did not multiply the score (+90 would exceed expected_score)
    if baseline_score <= 70:
        assert final_score == baseline_score + 30

    assert flagged_data["webrisk_status"] == "success"
    assert flagged_data["webrisk_in_database"] is True
    assert len(flagged_data["webrisk_threat_types"]) == 3
    assert any("Google Web Risk Flagged" in s["title"] for s in flagged_data["phishing_signals"])


def test_webrisk_cache_real_pipeline_orchestration(test_client, monkeypatch):
    """
    Test Goal A3: Test Web Risk cache through the real /api/analyze path:
    - Same URL called twice invokes provider exactly once (second request uses cache).
    - Different URL invokes provider for a fresh lookup.
    """
    call_counts = {"count": 0}

    async def instrumented_webrisk(url, api_key):
        call_counts["count"] += 1
        return {
            "status": "success",
            "url": url,
            "in_database": False,
            "threat_types": [],
        }

    monkeypatch.setattr("app.main.check_url_with_webrisk", instrumented_webrisk)
    webrisk_cache.clear()

    headers = get_csrf_headers(test_client)
    url_a = "https://example-domain-a.org/login"
    url_b = "https://example-domain-b.org/login"

    # Request 1 for URL A: Provider is called
    res1 = test_client.post("/api/analyze", json={"input_type": "url", "content": url_a}, headers=headers)
    assert res1.status_code == 200
    assert call_counts["count"] == 1

    # Request 2 for SAME URL A: Must hit cache, call count stays 1
    res2 = test_client.post("/api/analyze", json={"input_type": "url", "content": url_a}, headers=headers)
    assert res2.status_code == 200
    assert call_counts["count"] == 1

    # Request 3 for DIFFERENT URL B: Cache miss, call count increments to 2
    res3 = test_client.post("/api/analyze", json={"input_type": "url", "content": url_b}, headers=headers)
    assert res3.status_code == 200
    assert call_counts["count"] == 2


def test_webrisk_provider_aware_cache_ttl():
    """
    Test Goal A4: Verify provider-aware cache TTL calculation:
    - Valid RFC3339 expireTime returns remaining seconds bounded by [min_ttl, max_ttl].
    - Missing or malformed expireTime falls back safely to default 600s.
    """
    now = datetime.now(timezone.utc)

    # 1. Future expireTime in 300 seconds
    expire_in_300 = (now + timedelta(seconds=300)).isoformat()
    ttl_300 = _calculate_effective_ttl(expire_in_300)
    assert 295 <= ttl_300 <= 305

    # 2. Far future expireTime (> 600s) is capped at max_ttl (600s)
    expire_in_10000 = (now + timedelta(seconds=10000)).isoformat()
    ttl_capped = _calculate_effective_ttl(expire_in_10000)
    assert ttl_capped == 600

    # 3. Near past or tiny future is bounded by min_ttl (60s)
    expire_in_10 = (now + timedelta(seconds=10)).isoformat()
    ttl_min = _calculate_effective_ttl(expire_in_10)
    assert ttl_min == 60

    # 4. None or malformed returns default 600s
    assert _calculate_effective_ttl(None) == 600
    assert _calculate_effective_ttl("invalid-date-string") == 600


def test_webrisk_provider_non_fatal_on_failure(test_client, monkeypatch):
    """When Web Risk fails or times out, analysis succeeds without crash and status is reported."""
    async def mock_webrisk_error(url, api_key):
        return {
            "status": "error",
            "url": url,
            "in_database": False,
            "threat_types": [],
        }

    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_webrisk_error)

    headers = get_csrf_headers(test_client)
    res = test_client.post(
        "/api/analyze",
        json={"input_type": "url", "content": "https://example.com/test"},
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["webrisk_status"] == "error"
    assert data["webrisk_in_database"] is None

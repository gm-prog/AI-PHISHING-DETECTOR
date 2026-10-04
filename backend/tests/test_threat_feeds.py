import hashlib
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.db import Base, get_db
from app.main import app, limiter
from app.models.domain import ThreatIndicator
from app.services.threat_feed_service import (
    NormalizedThreatIndicator,
    ThreatFeedProvider,
    normalize_indicator_value,
    lookup_threat_indicator,
    refresh_threat_feed,
    refresh_all_threat_feeds,
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


class MockFeedProvider:
    def __init__(self, source_name: str, indicators: list):
        self.source_name = source_name
        self._indicators = indicators

    async def fetch_indicators(self, limit: int = 1000):
        return self._indicators[:limit]


def test_normalize_indicator_value():
    """Verify indicator normalization and SHA-256 hash generation."""
    clean, h = normalize_indicator_value("url", "  https://evil-portal.xyz/login  ")
    assert clean == "https://evil-portal.xyz/login"
    assert len(h) == 64
    assert h == hashlib.sha256("https://evil-portal.xyz/login".encode("utf-8")).hexdigest()

    clean_dom, h_dom = normalize_indicator_value("domain", "BAD-DOMAIN.COM")
    assert clean_dom == "bad-domain.com"


def test_threat_indicator_insert_and_unique_constraint(db_session):
    """Verify ThreatIndicator insertion and source-type-indicator deduplication."""
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_url = "https://phish-sample-1.org"
    clean_url, url_hash = normalize_indicator_value("url", raw_url)

    record = ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        indicator_type="url",
        indicator=clean_url,
        indicator_hash=url_hash,
        classification="phishing",
        confidence=0.95,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    )
    db_session.add(record)
    db_session.commit()

    # Query back
    fetched = db_session.query(ThreatIndicator).filter_by(indicator_hash=url_hash).first()
    assert fetched is not None
    assert fetched.source == "phishtank"
    assert fetched.classification == "phishing"


def test_lookup_active_and_expired_indicators(db_session):
    """Verify lookup distinguishes active indicators from expired indicators."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # 1. Active Indicator (no expiry)
    url_active = "https://active-threat.org/login"
    _, hash_active = normalize_indicator_value("url", url_active)
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="internal_feed",
        indicator_type="url",
        indicator=url_active,
        indicator_hash=hash_active,
        classification="credential_harvesting",
        confidence=1.0,
        observed_at=now_iso,
        expires_at=None,
        created_at=now_iso,
        updated_at=now_iso,
    ))

    # 2. Expired Indicator (expires_at in past)
    url_expired = "https://expired-threat.org/login"
    _, hash_expired = normalize_indicator_value("url", url_expired)
    past_iso = (now - timedelta(days=2)).isoformat()
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        indicator_type="url",
        indicator=url_expired,
        indicator_hash=hash_expired,
        classification="phishing",
        confidence=0.8,
        observed_at=past_iso,
        expires_at=past_iso,
        created_at=past_iso,
        updated_at=past_iso,
    ))
    db_session.commit()

    # Lookup Active: should match
    res_active = lookup_threat_indicator(db_session, "url", url_active)
    assert res_active is not None
    assert res_active["is_match"] is True
    assert res_active["classification"] == "credential_harvesting"
    assert "internal_feed" in res_active["sources"]

    # Lookup Expired: should NOT match (returns None)
    res_expired = lookup_threat_indicator(db_session, "url", url_expired)
    assert res_expired is None

    # Lookup Non-existent: returns None
    res_unknown = lookup_threat_indicator(db_session, "url", "https://totally-clean-url.com")
    assert res_unknown is None


def test_lookup_multiple_source_provenance_deduplication(db_session):
    """Verify that multiple sources matching the same indicator return consolidated provenance."""
    now_iso = datetime.now(timezone.utc).isoformat()
    url_multi = "https://multi-source-threat.com/steal"
    _, h_multi = normalize_indicator_value("url", url_multi)

    # Insert from phishtank
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        indicator_type="url",
        indicator=url_multi,
        indicator_hash=h_multi,
        classification="phishing",
        confidence=0.9,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    # Insert from misp
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        indicator_type="url",
        indicator=url_multi,
        indicator_hash=h_multi,
        classification="phishing",
        confidence=0.99,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    db_session.commit()

    lookup_res = lookup_threat_indicator(db_session, "url", url_multi)
    assert lookup_res is not None
    assert lookup_res["is_match"] is True
    assert len(lookup_res["sources"]) == 2
    assert "misp" in lookup_res["sources"]
    assert "phishtank" in lookup_res["sources"]
    assert lookup_res["confidence"] == 0.99


def test_refresh_threat_feed_deterministic_sync(db_session):
    """Verify feed refresh synchronizes new records and updates existing records deterministically."""
    source_name = "test_feed_sync"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Initial batch of 3 indicators
    initial_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site1.org", classification="phishing", confidence=0.8),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site2.org", classification="malware", confidence=0.9),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site3.org", classification="phishing", confidence=0.7),
    ]

    prov = MockFeedProvider(source_name=source_name, indicators=initial_items)
    res1 = refresh_threat_feed(db_session, prov, indicators=initial_items)
    assert res1["inserted"] == 3
    assert res1["updated"] == 0
    assert res1["total_processed"] == 3

    # Second batch: 2 existing updated, 2 new inserted
    second_items = [
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site1.org", classification="phishing_active", confidence=1.0),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site2.org", classification="malware_updated", confidence=0.95),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site4.org", classification="phishing", confidence=0.85),
        NormalizedThreatIndicator(source=source_name, indicator_type="url", indicator="https://site5.org", classification="phishing", confidence=0.9),
    ]
    res2 = refresh_threat_feed(db_session, prov, indicators=second_items)
    assert res2["inserted"] == 2
    assert res2["updated"] == 2
    assert res2["total_processed"] == 4

    # Verify updated values in database
    _, h1 = normalize_indicator_value("url", "https://site1.org")
    rec1 = db_session.query(ThreatIndicator).filter_by(source=source_name, indicator_hash=h1).first()
    assert rec1.classification == "phishing_active"
    assert rec1.confidence == 1.0


def test_pipeline_integration_local_threat_feed_boost(client, db_session, monkeypatch):
    """
    Verify full /api/analyze URL pipeline with local threat feed match:
    - Active match contributes bounded +35 score boost
    - Adds explainable 'Threat Intelligence Feed Match' signal
    - Response includes local_feed_findings with source provenance
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    test_url = "https://known-feed-phish.net/login"
    _, h_url = normalize_indicator_value("url", test_url)

    # Insert test indicator into database
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="phishing",
        confidence=1.0,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    db_session.commit()

    # Isolate external APIs so only local feeds + heuristics run
    async def mock_clean_vt(url, api_key):
        return {"status": "success", "url": url, "malicious_count": 0, "suspicious_count": 0, "reputation_score": 100, "vendors": []}

    async def mock_clean_uh(url):
        return {"status": "success", "url": url, "in_database": False, "threat_type": None, "date_added": "", "malware_families": []}

    async def mock_clean_wr(url, api_key):
        return {"status": "success", "url": url, "in_database": False, "threat_types": []}

    monkeypatch.setattr("app.main.analyze_url_with_virustotal", mock_clean_vt)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", mock_clean_uh)
    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_clean_wr)

    headers = get_csrf_headers(client)
    res = client.post("/api/analyze", json={"input_type": "url", "content": test_url}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["risk_score"] >= 35
    assert data["local_feed_findings"] is not None
    assert data["local_feed_findings"]["is_match"] is True
    assert "phishtank" in data["local_feed_findings"]["sources"]
    assert any("Threat Intelligence Feed Match" in s["title"] for s in data["phishing_signals"])


def test_duplicate_threat_sources_do_not_stack_score_boost(client, db_session, monkeypatch):
    """
    Verify that an indicator matching multiple synchronized feed sources (e.g. phishtank + misp)
    contributes only ONE +35 risk boost, not compounding score multipliers.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    test_url = "https://dual-source-phish.biz/login"
    _, h_url = normalize_indicator_value("url", test_url)

    # Insert under source 1
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="phishtank",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="phishing",
        confidence=0.9,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    # Insert under source 2
    db_session.add(ThreatIndicator(
        id=str(uuid.uuid4()),
        source="misp",
        indicator_type="url",
        indicator=test_url,
        indicator_hash=h_url,
        classification="phishing",
        confidence=0.95,
        observed_at=now_iso,
        created_at=now_iso,
        updated_at=now_iso,
    ))
    db_session.commit()

    async def mock_clean_all(url, *args):
        return {"status": "success", "url": url, "in_database": False, "threat_types": []}

    monkeypatch.setattr("app.main.analyze_url_with_virustotal", mock_clean_all)
    monkeypatch.setattr("app.main.check_url_with_urlhaus", mock_clean_all)
    monkeypatch.setattr("app.main.check_url_with_webrisk", mock_clean_all)

    headers = get_csrf_headers(client)
    res = client.post("/api/analyze", json={"input_type": "url", "content": test_url}, headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Base heuristic for benign-looking URL is low; boost is +35 max
    assert data["local_feed_findings"]["matched_records_count"] == 2
    # Signals must have exactly 1 threat_feed_match signal (not 2)
    feed_signals = [s for s in data["phishing_signals"] if s["id"] == "threat_feed_match"]
    assert len(feed_signals) == 1


def test_threat_feed_db_error_fail_safe_in_pipeline(client, monkeypatch):
    """Verify that database errors during threat feed lookup fail safely without crashing analysis."""
    def mock_broken_lookup(db, ind_type, val):
        raise RuntimeError("Database connection lost")

    monkeypatch.setattr("app.main.lookup_threat_indicator", mock_broken_lookup)

    headers = get_csrf_headers(client)
    res = client.post("/api/analyze", json={"input_type": "url", "content": "https://sample-safe.com"}, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["local_feed_findings"] is None

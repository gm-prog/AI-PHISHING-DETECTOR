"""Operational regression tests: isolated SQLite, in-memory sinks, no provider network."""
import asyncio
import logging
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from app import telemetry
from app import main
from app.db import Base, get_db
from app.jobs import refresh_threat_feeds as job
from app.services import provider_guard as guard, llm_service as llm, threat_feed_service as feeds

SECRET = "private-payload-example.invalid-token-938475"


@pytest.fixture(autouse=True)
def clean_telemetry(monkeypatch):
    telemetry.shutdown()
    # Alembic baseline tests run fileConfig(disable_existing_loggers=True).
    # Restore loggers for this test only, rather than changing migration behavior.
    for name in list(logging.Logger.manager.loggerDict):
        log = logging.getLogger(name)
        monkeypatch.setattr(log, "disabled", False)
    for key in list(__import__("os").environ):
        if key.startswith("OTEL_"):
            monkeypatch.delenv(key)
    yield
    telemetry.shutdown()


@pytest.fixture
def sinks():
    exporter, reader = InMemorySpanExporter(), InMemoryMetricReader()
    telemetry.initialize(span_exporter=exporter, metric_reader=reader)
    return exporter, reader


def points(reader, name):
    data = reader.get_metrics_data()
    if data is None:
        return []
    return [point for resource in data.resource_metrics for scope in resource.scope_metrics
            for metric in scope.metrics if metric.name == name for point in metric.data.data_points]


def spans(exporter):
    telemetry._runtime[0].force_flush()
    return exporter.get_finished_spans()


@pytest.fixture
def database():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as db:
        yield db
    engine.dispose()


@pytest.fixture
def client(monkeypatch, database):
    old = dict(main.app.dependency_overrides)
    def override():
        yield database
    main.app.dependency_overrides[get_db] = override
    monkeypatch.setattr(main, "verify_schema_invariants", lambda: None)
    monkeypatch.setattr(main.settings, "GEMINI_API_KEY", "")
    main.limiter.reset()
    for cache in (guard.llm_cache, guard.urlhaus_cache, guard.webrisk_cache, guard.virustotal_cache):
        cache.clear()
    async def fake(*args, **kwargs):
        return {"status": "success", "in_database": False, "malicious_count": 0}
    for name in ("analyze_url_with_virustotal", "check_url_with_urlhaus", "check_url_with_webrisk"):
        monkeypatch.setattr(main, name, fake)
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()
    main.app.dependency_overrides.update(old)
    main.limiter.reset()


def scan(client, input_type="email_text"):
    client.get("/api/health")
    return client.post("/api/analyze", json={"input_type": input_type,
        "content": "https://" + SECRET if input_type == "url" else SECRET},
        headers={"X-CSRF-Token": client.cookies.get(main.settings.CSRF_COOKIE_NAME)})


def test_initialization_idempotent_and_recreatable(sinks):
    original = telemetry._runtime
    assert telemetry.initialize() is original
    assert telemetry.initialize(span_exporter=InMemorySpanExporter()) is original
    telemetry.shutdown()
    telemetry.shutdown()
    assert telemetry.initialize() is None
    assert telemetry.initialize(span_exporter=InMemorySpanExporter()) is not original


def test_disabled_startup_requests_and_csrf(client):
    with client:
        assert telemetry._runtime is None
        assert scan(client).status_code == 200
        assert main.settings.CSRF_COOKIE_NAME in client.cookies
    with client:
        assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize("mode", ["unsupported_protocol", "disabled", "invalid_endpoint"])
def test_bad_or_disabled_export_configuration_does_not_fail_startup(monkeypatch, client, mode):
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "not-a-url")
    if mode == "unsupported_protocol":
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
    elif mode == "disabled":
        monkeypatch.setenv("OTEL_SDK_DISABLED", "true")
    with client:
        assert scan(client).status_code == 200


def test_health_never_queries_db_even_with_cookie(monkeypatch, client):
    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected database/provider call")
    monkeypatch.setattr(main.engine, "connect", forbidden)
    monkeypatch.setattr(main, "get_user_id_from_session", forbidden)
    client.cookies.set(main.settings.AUTH_COOKIE_NAME, SECRET)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "api_active": True, "version": "2.0.0",
        "message": "Sentinel AI Security Gateway is operational."}
    assert main.settings.CSRF_COOKIE_NAME in client.cookies


@pytest.mark.parametrize("failure", [False, True])
def test_readiness_connection_lifecycle_and_sanitization(monkeypatch, client, failure, caplog):
    engine = MagicMock()
    connection = engine.connect.return_value.__enter__.return_value
    if failure:
        connection.execute.side_effect = RuntimeError(SECRET)
    monkeypatch.setattr(main, "engine", engine)
    with caplog.at_level(logging.INFO, logger="sentinel.operations"):
        response = client.get("/api/ready")
    assert response.status_code == (503 if failure else 200)
    assert response.json()["database"] == ("unavailable" if failure else "available")
    assert str(connection.execute.call_args.args[0]) == "SELECT 1"
    engine.connect.return_value.__exit__.assert_called_once()
    assert SECRET not in response.text + caplog.text


@pytest.mark.parametrize("input_type", ["url", "email_text", "email_header"])
def test_analysis_spans_metrics_privacy_and_units(sinks, client, input_type, caplog):
    exporter, reader = sinks
    with caplog.at_level(logging.INFO, logger="sentinel.operations"):
        response = scan(client, input_type)
    assert response.status_code == 200
    recorded = spans(exporter)
    names = {s.name for s in recorded}
    assert {"analysis", "analysis.heuristic", "analysis.persistence", "POST /api/analyze"} <= names
    if input_type == "url":
        assert "threat_intelligence.local_lookup" in names
        assert "provider.lookup" in names
    assert SECRET not in str([(s.attributes, s.events, s.status.description) for s in recorded])
    assert SECRET not in caplog.text
    for name in ("sentinel.analysis.duration", "http.server.request.duration"):
        durations = points(reader, name)
        assert durations
        assert all(0 <= point.sum < 10 for point in durations)
    counts = points(reader, "sentinel.analysis.count")
    assert sum(p.value for p in counts) == 1
    assert counts[0].attributes["input_type"] == input_type
    assert counts[0].attributes["verdict"] in {"safe", "warning", "danger"}
    assert points(reader, "sentinel.llm.fallbacks")[0].attributes == {"reason": "unconfigured"}


def test_routes_methods_and_attributes_are_bounded(sinks, client):
    exporter, reader = sinks
    for path in (f"/api/history/{SECRET}?secret={SECRET}", f"/{SECRET}"):
        client.get(path, headers={"Authorization": SECRET, "Cookie": "private=" + SECRET,
                                 "baggage": "secret=" + SECRET})
    client.request(SECRET, "/api/health")
    for point in points(reader, "sentinel.http.requests"):
        assert SECRET not in str(point.attributes)
        assert point.attributes["http.route"] in {"/api/history/{scan_id}", "unmatched", "/api/health"}
    assert SECRET not in str([(s.name, s.attributes, s.events) for s in spans(exporter)])
    assert telemetry.attributes({"provider": SECRET, "source": SECRET, "outcome": SECRET,
                                  "http.route": SECRET, "user_id": SECRET}) == {
        "provider": "unknown", "source": "unknown", "outcome": "error", "http.route": "unmatched"}


def test_traceparent_only_propagates_trace_id(sinks, client):
    exporter, _ = sinks
    trace_id = "1234567890abcdef1234567890abcdef"
    client.get("/api/health", headers={"traceparent": f"00-{trace_id}-1234567890abcdef-01",
                                     "tracestate": "private=" + SECRET, "baggage": "private=" + SECRET})
    recorded = spans(exporter)[-1]
    assert format(recorded.context.trace_id, "032x") == trace_id
    assert not recorded.context.trace_state


@pytest.mark.asyncio
async def test_cache_events_do_not_include_keys(sinks):
    _, reader = sinks
    cache = guard.TTLCache(max_entries=1, ttl_seconds=100, provider="webrisk")
    assert await cache.get(SECRET) is None
    await cache.set(SECRET, SECRET)
    assert await cache.get(SECRET) == SECRET
    await cache.set("other", SECRET)
    cache._items["other"] = (0, SECRET)
    assert await cache.get("other") is None
    assert {p.attributes["cache.result"] for p in points(reader, "sentinel.cache.accesses")} == {"hit", "miss"}
    assert {p.attributes["cache.result"] for p in points(reader, "sentinel.cache.removals")} == {"expired", "evicted"}


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "timeout", "queue_exhausted", "error", "unexpected_status"])
async def test_provider_guard_outcomes_and_sanitization(sinks, outcome, caplog):
    exporter, reader = sinks
    sem = asyncio.Semaphore(0 if outcome == "queue_exhausted" else 1)
    async def provider():
        if outcome == "timeout":
            await asyncio.sleep(1)
        if outcome == "error":
            raise RuntimeError(SECRET)
        return {"status": SECRET if outcome == "unexpected_status" else "success", "url": SECRET}
    with caplog.at_level(logging.INFO):
        if outcome in {"timeout", "queue_exhausted", "error"}:
            with pytest.raises((TimeoutError, guard.ProviderQueueExhaustedError, RuntimeError)):
                await guard.run_bounded(provider, sem, .001, .001)
        else:
            await guard.run_bounded(provider, sem, .001, .001)
    expected = "error" if outcome == "unexpected_status" else outcome
    assert points(reader, "sentinel.provider.calls")[0].attributes["outcome"] == expected
    assert points(reader, "sentinel.provider.queue_wait")[0].sum >= 0
    if outcome in {"timeout", "queue_exhausted"}:
        assert points(reader, "sentinel.provider.exhaustion")[0].value == 1
    assert SECRET not in caplog.text
    assert SECRET not in str([(s.attributes, s.events) for s in spans(exporter)])


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", ["unconfigured", "queue_exhausted", "timeout", "provider_error"])
async def test_llm_fallback_categories(sinks, monkeypatch, reason):
    _, reader = sinks
    guard.llm_cache.clear()
    monkeypatch.setattr(llm, "llm_semaphore", asyncio.Semaphore(0 if reason == "queue_exhausted" else 1))
    def create_client(**kwargs):
        if reason == "timeout":
            raise TimeoutError(SECRET)
        raise RuntimeError(SECRET)
    client_factory = MagicMock(side_effect=create_client)
    monkeypatch.setattr(llm.genai, "Client", client_factory)
    result = await llm.analyze_with_llm("email_text", SECRET, "" if reason == "unconfigured" else SECRET,
                                     70, [], acquire_timeout_seconds=.001)
    assert result["risk_score"] == 70
    assert result["status"] == "danger"
    counts = points(reader, "sentinel.llm.fallbacks")
    assert [(dict(p.attributes), p.value) for p in counts] == [({"reason": reason}, 1)]
    assert set(result) == {"risk_score", "status", "phishing_signals", "ai_explanation"}
    if reason in {"unconfigured", "queue_exhausted"}:
        client_factory.assert_not_called()
    else:
        client_factory.assert_called_once()


class FakeFeed:
    source_name = "openphish"
    fetch_limit = 10
    default_refresh_interval_seconds = 21600
    supports_etag = False
    supports_last_modified = False
    def __init__(self, outcome="success"):
        self.outcome = outcome
        self.is_enabled = outcome != "disabled"
    async def fetch_indicators(self, **kwargs):
        if self.outcome == "failed":
            raise RuntimeError(SECRET)
        if self.outcome == "not_modified":
            return [], None, None, True
        return [feeds.NormalizedThreatIndicator(self.source_name, "url", "https://" + SECRET,
                                               "phishing")], None, None, False


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["success", "not_modified", "disabled", "failed"])
async def test_feed_instrumentation_uses_existing_refresh(sinks, database, outcome, caplog):
    exporter, reader = sinks
    with caplog.at_level(logging.INFO):
        result = await feeds.refresh_threat_feed(database, FakeFeed(outcome))
    assert result["status"] == outcome
    assert points(reader, "sentinel.feed.attempts")[0].value == 1
    assert points(reader, "sentinel.feed.outcomes")[0].attributes["outcome"] == outcome
    assert points(reader, "sentinel.feed.duration")[0].sum >= 0
    if outcome in {"success", "not_modified"}:
        assert points(reader, "sentinel.feed.last_success")[0].value > 0
    assert SECRET not in caplog.text
    assert SECRET not in str([(s.attributes, s.events) for s in spans(exporter)])


@pytest.mark.asyncio
@pytest.mark.parametrize("outcomes,expected", [(["success"], 0), (["not_modified"], 0),
    (["disabled"], 0), (["failed", "success"], 1)])
async def test_job_exit_and_session_closure(monkeypatch, database, outcomes, expected, caplog):
    providers = [FakeFeed(o) for o in outcomes]
    for index, provider in enumerate(providers):
        provider.source_name = ["openphish", "phishtank"][index]
    factory = MagicMock()
    factory.return_value.__enter__.return_value = database
    monkeypatch.setattr(job, "open_session", factory)
    monkeypatch.setattr(job, "verify_schema", lambda: None)
    monkeypatch.setattr(job, "registered_providers", lambda: providers)
    with caplog.at_level(logging.INFO):
        assert await job.run() == expected
    factory.return_value.__exit__.assert_called_once()
    assert caplog.text.count("event=feed_job_source_completed") == len(providers)
    assert SECRET not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["refresh", "session", "schema"])
async def test_job_unexpected_failures_close_session_and_sanitize(monkeypatch, stage, caplog):
    factory = MagicMock()
    monkeypatch.setattr(job, "open_session", factory)
    monkeypatch.setattr(job, "verify_schema", MagicMock(side_effect=RuntimeError(SECRET))
                        if stage == "schema" else lambda: None)
    if stage == "session":
        factory.side_effect = RuntimeError(SECRET)
    async def fail(*args):
        raise RuntimeError(SECRET)
    monkeypatch.setattr(job, "refresh_all", fail)
    with caplog.at_level(logging.INFO):
        assert await job.run() == 1
    if stage == "refresh":
        factory.return_value.__exit__.assert_called_once()
    assert SECRET not in caplog.text


@pytest.mark.asyncio
async def test_refresh_all_continues_after_unexpected_failure(monkeypatch):
    calls, db = [], MagicMock()
    async def refresh(db, provider):
        calls.append(provider.source_name)
        if len(calls) == 1:
            raise RuntimeError(SECRET)
        return {"status": "success"}
    monkeypatch.setattr(feeds, "refresh_threat_feed", refresh)
    results = await feeds.refresh_all_threat_feeds(db, [FakeFeed(), FakeFeed()])
    assert len(calls) == 2
    assert [r["status"] for r in results] == ["failed", "success"]
    db.rollback.assert_called_once()
    assert await feeds.refresh_all_threat_feeds(db, []) == []


def test_export_failure_does_not_change_scan_or_leak(client, caplog):
    class BrokenExporter(InMemorySpanExporter):
        def export(self, spans):
            raise RuntimeError(SECRET)
    telemetry.initialize(span_exporter=BrokenExporter())
    with caplog.at_level(logging.INFO):
        result = scan(client)
        telemetry._runtime[0].force_flush()
    telemetry.shutdown()
    baseline = scan(client)
    assert result.status_code == baseline.status_code == 200
    assert result.json() == baseline.json()
    assert SECRET not in caplog.text
    assert "telemetry_export_failed" in caplog.text


def test_duration_is_seconds_and_event_milliseconds(sinks, monkeypatch, caplog):
    from types import SimpleNamespace
    _, reader = sinks
    monkeypatch.setattr(telemetry, "time", SimpleNamespace(monotonic=lambda: 102.5))
    with caplog.at_level(logging.INFO, logger="sentinel.operations"):
        telemetry.provider_result("webrisk", "success", 100)
    assert points(reader, "sentinel.provider.duration")[0].sum == 2.5
    assert "duration_ms=2500.0" in caplog.text
    data = reader.get_metrics_data()
    assert {metric.unit for rm in data.resource_metrics for sm in rm.scope_metrics
            for metric in sm.metrics if metric.name == "sentinel.provider.duration"} == {"s"}


def test_persistence_and_heuristic_failure_events_are_private(sinks, client, database, monkeypatch, caplog):
    exporter, _ = sinks
    monkeypatch.setattr(database, "commit", MagicMock(side_effect=RuntimeError(SECRET)))
    with caplog.at_level(logging.INFO, logger="sentinel.operations"):
        assert scan(client).status_code == 200  # existing graceful persistence failure contract
    assert "scan_persistence_failed" in caplog.text
    monkeypatch.setattr(main, "analyze_email_text", MagicMock(side_effect=RuntimeError(SECRET)))
    with caplog.at_level(logging.INFO, logger="sentinel.operations"):
        assert scan(client).status_code == 500
    recorded = spans(exporter)
    assert SECRET not in str([(s.attributes, s.events, s.status.description) for s in recorded])
    assert SECRET not in caplog.text
    assert any(s.attributes.get("verdict") == "error" for s in recorded)


def test_metric_export_failure_does_not_fail_request(client, caplog):
    from opentelemetry.sdk.metrics.export import MetricExporter, PeriodicExportingMetricReader
    class BrokenExporter(MetricExporter):
        def export(self, metrics_data, timeout_millis=10000, **kwargs):
            raise RuntimeError(SECRET)
        def force_flush(self, timeout_millis=10000):
            return True
        def shutdown(self, timeout_millis=30000, **kwargs):
            return None
    reader = PeriodicExportingMetricReader(BrokenExporter(), export_interval_millis=60000)
    telemetry.initialize(metric_reader=reader)
    with caplog.at_level(logging.INFO):
        assert scan(client).status_code == 200
        reader.collect()
    assert SECRET not in caplog.text
    assert "telemetry_export_failed" in caplog.text


@pytest.mark.asyncio
async def test_job_aborts_if_rollback_cannot_restore_session(monkeypatch):
    db = MagicMock()
    db.rollback.side_effect = RuntimeError(SECRET)
    calls = []
    async def fail(db, provider):
        calls.append(provider)
        raise RuntimeError(SECRET)
    monkeypatch.setattr(feeds, "refresh_threat_feed", fail)
    with pytest.raises(RuntimeError):
        await feeds.refresh_all_threat_feeds(db, [FakeFeed(), FakeFeed()])
    assert len(calls) == 1


def test_cli_configuration_error_is_sanitized():
    import os
    import subprocess
    import sys
    environment = dict(os.environ, DATABASE_URL="malformed-" + SECRET)
    result = subprocess.run([sys.executable, "-m", "app.jobs.refresh_threat_feeds"],
                            env=environment, capture_output=True, text=True, timeout=20)
    assert result.returncode == 1
    assert SECRET not in result.stdout + result.stderr
    assert "feed_job_failed" in result.stderr


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["interactions_output_text", "interactions_text", "generate", "compatibility"])
@pytest.mark.parametrize("output", ["valid", "malformed_json", "invalid_schema", "empty"])
async def test_llm_real_output_boundary_counts_once(sinks, monkeypatch, caplog, api, output):
    """Exercise the real worker's extraction, parsing and caught validation failures."""
    exporter, reader = sinks
    monkeypatch.setattr(llm, "llm_cache", guard.TTLCache(provider="gemini"))
    monkeypatch.setattr(llm, "llm_semaphore", asyncio.Semaphore(1))
    payloads = {
        "valid": json.dumps({"risk_score": 10, "status": "safe", "phishing_signals": [],
                             "ai_explanation": "Validated response."}),
        "malformed_json": "{bad json " + SECRET,
        "invalid_schema": json.dumps({"risk_score": 101, "status": SECRET}),
        "empty": "",
    }
    response = SimpleNamespace(text=payloads[output])
    generate = MagicMock(return_value=response)
    sdk = SimpleNamespace(models=SimpleNamespace(generate_content=generate))
    interaction = MagicMock(return_value=SimpleNamespace(**{
        "output_text" if api == "interactions_output_text" else "text": payloads[output]}))
    if api != "generate":
        sdk.interactions = SimpleNamespace(create=interaction)
    if api == "compatibility":
        interaction.side_effect = RuntimeError(SECRET)
    client_factory = MagicMock(return_value=sdk)
    monkeypatch.setattr(llm.genai, "Client", client_factory)
    signals = [{"id": "heuristic", "severity": "high", "title": "Test", "description": "Test"}]
    with caplog.at_level(logging.INFO):
        result = await llm.analyze_with_llm("email_text", SECRET, SECRET, 70, signals)
        # Invalid-output results already use the cache; preserve it without recounting.
        repeated = await llm.analyze_with_llm("email_text", SECRET, SECRET, 70, signals)
    client_factory.assert_called_once()
    assert repeated == result
    assert type(result) is dict
    assert set(result) == {"risk_score", "status", "phishing_signals", "ai_explanation"}
    assert result["risk_score"] == 70  # Preserve server-side floor and verdict.
    assert result["status"] == "danger"
    assert result["phishing_signals"] == signals
    if output == "valid":
        assert result["ai_explanation"] == "Validated response."
    else:
        assert result == llm.get_fallback_analysis("email_text", SECRET, 70, signals)
    counts = points(reader, "sentinel.llm.fallbacks")
    assert [(dict(p.attributes), p.value) for p in counts] == (
        [] if output == "valid" else [({"reason": "invalid_output"}, 1)])
    calls = points(reader, "sentinel.provider.calls")
    assert [(p.attributes["outcome"], p.value) for p in calls] == [
        ("success" if output == "valid" else "error", 1)]
    assert SECRET not in caplog.text
    assert SECRET not in str([(s.attributes, s.events) for s in spans(exporter)])
    if api in {"generate", "compatibility"}:
        generate.assert_called_once()
    else:
        generate.assert_not_called()
        assert interaction.call_args.kwargs["store"] is False


@pytest.mark.asyncio
async def test_llm_late_invalid_output_after_timeout_is_not_counted_twice(sinks, monkeypatch):
    """A timed-out synchronous SDK worker can finish later; only its caller accounts."""
    import threading
    _, reader = sinks
    release = threading.Event()
    completed = threading.Event()
    original_fallback = llm.get_fallback_analysis
    def observe_fallback(*args):
        result = original_fallback(*args)
        if threading.current_thread() is not threading.main_thread():
            completed.set()
        return result
    def create(**kwargs):
        assert release.wait(timeout=5), "test did not release SDK worker"
        return SimpleNamespace(output_text="{bad json " + SECRET)
    monkeypatch.setattr(llm, "llm_cache", guard.TTLCache(provider="gemini"))
    monkeypatch.setattr(llm, "llm_semaphore", asyncio.Semaphore(1))
    monkeypatch.setattr(llm, "get_fallback_analysis", observe_fallback)
    monkeypatch.setattr(llm.genai, "Client", lambda **kwargs:
                        SimpleNamespace(interactions=SimpleNamespace(create=create)))
    try:
        result = await llm.analyze_with_llm("email_text", SECRET, SECRET, 70, [],
                                          request_timeout_seconds=.02)
    finally:
        release.set()
    assert await asyncio.to_thread(completed.wait, 5), "real worker validation did not execute"
    assert result["risk_score"] == 70
    assert [(dict(p.attributes), p.value) for p in points(reader, "sentinel.llm.fallbacks")] == [
        ({"reason": "timeout"}, 1)]

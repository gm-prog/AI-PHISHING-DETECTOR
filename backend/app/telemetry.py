"""Explicit, content-free OTel instrumentation; no global provider registration.

Providers belong to a process lifecycle and can be recreated after shutdown in tests.
No auto-instrumentation, baggage, exception recording, or default resource detectors.
"""
import logging
import os
import math
import threading
import time
from contextlib import contextmanager
from functools import wraps

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.metrics.view import View, ExplicitBucketHistogramAggregation
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

logger = logging.getLogger("sentinel.operations")
PROVIDERS = {"gemini", "virustotal", "urlhaus", "webrisk", "threat_feed", "unknown"}
SOURCES = {"phishtank", "openphish", "misp", "unknown"}
OUTCOMES = {"success", "error", "failed", "timeout", "queue_exhausted", "skipped",
            "disabled", "not_modified", "rate_limited", "provider_unavailable", "cancelled"}
REASONS = {"unconfigured", "queue_exhausted", "timeout", "provider_error", "invalid_output"}
ERRORS = {"timeout", "auth_error", "network_error", "invalid_payload", "too_large",
          "decompression_too_large", "decompression_invalid", "snapshot_validation_failed_empty",
          "snapshot_validation_failed_no_valid_records", "db_commit_error", "database_unavailable", "unexpected", "none"}
DIMENSIONS = {
    "provider": PROVIDERS, "source": SOURCES, "outcome": OUTCOMES,
    "input_type": {"url", "email_text", "email_header"},
    "verdict": {"safe", "warning", "danger", "error"},
    "reason": REASONS, "error.type": ERRORS,
    "cache.result": {"hit", "miss", "expired", "evicted"},
    "freshness": {"fresh", "stale", "expired", "never_synced", "failed", "disabled"},
    "record.type": {"processed", "inserted"},
    "http.request.method": {"GET", "POST", "DELETE", "PUT", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE", "QUERY", "_OTHER"},
    "url.scheme": {"http", "https"},
    "status_class": {"1xx", "2xx", "3xx", "4xx", "5xx"},
}
# Instrument name -> (type, unit). All durations are monotonic seconds.
INSTRUMENTS = {
    "http.server.request.duration": ("histogram", "s"),
    "sentinel.http.requests": ("counter", "{request}"),
    "sentinel.analysis.count": ("counter", "{analysis}"),
    "sentinel.analysis.duration": ("histogram", "s"),
    "sentinel.provider.calls": ("counter", "{call}"),
    "sentinel.provider.duration": ("histogram", "s"),
    "sentinel.provider.execution.duration": ("histogram", "s"),
    "sentinel.provider.queue_wait": ("histogram", "s"),
    "sentinel.provider.errors": ("counter", "{error}"),
    "sentinel.provider.exhaustion": ("counter", "{error}"),
    "sentinel.llm.fallbacks": ("counter", "{fallback}"),
    "sentinel.cache.accesses": ("counter", "{access}"),
    "sentinel.cache.removals": ("counter", "{entry}"),
    "sentinel.feed.attempts": ("counter", "{refresh}"),
    "sentinel.feed.outcomes": ("counter", "{refresh}"),
    "sentinel.feed.duration": ("histogram", "s"),
    "sentinel.feed.records": ("counter", "{record}"),
    "sentinel.feed.last_success": ("gauge", "s"),
}
_lock = threading.RLock()
_runtime = None
_routes = frozenset()


def bounded(value, allowed, default="unknown"):
    return value if isinstance(value, str) and value in allowed else default


def attributes(fields):
    result = {}
    for key, value in fields.items():
        if key in DIMENSIONS:
            result[key] = bounded(value, DIMENSIONS[key], "error" if key == "outcome" else "unknown")
        elif key == "http.route":
            result[key] = value if value in _routes else "unmatched"
        elif key == "http.response.status_code" and isinstance(value, int) and 100 <= value <= 599:
            result[key] = value
    return result


def event(name, **fields):
    # Names are internal constants; fields are the same finite schema as metrics.
    safe = attributes(fields)
    duration = fields.get("duration_ms")
    if isinstance(duration, (int, float)) and math.isfinite(duration) and duration >= 0:
        safe["duration_ms"] = round(duration, 3)
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        safe["trace_id"] = format(ctx.trace_id, "032x")
        safe["span_id"] = format(ctx.span_id, "016x")
    logger.info("event=%s %s", name, " ".join(f"{k}={v}" for k, v in sorted(safe.items())))


class ExportLogFilter(logging.Filter):
    """Exporter libraries may log collector response bodies or credential-bearing URLs."""
    def filter(self, record):
        record.msg = "event=telemetry_export_failed"
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        return True


def _sanitize_export_logs():
    for name in list(logging.Logger.manager.loggerDict):
        if name.startswith(("opentelemetry", "urllib3")):
            log = logging.getLogger(name)
            if not any(isinstance(f, ExportLogFilter) for f in log.filters):
                log.addFilter(ExportLogFilter())


def initialize(service_name="sentinel-ai-api", *, span_exporter=None, metric_reader=None):
    """Idempotent; disabled without an explicit endpoint (test sinks are injectable).

    Own providers rather than replacing OTel's write-once process globals. Export
    errors run off-request on bounded SDK workers; initialization fails open.
    """
    global _runtime
    with _lock:
        if _runtime is not None:
            return _runtime
        if os.getenv("OTEL_SDK_DISABLED", "false").lower() == "true":
            return None
        endpoints = any(os.getenv(k) for k in (
            "OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))
        if not endpoints and span_exporter is None and metric_reader is None:
            return None
        tp = mp = None
        # SDK worker errors must also be sanitized with injected/test exporters.
        _sanitize_export_logs()
        try:
            if endpoints and span_exporter is None and metric_reader is None:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
                # No raw SDK diagnostics, including invalid sampler/env configuration.
                _sanitize_export_logs()
                for signal in ("TRACES", "METRICS"):
                    if os.getenv(f"OTEL_{signal}_EXPORTER", "otlp") not in {"otlp", "none"}:
                        raise ValueError("Unsupported telemetry exporter")
                    protocol = os.getenv(f"OTEL_EXPORTER_OTLP_{signal}_PROTOCOL",
                                         os.getenv("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf"))
                    if protocol != "http/protobuf":
                        raise ValueError("Unsupported telemetry protocol")
                if os.getenv("OTEL_TRACES_EXPORTER", "otlp") != "none" and (
                    os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
                ):
                    span_exporter = OTLPSpanExporter(timeout=3)
                if os.getenv("OTEL_METRICS_EXPORTER", "otlp") != "none" and (
                    os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
                ):
                    metric_reader = PeriodicExportingMetricReader(
                        OTLPMetricExporter(timeout=3), export_interval_millis=60000,
                        export_timeout_millis=4000)
            from app.config import settings
            resource = Resource({"service.name": bounded(service_name, {"sentinel-ai-api", "sentinel-ai-feed-job"}),
                                 "deployment.environment.name": settings.ENVIRONMENT})
            tp = TracerProvider(resource=resource, shutdown_on_exit=False)
            if span_exporter is not None:
                tp.add_span_processor(BatchSpanProcessor(span_exporter, max_queue_size=512,
                    max_export_batch_size=128, schedule_delay_millis=5000, export_timeout_millis=4000))
            mp = MeterProvider(resource=resource, metric_readers=[metric_reader] if metric_reader else [],
                shutdown_on_exit=False, views=[View(instrument_name="http.server.request.duration",
                    aggregation=ExplicitBucketHistogramAggregation(
                        boundaries=(.005, .01, .025, .05, .075, .1, .25, .5, .75, 1, 2.5, 5, 7.5, 10)))])
            meter = mp.get_meter("sentinel.operations")
            instruments = {name: getattr(meter, f"create_{kind}")(name, unit=unit)
                           for name, (kind, unit) in INSTRUMENTS.items()}
            _runtime = (tp, mp, instruments)
            return _runtime
        except Exception:
            event("telemetry_initialization_failed")
            for provider in (mp or metric_reader, tp or span_exporter):
                if provider:
                    try:
                        provider.shutdown()
                    except Exception:
                        event("telemetry_shutdown_failed")
            return None


def shutdown():
    global _runtime
    with _lock:
        runtime, _runtime = _runtime, None
        if runtime:
            for provider in runtime[:2]:
                try:
                    provider.shutdown()
                except Exception:
                    event("telemetry_shutdown_failed")


def measure(name, value=1, **fields):
    try:
        if _runtime is not None:
            instrument = _runtime[2][name]
            kind = INSTRUMENTS[name][0]
            getattr(instrument, {"counter": "add", "histogram": "record", "gauge": "set"}[kind])(
                value, attributes(fields))
    except Exception:
        event("telemetry_record_failed")


@contextmanager
def span(name, *, context=None, kind=trace.SpanKind.INTERNAL, **fields):
    tracer = _runtime[0].get_tracer("sentinel.operations") if _runtime else trace.NoOpTracer()
    # Explicitly disable automatic exception messages, stack traces and status descriptions.
    with tracer.start_as_current_span(name, context=context, kind=kind, attributes=attributes(fields),
                                     record_exception=False, set_status_on_exception=False) as current:
        try:
            yield current
        except BaseException as exc:
            current.set_attribute("error.type", "timeout" if isinstance(exc, TimeoutError) else "unexpected")
            current.set_status(trace.StatusCode.ERROR)
            raise


@contextmanager
def operation(name):
    with span(name):
        yield


def fallback(reason):
    reason = bounded(reason, REASONS, "provider_error")
    measure("sentinel.llm.fallbacks", reason=reason)
    event("llm_fallback", reason=reason)


def provider_result(provider, outcome, started):
    outcome = bounded(outcome, OUTCOMES, "error")
    fields = {"provider": provider, "outcome": outcome}
    measure("sentinel.provider.calls", **fields)
    measure("sentinel.provider.duration", time.monotonic() - started, **fields)
    if outcome in {"timeout", "queue_exhausted"}:
        measure("sentinel.provider.exhaustion", **fields)
    if outcome not in {"success", "skipped", "disabled", "not_modified"}:
        measure("sentinel.provider.errors", **fields)
    event("provider_call_completed", duration_ms=(time.monotonic() - started) * 1000, **fields)


def analysis_operation(fn):
    @wraps(fn)
    async def wrapped(*args, **kwargs):
        input_type = kwargs["body"].input_type
        started = time.monotonic()
        verdict = "error"
        with span("analysis", input_type=input_type) as current:
            try:
                result = await fn(*args, **kwargs)
                verdict = bounded(result.status, {"safe", "warning", "danger"}, "error")
                return result
            finally:
                current.set_attribute("verdict", verdict)
                measure("sentinel.analysis.count", input_type=input_type, verdict=verdict)
                measure("sentinel.analysis.duration", time.monotonic() - started, input_type=input_type, verdict=verdict)
                event("analysis_completed", input_type=input_type, verdict=verdict,
                      duration_ms=(time.monotonic() - started) * 1000)
    return wrapped


def feed_operation(fn):
    @wraps(fn)
    async def wrapped(db, provider, *args, **kwargs):
        source = bounded(provider.source_name, SOURCES)
        started = time.monotonic()
        outcome, error, freshness = "failed", "unexpected", "failed"
        measure("sentinel.feed.attempts", source=source)
        with span("threat_feed.refresh", source=source) as current:
            try:
                result = await fn(db, provider, *args, **kwargs)
                outcome = bounded(result.get("status"), OUTCOMES, "error")
                error = bounded(result.get("error_code", "none"), ERRORS, "unexpected")
                freshness = bounded(result.get("freshness"), DIMENSIONS["freshness"])
                for kind in ("processed", "inserted"):
                    measure("sentinel.feed.records", result.get(f"records_{kind}", 0),
                            source=source, **{"record.type": kind})
                if outcome in {"success", "not_modified"}:
                    measure("sentinel.feed.last_success", time.time(), source=source)
                return result
            finally:
                fields = {"source": source, "outcome": outcome, "error.type": error, "freshness": freshness}
                current.set_attributes(attributes(fields))
                measure("sentinel.feed.outcomes", **fields)
                measure("sentinel.feed.duration", time.monotonic() - started, **fields)
                event("feed_refresh_completed", duration_ms=(time.monotonic() - started) * 1000, **fields)
    return wrapped


class RequestTelemetry:
    """Pure ASGI wrapper: never reads payloads, cookies, query strings or raw paths."""
    def __init__(self, app, routes):
        global _routes
        self.app = app
        self.routes = routes
        _routes = frozenset(route.path for route in routes)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        method = bounded(scope.get("method"), DIMENSIONS["http.request.method"], "_OTHER")
        # Only W3C traceparent, never baggage/tracestate or other headers.
        carrier = {"traceparent": v.decode("ascii", errors="ignore") for k, v in scope.get("headers", [])
                   if k == b"traceparent" and len(v) == 55}
        context = TraceContextTextMapPropagator().extract(carrier)
        started, status_code = time.monotonic(), 500
        async def tracked_send(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)
        with span("HTTP", context=context, kind=trace.SpanKind.SERVER) as current:
            try:
                await self.app(scope, receive, tracked_send)
            finally:
                route = getattr(scope.get("route"), "path", "unmatched")
                fields = attributes({"http.request.method": method, "http.route": route,
                    "url.scheme": scope.get("scheme"),
                    "http.response.status_code": status_code, "status_class": f"{status_code // 100}xx"})
                if status_code >= 500:
                    fields["error.type"] = "unexpected"
                current.update_name(f"{method} {fields['http.route']}")
                current.set_attributes(fields)
                if status_code >= 500:
                    current.set_status(trace.StatusCode.ERROR)
                    current.set_attribute("error.type", "unexpected")
                measure("sentinel.http.requests", **fields)
                measure("http.server.request.duration", time.monotonic() - started, **fields)

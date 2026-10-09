import asyncio
import hashlib
import time
from app import telemetry
from typing import Any, Optional


class TTLCache:
    """Small bounded in-process cache used only to prevent duplicate provider spend."""

    def __init__(self, max_entries: int = 512, ttl_seconds: int = 600, provider: str = "unknown"):
        self.provider = telemetry.bounded(provider, telemetry.PROVIDERS)
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._items.get(key)
            if not item:
                telemetry.measure("sentinel.cache.accesses", provider=self.provider, **{"cache.result": "miss"})
                return None
            expires_at, value = item
            if expires_at <= time.monotonic():
                self._items.pop(key, None)
                telemetry.measure("sentinel.cache.accesses", provider=self.provider, **{"cache.result": "miss"})
                telemetry.measure("sentinel.cache.removals", provider=self.provider, **{"cache.result": "expired"})
                return None
            telemetry.measure("sentinel.cache.accesses", provider=self.provider, **{"cache.result": "hit"})
            return value

    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        if ttl_seconds is not None and ttl_seconds <= 0:
            async with self._lock:
                self._items.pop(key, None)
            return

        async with self._lock:
            now = time.monotonic()
            effective_ttl = ttl_seconds if (ttl_seconds is not None and ttl_seconds > 0) else self.ttl_seconds
            expired = [k for k, (expires, _) in self._items.items() if expires <= now]
            if expired:
                telemetry.measure("sentinel.cache.removals", len(expired), provider=self.provider, **{"cache.result": "expired"})
            for k in expired:
                self._items.pop(k, None)
            while len(self._items) >= self.max_entries:
                self._items.pop(next(iter(self._items)))
                telemetry.measure("sentinel.cache.removals", provider=self.provider, **{"cache.result": "evicted"})
            self._items[key] = (now + effective_ttl, value)

    def clear(self) -> None:
        self._items.clear()


def stable_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{namespace}:{digest}"


llm_cache = TTLCache(provider="gemini", max_entries=256, ttl_seconds=600)
virustotal_cache = TTLCache(provider="virustotal", max_entries=512, ttl_seconds=600)
urlhaus_cache = TTLCache(provider="urlhaus", max_entries=512, ttl_seconds=600)
webrisk_cache = TTLCache(provider="webrisk", max_entries=512, ttl_seconds=600)

# Prevent an attacker from creating an unbounded burst of paid/limited provider calls.
llm_semaphore = asyncio.Semaphore(4)
virustotal_semaphore = asyncio.Semaphore(4)
urlhaus_semaphore = asyncio.Semaphore(8)
webrisk_semaphore = asyncio.Semaphore(4)
threat_feed_semaphore = asyncio.Semaphore(2)


class ProviderQueueExhaustedError(Exception):
    """Raised when provider capacity cannot be acquired within the bounded queue wait timeout."""
    pass


async def _run_bounded(
    coro_or_factory,
    semaphore: asyncio.Semaphore,
    timeout_seconds: float = 6.0,
    acquire_timeout_seconds: float = 2.0,
) -> Any:
    """
    Run one provider operation with a concurrency cap, bounded queue wait, and hard timeout.

    Queue wait is bounded independently from the operation execution timeout.
    """
    queue_started = time.monotonic()
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=acquire_timeout_seconds)
    except asyncio.TimeoutError:
        if asyncio.iscoroutine(coro_or_factory):
            coro_or_factory.close()
        raise ProviderQueueExhaustedError("Provider capacity wait timeout exceeded.")
    finally:
        telemetry.measure("sentinel.provider.queue_wait", time.monotonic() - queue_started,
                          provider=_provider_name(semaphore))

    execution_started = time.monotonic()
    try:
        if asyncio.iscoroutine(coro_or_factory):
            return await asyncio.wait_for(coro_or_factory, timeout=timeout_seconds)
        elif callable(coro_or_factory):
            res = coro_or_factory()
            if asyncio.iscoroutine(res):
                return await asyncio.wait_for(res, timeout=timeout_seconds)
            return res
        else:
            raise TypeError("coro_or_factory must be a coroutine or callable returning a coroutine")
    finally:
        semaphore.release()
        telemetry.measure("sentinel.provider.execution.duration", time.monotonic() - execution_started,
                          provider=_provider_name(semaphore))


def _provider_name(semaphore):
    return {id(llm_semaphore): "gemini", id(virustotal_semaphore): "virustotal",
            id(urlhaus_semaphore): "urlhaus", id(webrisk_semaphore): "webrisk",
            id(threat_feed_semaphore): "threat_feed"}.get(id(semaphore), "unknown")


async def run_bounded(coro_or_factory, semaphore, timeout_seconds=6.0, acquire_timeout_seconds=2.0):
    provider = _provider_name(semaphore)
    started, outcome = time.monotonic(), "error"
    with telemetry.span("provider.lookup", provider=provider) as current:
        try:
            result = await _run_bounded(coro_or_factory, semaphore, timeout_seconds, acquire_timeout_seconds)
            outcome = telemetry.bounded(result.get("status") if isinstance(result, dict) else "success",
                                        telemetry.OUTCOMES, "error")
            return result
        except ProviderQueueExhaustedError:
            outcome = "queue_exhausted"
            raise
        except asyncio.TimeoutError:
            outcome = "timeout"
            raise
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        finally:
            current.set_attribute("outcome", outcome)
            telemetry.provider_result(provider, outcome, started)

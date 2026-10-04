import asyncio
import hashlib
import time
from typing import Any, Optional


class TTLCache:
    """Small bounded in-process cache used only to prevent duplicate provider spend."""

    def __init__(self, max_entries: int = 512, ttl_seconds: int = 600):
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            item = self._items.get(key)
            if not item:
                return None
            expires_at, value = item
            if expires_at <= time.monotonic():
                self._items.pop(key, None)
                return None
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
            for k in expired:
                self._items.pop(k, None)
            while len(self._items) >= self.max_entries:
                self._items.pop(next(iter(self._items)))
            self._items[key] = (now + effective_ttl, value)

    def clear(self) -> None:
        self._items.clear()


def stable_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{namespace}:{digest}"


llm_cache = TTLCache(max_entries=256, ttl_seconds=600)
virustotal_cache = TTLCache(max_entries=512, ttl_seconds=600)
urlhaus_cache = TTLCache(max_entries=512, ttl_seconds=600)
webrisk_cache = TTLCache(max_entries=512, ttl_seconds=600)

# Prevent an attacker from creating an unbounded burst of paid/limited provider calls.
llm_semaphore = asyncio.Semaphore(4)
virustotal_semaphore = asyncio.Semaphore(4)
urlhaus_semaphore = asyncio.Semaphore(8)
webrisk_semaphore = asyncio.Semaphore(4)


class ProviderQueueExhaustedError(Exception):
    """Raised when provider capacity cannot be acquired within the bounded queue wait timeout."""
    pass


async def run_bounded(
    coro_or_factory,
    semaphore: asyncio.Semaphore,
    timeout_seconds: float = 6.0,
    acquire_timeout_seconds: float = 2.0,
) -> Any:
    """
    Run one provider operation with a concurrency cap, bounded queue wait, and hard timeout.

    Queue wait is bounded independently from the operation execution timeout.
    """
    try:
        await asyncio.wait_for(semaphore.acquire(), timeout=acquire_timeout_seconds)
    except asyncio.TimeoutError:
        if asyncio.iscoroutine(coro_or_factory):
            coro_or_factory.close()
        raise ProviderQueueExhaustedError("Provider capacity wait timeout exceeded.")

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

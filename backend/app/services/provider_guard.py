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

    async def set(self, key: str, value: Any) -> None:
        async with self._lock:
            now = time.monotonic()
            expired = [k for k, (expires, _) in self._items.items() if expires <= now]
            for k in expired:
                self._items.pop(k, None)
            while len(self._items) >= self.max_entries:
                self._items.pop(next(iter(self._items)))
            self._items[key] = (now + self.ttl_seconds, value)


def stable_key(namespace: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return f"{namespace}:{digest}"


llm_cache = TTLCache(max_entries=256, ttl_seconds=600)
virustotal_cache = TTLCache(max_entries=512, ttl_seconds=600)
urlhaus_cache = TTLCache(max_entries=512, ttl_seconds=600)

# Prevent an attacker from creating an unbounded burst of paid/limited provider calls.
llm_semaphore = asyncio.Semaphore(4)
virustotal_semaphore = asyncio.Semaphore(4)
urlhaus_semaphore = asyncio.Semaphore(8)

from asyncio import Lock
from collections import defaultdict
import time

from authshield._shared.rate_limiter import RateLimiter


class InMemoryRateLimiter(RateLimiter):
    """Simple in-memory rate limiter. Suitable for single-worker deployments."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
        

    async def _cleanup(self, key: str) -> None:
        cutoff = time.monotonic() - self.window_seconds
        self._attempts[key] = [t for t in self._attempts[key] if t > cutoff]
        if not self._attempts[key]:
            del self._attempts[key]

    async def record_failure(self, key: str) -> None:
        async with self._lock:
            self._attempts[key].append(time.monotonic())

    async def is_blocked(self, key: str) -> bool:
        async with self._lock:
            await self._cleanup(key)
            return len(self._attempts.get(key, [])) >= self.max_attempts

    async def reset(self, key: str) -> None:
        async with self._lock:
            self._attempts.pop(key, None)
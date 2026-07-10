from abc import ABC, abstractmethod

class RateLimiter(ABC):

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    @abstractmethod
    async def _cleanup(self, key: str) -> None:
        pass

    @abstractmethod
    async def record_failure(self, key: str) -> None:
        pass

    @abstractmethod
    async def is_blocked(self, key: str) -> bool:
        pass
    
    @abstractmethod
    async def reset(self, key: str) -> None:
        pass
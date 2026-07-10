"""In-memory session storage implementation.

Stores sessions in a plain Python dictionary.  Suitable **only** for
single-worker development or testing environments -- sessions are not
shared across processes and are lost on restart.
"""

from typing import Optional

from authshield.auth.models import UserSession
from authshield.session.base import SessionStorage


class InMemorySessionStorage(SessionStorage):
    """Dictionary-backed session store.

    .. warning::

        This implementation keeps all sessions in process memory.
        It **must not** be used with multiple workers (e.g. via
        ``uvicorn --workers N``) because each worker maintains its
        own isolated dict.  Pick
        :class:`~authshield.session.base.SessionStorage` backed by
        Redis, a database, or another shared store for production
        deployments with more than one worker.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, UserSession] = {}

    async def create(self, session: UserSession) -> None:
        self._sessions[session.session_token] = session

    async def get(self, session_token: str) -> Optional[UserSession]:
        return self._sessions.get(session_token)

    async def delete(self, session_token: str) -> None:
        self._sessions.pop(session_token, None)

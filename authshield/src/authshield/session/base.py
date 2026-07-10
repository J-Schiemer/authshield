"""Abstract base class for session storage backends.

Defines the async interface that concrete session stores must implement.
When provided via :attr:`~authshield.config.AuthConfig.session_storage`,
the auth layer automatically wires session persistence into authentication
and logout flows.
"""

from abc import ABC, abstractmethod
from typing import Optional

from authshield.auth.models import UserSession


class SessionStorage(ABC):
    """Abstract interface for server-side session persistence.

    Subclass this to integrate a custom session store (Redis, database,
    etc.).  The default :class:`~authshield.session.InMemorySessionStorage`
    works for single-worker development deployments.
    """

    @abstractmethod
    async def create(self, session: UserSession) -> None:
        """Persist a newly created session.

        Parameters
        ----------
        session : UserSession
            The session to store.  Called immediately after authentication
            succeeds so the token can be resolved on subsequent requests.
        """

    @abstractmethod
    async def get(self, session_token: str) -> Optional[UserSession]:
        """Look up a session by its token.

        Parameters
        ----------
        session_token : str
            The opaque token from the session cookie.

        Returns
        -------
        Optional[UserSession]
            The stored session, or ``None`` when the token is unknown or
            has been evicted.
        """

    @abstractmethod
    async def delete(self, session_token: str) -> None:
        """Remove a session (logout).

        Parameters
        ----------
        session_token : str
            The token of the session to revoke.
        """

"""Session management sub-package.

Provides the :class:`SessionStorage` abstract interface and the default
:class:`InMemorySessionStorage` implementation.
"""

from authshield.session.base import SessionStorage
from authshield.session._in_memory_session_storage import InMemorySessionStorage

__all__ = [
    "SessionStorage",
    "InMemorySessionStorage",
]

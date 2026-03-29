"""Unified context management for Stihia SDK.

Entity hierarchy::

    Process (agent)
    └── Thread (conversation)
        └── Run (single agent invocation)
            └── Operation (one sense API call)

``StihiaContext`` sets ``process_key``, ``thread_key``, and ``run_key``
as ``contextvars`` so that ``StihiaClient`` resolves them automatically
without explicit arguments on every call.
"""

from contextvars import ContextVar
from uuid import uuid4

_current_process_key: ContextVar[str | None] = ContextVar(
    "stihia_process_key", default=None
)
_current_thread_key: ContextVar[str | None] = ContextVar(
    "stihia_thread_key", default=None
)
_current_run_key: ContextVar[str | None] = ContextVar("stihia_run_key", default=None)


class StihiaContext:
    """Context manager that propagates tracing keys via ``contextvars``.

    One ``StihiaContext`` represents a single **run** within a **thread**.
    ``thread_key`` and ``run_key`` are auto-generated as UUIDs when omitted.

    Works with both sync and async code::

        # Sync
        with StihiaContext(process_key="onboarding", thread_key="conv-1") as ctx:
            print(ctx.run_key)           # auto-generated UUID
            client.sense(messages, ...)  # keys resolved automatically

        # Async
        async with StihiaContext(thread_key="conv-1") as ctx:
            await client.asense(messages, ...)

    Args:
        process_key: The key of the process (e.g., agent) that is being observed.
        thread_key: Conversation identifier. Auto-generated UUID if omitted.
        run_key: Agent invocation identifier. Auto-generated UUID if omitted.
    """

    def __init__(
        self,
        *,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> None:
        """Initialize context. See class docstring for Args."""
        self.process_key = process_key
        self.thread_key = thread_key or str(uuid4())
        self.run_key = run_key or str(uuid4())
        self._process_token = None
        self._thread_token = None
        self._run_token = None

    def __enter__(self) -> "StihiaContext":
        """Enter context and set run_key, process_key, and thread_key."""
        if self.process_key:
            self._process_token = _current_process_key.set(self.process_key)
        if self.thread_key:
            self._thread_token = _current_thread_key.set(self.thread_key)
        self._run_token = _current_run_key.set(self.run_key)
        return self

    def __exit__(self, *args) -> None:
        """Exit context and restore previous values."""
        if self._process_token:
            _current_process_key.reset(self._process_token)
        if self._thread_token:
            _current_thread_key.reset(self._thread_token)
        if self._run_token:
            _current_run_key.reset(self._run_token)

    async def __aenter__(self) -> "StihiaContext":
        """Async enter context."""
        return self.__enter__()

    async def __aexit__(self, *args) -> None:
        """Async exit context."""
        self.__exit__(*args)


def get_current_run_key() -> str | None:
    """Get the current run_key from context, if set.

    Returns:
        Current run_key if within StihiaContext, None otherwise.
    """
    return _current_run_key.get()


def get_current_process_key() -> str | None:
    """Get the current process_key from context, if set.

    Returns:
        Current process_key if within StihiaContext, None otherwise.
    """
    return _current_process_key.get()


def get_current_thread_key() -> str | None:
    """Get the current thread_key from context, if set.

    Returns:
        Current thread_key if within StihiaContext, None otherwise.
    """
    return _current_thread_key.get()

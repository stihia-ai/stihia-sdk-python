"""Stihia API client.

Key resolution priority for ``thread_key``, ``process_key``, etc.:
explicit argument → ``StihiaContext`` (context var) → client default → ``ValueError``.
"""

import asyncio
import logging
import os
from collections.abc import Callable
from typing import Any, overload

import httpx

from stihia.background import BackgroundTaskManager
from stihia.context import (
    get_current_process_key,
    get_current_run_key,
    get_current_thread_key,
)
from stihia.exceptions import StihiaAPIError
from stihia.models import Message, SenseOperation, SenseRequest

logger = logging.getLogger(__name__)


class StihiaClient:
    """Stihia API client for real-time threat detection for AI systems.

    Supports three execution modes:

    1. **Sync blocking** — ``sense()``
    2. **Async blocking** — ``asense()``
    3. **Background (fire-and-forget)** — ``sense_background()``

    Use as a context manager to ensure resources are cleaned up::

        with StihiaClient(api_key="sk-...") as client:
            op = client.sense(
                messages=[{"role": "user", "content": "hi"}],
                sensor="prompt-injection",
                project_key="proj", user_key="u1",
                process_key="p1", thread_key="t1", run_key="r1",
            )
            severity = op.payload.sense_result.aggregated_signal.payload.severity

    Or async::

        async with StihiaClient(api_key="sk-...") as client:
            op = await client.asense(...)
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.stihia.ai",
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        timeout: float = 30.0,
        max_background_workers: int = 4,
    ):
        """Initialize Stihia client.

        Supports both sync (``with``) and async (``async with``) context
        managers for automatic resource cleanup.

        Args:
            api_key: Stihia API key (or set ``STIHIA_API_KEY`` env var).
            base_url: Base URL for Stihia API.
            project_key: Default project key (can be overridden per request).
            user_key: Default user key (can be overridden per request).
            process_key: Default process key (can be overridden per request).
            thread_key: Default thread key (can be overridden per request).
            timeout: Request timeout in seconds.
            max_background_workers: Max worker threads for background tasks.

        Raises:
            ValueError: If api_key is not provided and STIHIA_API_KEY is not set.
        """
        resolved_api_key = api_key or os.environ.get("STIHIA_API_KEY")
        if not resolved_api_key:
            raise ValueError(
                "api_key is required. Provide it directly or "
                "set STIHIA_API_KEY env var."
            )
        self.api_key = resolved_api_key
        self.base_url = base_url.rstrip("/")
        self.project_key = project_key
        self.user_key = user_key
        self.process_key = process_key
        self.thread_key = thread_key
        self.timeout = timeout

        self._sync_client = httpx.Client(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._get_headers(),
        )
        self._async_client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._get_headers(),
        )
        self._background_manager = BackgroundTaskManager(
            max_workers=max_background_workers
        )

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for requests."""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _prepare_request_data(
        self,
        messages: list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any],
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> dict[str, Any]:
        """Prepare request data for sense API.

        Resolves keys via chain: explicit → StihiaContext → client default → ValueError.

        Args:
            messages: Messages to analyze.
            sensor: Sensor configuration (preset name or config dict).
            project_key: Project key (overrides default).
            user_key: User key (overrides default).
            process_key: Process key (explicit > context > client default).
            thread_key: Thread key (explicit > context > client default > error).
            run_key: Run key for tracing (explicit > context > error).

        Returns:
            Request data dict.

        Raises:
            ValueError: If required keys are missing.
        """
        # Use provided keys or fall back to defaults
        final_project_key = project_key or self.project_key
        final_user_key = user_key or self.user_key
        # process_key resolution: explicit > context > client default > error
        final_process_key = process_key or get_current_process_key() or self.process_key
        # thread_key resolution: explicit > context > client default > error
        final_thread_key = thread_key or get_current_thread_key() or self.thread_key
        # run_key resolution: explicit > context > error
        final_run_key = run_key or get_current_run_key()

        if not final_project_key:
            raise ValueError(
                "project_key is required (provide in constructor or method)"
            )
        if not final_user_key:
            raise ValueError("user_key is required (provide in constructor or method)")
        if not final_process_key:
            raise ValueError(
                "process_key is required (provide in constructor or method)"
            )
        if not final_thread_key:
            raise ValueError(
                "thread_key is required "
                "(provide in constructor, method, or StihiaContext)"
            )
        if not final_run_key:
            raise ValueError("run_key is required (provide in method or StihiaContext)")

        # Convert Message objects to dicts if needed
        messages_data = []
        for msg in messages:
            if isinstance(msg, Message):
                messages_data.append({"role": msg.role, "content": msg.content})
            else:
                messages_data.append(msg)

        return {
            "project_key": final_project_key,
            "user_key": final_user_key,
            "process_key": final_process_key,
            "thread_key": final_thread_key,
            "run_key": final_run_key,
            "sensor": sensor,
            "messages": messages_data,
        }

    @staticmethod
    def _request_to_data(request: SenseRequest) -> dict[str, Any]:
        """Convert a ``SenseRequest`` to a wire-format dict.

        Strips server-set optional ``*_uid`` fields (None values).
        """
        return request.model_dump(exclude_none=True)

    def build_sense_request(
        self,
        messages: list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any],
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> SenseRequest:
        """Build a ``SenseRequest`` with full key resolution.

        Same key resolution as ``sense()`` (explicit → context → default → error),
        but returns the validated model instead of sending it. Useful for
        inspecting or reusing the request across multiple calls.

        Args:
            messages: Messages to analyze.
            sensor: Sensor configuration (preset name or config dict).
            project_key: Project key (overrides default).
            user_key: User key (overrides default).
            process_key: Process key (explicit > context > client default).
            thread_key: Thread key (explicit > context > client default > error).
            run_key: Run key for tracing (explicit > context > error).

        Returns:
            Validated ``SenseRequest`` ready to pass to ``sense()``.

        Raises:
            ValueError: If required keys are missing.
        """
        data = self._prepare_request_data(
            messages=messages,
            sensor=sensor,
            project_key=project_key,
            user_key=user_key,
            process_key=process_key,
            thread_key=thread_key,
            run_key=run_key,
        )
        return SenseRequest(**data)

    def _send_sense_sync(self, request_data: dict[str, Any]) -> SenseOperation:
        """Send a sync sense request and handle errors.

        Args:
            request_data: Validated request payload dict.

        Returns:
            Parsed ``SenseOperation``.

        Raises:
            StihiaAPIError: On HTTP or connection errors.
        """
        try:
            response = self._sync_client.post("/v1/sense", json=request_data)
            response.raise_for_status()
            return SenseOperation(**response.json())
        except httpx.HTTPStatusError as e:
            detail = e.response.text
            try:
                error_data = e.response.json()
                detail = error_data.get("detail", detail)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            raise StihiaAPIError(e.response.status_code, detail) from e
        except httpx.RequestError as e:
            detail = str(e) or repr(e)
            raise StihiaAPIError(
                0, f"Request error ({type(e).__name__}): {detail}"
            ) from e

    async def _send_sense_async(self, request_data: dict[str, Any]) -> SenseOperation:
        """Send an async sense request and handle errors.

        Args:
            request_data: Validated request payload dict.

        Returns:
            Parsed ``SenseOperation``.

        Raises:
            StihiaAPIError: On HTTP or connection errors.
        """
        try:
            response = await self._async_client.post("/v1/sense", json=request_data)
            response.raise_for_status()
            return SenseOperation(**response.json())
        except httpx.HTTPStatusError as e:
            detail = e.response.text
            try:
                error_data = e.response.json()
                detail = error_data.get("detail", detail)
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            raise StihiaAPIError(e.response.status_code, detail) from e
        except httpx.RequestError as e:
            detail = str(e) or repr(e)
            raise StihiaAPIError(
                0, f"Request error ({type(e).__name__}): {detail}"
            ) from e

    # -- sense() ---------------------------------------------------------------

    @overload
    def sense(self, request: SenseRequest, /) -> SenseOperation: ...

    @overload
    def sense(
        self,
        messages: list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any],
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> SenseOperation: ...

    def sense(  # type: ignore[overload-overlap]
        self,
        messages: SenseRequest | list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any] | None = None,
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> SenseOperation:
        """Sync blocking sense call — waits for result.

        Can be called two ways:

        1. **Pre-built request** (bypasses key resolution)::

            req = SenseRequest(project_key="p", user_key="u", ...)
            op = client.sense(req)

        2. **Individual arguments** (existing behavior, resolves keys)::

            op = client.sense(messages=[...], sensor="prompt-injection", run_key="r1")

        Args:
            messages: A ``SenseRequest`` or messages list (see overloads).
            sensor: Sensor config (required when passing messages, ignored for request).
            project_key: Project key (overrides default).
            user_key: User key (overrides default).
            process_key: Process key (overrides default).
            thread_key: Thread key (overrides default).
            run_key: Run key for tracing (explicit > context > error).

        Returns:
            SenseOperation with results.

        Raises:
            StihiaAPIError: If API returns an error.
            ValueError: If required parameters are missing.
        """
        if isinstance(messages, SenseRequest):
            return self._send_sense_sync(self._request_to_data(messages))

        if sensor is None:
            raise ValueError("sensor is required when passing messages directly")

        request_data = self._prepare_request_data(
            messages=messages,
            sensor=sensor,
            project_key=project_key,
            user_key=user_key,
            process_key=process_key,
            thread_key=thread_key,
            run_key=run_key,
        )
        return self._send_sense_sync(request_data)

    # -- asense() --------------------------------------------------------------

    @overload
    async def asense(self, request: SenseRequest, /) -> SenseOperation: ...

    @overload
    async def asense(
        self,
        messages: list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any],
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> SenseOperation: ...

    async def asense(  # type: ignore[overload-overlap]
        self,
        messages: SenseRequest | list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any] | None = None,
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> SenseOperation:
        """Async blocking sense call — awaits result.

        Can be called two ways:

        1. **Pre-built request** (bypasses key resolution)::

            req = SenseRequest(project_key="p", user_key="u", ...)
            op = await client.asense(req)

        2. **Individual arguments** (existing behavior, resolves keys)::

            op = await client.asense(messages=[...], sensor="prompt-injection", ...)

        Args:
            messages: A ``SenseRequest`` or messages list (see overloads).
            sensor: Sensor config (required when passing messages, ignored for request).
            project_key: Project key (overrides default).
            user_key: User key (overrides default).
            process_key: Process key (overrides default).
            thread_key: Thread key (explicit > context > client default > error).
            run_key: Run key for tracing (explicit > context > error).

        Returns:
            SenseOperation with results.

        Raises:
            StihiaAPIError: If API returns an error.
            ValueError: If required parameters are missing.
        """
        if isinstance(messages, SenseRequest):
            return await self._send_sense_async(self._request_to_data(messages))

        if sensor is None:
            raise ValueError("sensor is required when passing messages directly")

        request_data = self._prepare_request_data(
            messages=messages,
            sensor=sensor,
            project_key=project_key,
            user_key=user_key,
            process_key=process_key,
            thread_key=thread_key,
            run_key=run_key,
        )
        return await self._send_sense_async(request_data)

    # -- sense_background() ----------------------------------------------------

    @overload
    def sense_background(
        self,
        request: SenseRequest,
        /,
        *,
        on_complete: Callable[[SenseOperation], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None: ...

    @overload
    def sense_background(
        self,
        messages: list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any],
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
        on_complete: Callable[[SenseOperation], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None: ...

    def sense_background(  # type: ignore[overload-overlap]
        self,
        messages: SenseRequest | list[dict[str, str]] | list[Message],
        sensor: str | dict[str, Any] | None = None,
        *,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
        on_complete: Callable[[SenseOperation], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        """Fire-and-forget sense call — no latency impact.

        Can be called two ways:

        1. **Pre-built request** (bypasses key resolution)::

            req = SenseRequest(project_key="p", user_key="u", ...)
            client.sense_background(req, on_complete=callback)

        2. **Individual arguments** (existing behavior, resolves keys)::

            client.sense_background(messages=[...], sensor="default", run_key="r1")

        Args:
            messages: A ``SenseRequest`` or messages list (see overloads).
            sensor: Sensor config (required when passing messages, ignored for request).
            project_key: Project key (overrides default).
            user_key: User key (overrides default).
            process_key: Process key (overrides default).
            thread_key: Thread key (explicit > context > client default > error).
            run_key: Run key for tracing (explicit > context > error).
            on_complete: Optional callback on successful completion.
            on_error: Optional callback on error.
        """
        if isinstance(messages, SenseRequest):
            request_data = self._request_to_data(messages)
        else:
            if sensor is None:
                raise ValueError("sensor is required when passing messages directly")
            request_data = self._prepare_request_data(
                messages=messages,
                sensor=sensor,
                project_key=project_key,
                user_key=user_key,
                process_key=process_key,
                thread_key=thread_key,
                run_key=run_key,
            )

        try:
            # Check if we're in an async context with a running event loop
            loop = asyncio.get_running_loop()  # noqa: F841
            # We have a running loop — use async client via create_task
            coro = self._send_sense_async(request_data)
            self._background_manager.submit(coro, on_complete, on_error)
        except RuntimeError:
            # No running loop (sync context) — use sync callable in thread
            self._background_manager.submit_sync(
                lambda: self._send_sense_sync(request_data),
                on_complete,
                on_error,
            )

    def close(self) -> None:
        """Close the client and cleanup resources (sync)."""
        self._sync_client.close()
        self._background_manager.shutdown()

    async def aclose(self) -> None:
        """Close the client and cleanup resources (async)."""
        await self._async_client.aclose()
        await self._background_manager.ashutdown()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.aclose()

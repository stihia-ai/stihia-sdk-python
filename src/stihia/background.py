"""Background task manager for fire-and-forget execution."""

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import Any

logger = logging.getLogger(__name__)


class BackgroundTaskManager:
    """Manages background task execution without blocking.

    Handles fire-and-forget execution in both async and sync contexts.
    In async contexts, uses asyncio.create_task().
    In sync contexts, uses ThreadPoolExecutor.
    """

    def __init__(self, max_workers: int = 4):
        """Initialize the background task manager.

        Args:
            max_workers: Maximum number of worker threads for sync contexts
        """
        self._pending_tasks: set[asyncio.Task] = set()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._shutdown = False

    def submit(
        self,
        coro: Coroutine[Any, Any, Any],
        on_complete: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        """Submit coroutine for background execution in async context.

        This method should only be called when a running event loop exists.
        For sync contexts, use submit_sync() instead.

        Args:
            coro: Coroutine to execute
            on_complete: Optional callback on successful completion
            on_error: Optional callback on error
        """
        if self._shutdown:
            logger.warning(
                "BackgroundTaskManager is shut down, ignoring task submission"
            )
            coro.close()  # Properly clean up the coroutine
            return

        try:
            # Try to get the running event loop (async context)
            loop = asyncio.get_running_loop()
            task = loop.create_task(self._awrapped_coro(coro, on_complete, on_error))
            self._pending_tasks.add(task)
            task.add_done_callback(self._pending_tasks.discard)
        except RuntimeError:
            # Fallback: run in thread (less ideal due to event loop issues)
            self._executor.submit(self._run_in_thread, coro, on_complete, on_error)

    def submit_sync(
        self,
        func: Callable[[], Any],
        on_complete: Callable[[Any], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        """Submit sync callable for background execution in thread.

        Use this method when calling from a sync context to avoid
        event loop issues with async clients.

        Args:
            func: Sync callable to execute
            on_complete: Optional callback on successful completion
            on_error: Optional callback on error
        """
        if self._shutdown:
            logger.warning(
                "BackgroundTaskManager is shut down, ignoring task submission"
            )
            return

        self._executor.submit(self._run_sync_in_thread, func, on_complete, on_error)

    def _run_sync_in_thread(
        self,
        func: Callable[[], Any],
        on_complete: Callable[[Any], None] | None,
        on_error: Callable[[Exception], None] | None,
    ) -> None:
        """Run sync callable in a thread.

        Args:
            func: Sync callable to execute
            on_complete: Optional callback on successful completion
            on_error: Optional callback on error
        """
        try:
            result = func()
            if on_complete:
                try:
                    on_complete(result)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.exception("Error in on_complete callback: %s", e)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.exception("Error in background task (sync thread): %s", e)
            if on_error:
                try:
                    on_error(e)
                except (
                    Exception  # pylint: disable=broad-exception-caught
                ) as callback_error:
                    logger.exception("Error in on_error callback: %s", callback_error)

    async def _awrapped_coro(
        self,
        coro: Coroutine[Any, Any, Any],
        on_complete: Callable[[Any], None] | None,
        on_error: Callable[[Exception], None] | None,
    ) -> None:
        """Wrap coroutine with completion and error handlers.

        Args:
            coro: Coroutine to execute
            on_complete: Optional callback on successful completion
            on_error: Optional callback on error
        """
        try:
            result = await coro
            if on_complete:
                try:
                    on_complete(result)
                except Exception as e:  # pylint: disable=broad-exception-caught
                    logger.exception("Error in on_complete callback: %s", e)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.exception("Error in background task: %s", e)
            if on_error:
                try:
                    on_error(e)
                except (
                    Exception  # pylint: disable=broad-exception-caught
                ) as callback_error:
                    logger.exception("Error in on_error callback: %s", callback_error)

    def _run_in_thread(
        self,
        coro: Coroutine[Any, Any, Any],
        on_complete: Callable[[Any], None] | None,
        on_error: Callable[[Exception], None] | None,
    ) -> None:
        """Run coroutine in a thread with new event loop.

        Args:
            coro: Coroutine to execute
            on_complete: Optional callback on successful completion
            on_error: Optional callback on error
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(coro)
                if on_complete:
                    try:
                        on_complete(result)
                    except Exception as e:  # pylint: disable=broad-exception-caught
                        logger.exception("Error in on_complete callback: %s", e)
            finally:
                loop.close()
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.exception("Error in background task (thread): %s", e)
            if on_error:
                try:
                    on_error(e)
                except (
                    Exception  # pylint: disable=broad-exception-caught
                ) as callback_error:
                    logger.exception("Error in on_error callback: %s", callback_error)

    async def ashutdown(self, timeout: float = 5.0) -> None:
        """Async graceful shutdown - wait for pending tasks.

        Args:
            timeout: Maximum time to wait for pending tasks in seconds
        """
        self._shutdown = True

        if not self._pending_tasks:
            return

        logger.info(
            "Waiting for %d pending background tasks (timeout: %ss)",
            len(self._pending_tasks),
            timeout,
        )

        try:
            await asyncio.wait_for(
                asyncio.gather(*self._pending_tasks, return_exceptions=True),
                timeout=timeout,
            )
        except TimeoutError:
            logger.warning(
                "Timeout waiting for background tasks, %d tasks still pending",
                len(self._pending_tasks),
            )

    def shutdown(self, timeout: float = 5.0) -> None:
        """Sync shutdown for non-async contexts.

        Args:
            timeout: Maximum time to wait for executor shutdown in seconds
        """
        self._shutdown = True
        self._executor.shutdown(wait=False, cancel_futures=False)

        # Wait for pending tasks with timeout
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            if not self._pending_tasks:
                break
            time.sleep(0.1)

        logger.info("BackgroundTaskManager shut down")

    def __del__(self):
        """Cleanup on deletion."""
        if not self._shutdown:
            try:
                self.shutdown(timeout=1.0)
            except Exception:  # pylint: disable=broad-exception-caught
                pass

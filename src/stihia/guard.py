"""SenseGuard — guardrail wrapper for async streams.

Runs input and output security checks concurrently with an async LLM stream.
The input check starts immediately when ``shield()`` is called and must
complete before the first chunk is yielded ("gate first chunk").

Output checking supports two modes controlled by ``output_check_mode``:

* **blocking** (default) — periodic output sense API calls **pause** chunk
  delivery until a green light is received. While the API call is in-flight,
  the underlying LLM stream continues reading into a buffer. On a green
  light, buffered chunks are burst-released. On a threat, the stream
  terminates immediately. When ``output_check_interval`` is ``None``, all
  chunks are buffered internally and only released after the final
  post-stream check passes. After the stream completes, a final blocking
  check runs on the full accumulated text.

* **parallel** — periodic output sense API calls run concurrently (fire-and-
  forget) without pausing chunk delivery. Chunks flow to the caller
  immediately. After the stream completes, pending periodic results are
  collected and a final blocking check runs. If any check (periodic or
  final) detected a threat, the exception is raised post-stream.

Supports ``fail_open=False`` for fail-closed mode (block on API errors),
``input_timeout`` to prevent indefinite blocking, and ``on_trigger`` callback
for observability hooks.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import TYPE_CHECKING, Any, Literal

from stihia.exceptions import StihiaError, StihiaThreatDetectedError
from stihia.models import SignalSeverity

if TYPE_CHECKING:
    from collections.abc import AsyncIterable, AsyncIterator, Callable

    from stihia.client import StihiaClient
    from stihia.models import Message, SenseOperation, SenseResult, SignalPayload
    from stihia.processors import PostProcessor

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[SignalSeverity, int] = {
    SignalSeverity.LOW: 0,
    SignalSeverity.MEDIUM: 1,
    SignalSeverity.HIGH: 2,
    SignalSeverity.CRITICAL: 3,
}


def _severity_meets_threshold(severity: SignalSeverity, threshold: SignalSeverity) -> bool:
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 0)


class SenseGuard:
    """Wraps an async stream and runs input/output sense checks concurrently.

    Both ``input_sensor`` and ``output_sensor`` are optional. When a sensor
    is ``None``, the corresponding API call is skipped entirely. This enables
    output-only guardrails, input-only guardrails, or passthrough mode (no
    sensors) where only ``post_processors`` are applied.

    When ``input_sensor`` is set, input messages are checked as soon as
    ``shield()`` is called. The first chunk is gated on the input check
    completing — no chunks are yielded until the input is validated. When
    ``input_sensor`` is ``None``, chunks flow immediately with no input gate.

    Output checks support two modes via ``output_check_mode``:

    * ``"blocking"`` (default) — periodic checks **pause** chunk delivery
      until the API responds. Buffered chunks are burst-released on green
      light. On a threat, the stream terminates immediately.
    * ``"parallel"`` — periodic checks run concurrently without pausing
      delivery. Chunks flow immediately. Results are collected after the
      stream, and threats raise post-stream.

    After the stream completes, a final output check runs on the full
    accumulated text. Remaining buffered chunks are withheld until the
    final check passes.

    After iteration completes (or raises), inspect ``input_triggered``,
    ``output_triggered``, and ``triggered`` to see what was detected.

    Args:
        client: ``StihiaClient`` instance.
        messages: Conversation history to check on the input side.
        input_sensor: Sensor for input check (preset name or config dict).
            ``None`` (default) disables input sensing — chunks flow with
            no input gate.
        output_sensor: Sensor for output check. ``None`` disables output
            sensing.
        output_check_interval: Number of output chunks between periodic
            output checks during streaming. For example, ``30`` fires a
            check every 30 chunks. Each check's behavior depends on
            ``output_check_mode``. ``None`` disables periodic checks —
            only the final post-stream check runs. In blocking mode with
            ``None``, all chunks are buffered and only released after the
            final check passes.
        output_check_mode: ``"blocking"`` (default) pauses chunk delivery
            during each periodic check. When ``output_check_interval`` is
            ``None``, all chunks are buffered internally and delivered only
            after the final post-stream check passes. ``"parallel"`` fires
            checks in the background without pausing. Both modes run a
            final blocking check after the stream completes.
        chunk_to_text: Converts a stream chunk to ``str``. Defaults to
            ``str()``.
        min_severity: Minimum severity that counts as "triggered".
        raise_on_trigger: If ``True``, raises
            ``StihiaThreatDetectedError`` when triggered mid-stream.
            If ``False``, stops yielding silently.
        fail_open: If ``False`` (default), API errors trigger blocking.
            If ``True``, API errors are logged but streaming continues.
        input_timeout: Timeout in seconds for the input gate. ``None``
            (default) means no timeout. On timeout, behavior follows
            ``fail_open``.
        on_trigger: Callback invoked when triggered, before raising or
            stopping. Receives ``source`` (``"input"``/``"output"``) and
            the triggering ``SenseOperation`` (``None`` on API error with
            ``fail_open=False``). Supports sync and async callables.
        post_processors: List of sync callables applied to each chunk
            before yielding. Processors run **after** text accumulation
            for output sensing, so sensors see raw model output. Applied
            left-to-right. ``None`` (default) means no post-processing.
        project_key: Overrides client default.
        user_key: Overrides client default.
        process_key: Overrides client default.
        thread_key: Overrides client default.
        run_key: Overrides context default.

    Examples::

        # 1. Input + output guardrails with periodic mid-stream checks
        guard = SenseGuard(
            client,
            messages=[{"role": "user", "content": user_input}],
            input_sensor="default-input",
            output_sensor="default-output",
            output_check_interval=30,  # check output every 30 chunks
            project_key="my-app",
            user_key="user-123",
        )
        try:
            async for chunk in guard.shield(llm.astream(prompt)):
                print(chunk, end="")
        except StihiaThreatDetectedError as exc:
            print(f"Blocked by {exc.source} guardrail")

        # 2. Final-only output check (buffers all, delivers after green light)
        guard = SenseGuard(
            client,
            messages=messages,
            input_sensor="default-input",
            output_sensor="default-output",
            output_check_interval=None,  # skip periodic, final only
            project_key="my-app",
            user_key="user-123",
        )
        try:
            async for chunk in guard.shield(llm.astream(prompt)):
                # chunks arrive only after final check passes
                print(chunk, end="")
        except StihiaThreatDetectedError as exc:
            print(f"Output blocked: {exc.source}")

        # 3. Input-only (no output sensing)
        guard = SenseGuard(
            client,
            messages=messages,
            input_sensor="default-input",
            project_key="my-app",
            user_key="user-123",
        )
        async for chunk in guard.shield(llm.astream(prompt)):
            print(chunk, end="")

        # 4. Output-only (no input sensing — chunks flow immediately)
        guard = SenseGuard(
            client,
            messages=messages,
            output_sensor="default-output",
            output_check_interval=30,
            project_key="my-app",
            user_key="user-123",
        )
        async for chunk in guard.shield(llm.astream(prompt)):
            print(chunk, end="")

        # 5. Passthrough (no sensors — only post-processors applied)
        guard = SenseGuard(
            client,
            messages=messages,
            post_processors=[strip_markdown_images],
            project_key="my-app",
            user_key="user-123",
        )
        async for chunk in guard.shield(llm.astream(prompt)):
            print(chunk, end="")

        # 6. Silent mode — stop yielding without raising
        guard = SenseGuard(
            client,
            messages=messages,
            input_sensor="default-input",
            output_sensor="default-output",
            raise_on_trigger=False,
            project_key="my-app",
            user_key="user-123",
        )
        async for chunk in guard.shield(llm.astream(prompt)):
            print(chunk, end="")
        # iteration stops early if triggered; check guard.triggered after

        # 7. Fail-closed mode — block on API errors
        guard = SenseGuard(
            client,
            messages=messages,
            input_sensor="default-input",
            fail_open=False,
            input_timeout=5.0,
            project_key="my-app",
            user_key="user-123",
        )

        # 8. Observability callback
        guard = SenseGuard(
            client,
            messages=messages,
            input_sensor="default-input",
            on_trigger=lambda src, op: log.warning("Triggered: %s", src),
            project_key="my-app",
            user_key="user-123",
        )
    """

    def __init__(
        self,
        client: StihiaClient,
        *,
        messages: list[dict[str, str]] | list[Message],
        input_sensor: str | dict[str, Any] | None = None,
        output_sensor: str | dict[str, Any] | None = None,
        output_check_interval: int | None = None,
        output_check_mode: Literal["blocking", "parallel"] = "blocking",
        chunk_to_text: Callable[[Any], str] | None = None,
        min_severity: SignalSeverity = SignalSeverity.HIGH,
        raise_on_trigger: bool = True,
        fail_open: bool = False,
        input_timeout: float | None = None,
        on_trigger: Callable[[str, SenseOperation | None], Any] | None = None,
        post_processors: list[PostProcessor] | None = None,
        project_key: str | None = None,
        user_key: str | None = None,
        process_key: str | None = None,
        thread_key: str | None = None,
        run_key: str | None = None,
    ) -> None:
        """Initialize SenseGuard. See class docstring for full Args."""
        self._client = client
        self._messages = messages
        self._input_sensor = input_sensor
        self._output_sensor = output_sensor
        self._output_check_interval = output_check_interval
        if output_check_mode not in ("blocking", "parallel"):
            raise ValueError(f"output_check_mode must be 'blocking' or 'parallel', got {output_check_mode!r}")
        self._output_check_mode = output_check_mode
        self._chunk_to_text = chunk_to_text or str
        self._min_severity = min_severity
        self._raise_on_trigger = raise_on_trigger
        self._fail_open = fail_open
        self._input_timeout = input_timeout
        self._on_trigger = on_trigger
        self._post_processors: list[PostProcessor] = post_processors or []
        self._sense_kwargs: dict[str, Any] = {
            "project_key": project_key,
            "user_key": user_key,
            "process_key": process_key,
            "thread_key": thread_key,
            "run_key": run_key,
        }

        self._shield_called = False

        # Input state
        self._input_triggered = False
        self._input_operation: SenseOperation | None = None
        self._input_result: SenseResult | None = None
        self._input_error: Exception | None = None

        # Output state
        self._output_triggered = False
        self._output_operation: SenseOperation | None = None
        self._output_result: SenseResult | None = None
        self._output_error: Exception | None = None
        self._output_operations: list[SenseOperation] = []

    # -- Input properties (renamed from old names) --

    @property
    def input_triggered(self) -> bool:
        """``True`` if input severity met ``min_severity`` threshold."""
        return self._input_triggered

    @property
    def input_operation(self) -> SenseOperation | None:
        """Full ``SenseOperation`` from the input check, or ``None``."""
        return self._input_operation

    @property
    def input_result(self) -> SenseResult | None:
        """Shortcut to ``input_operation.payload.sense_result``."""
        return self._input_result

    @property
    def input_error(self) -> Exception | None:
        """Exception from input sense call, if it failed."""
        return self._input_error

    # -- Output properties --

    @property
    def output_triggered(self) -> bool:
        """``True`` if any output check severity met ``min_severity``."""
        return self._output_triggered

    @property
    def output_operation(self) -> SenseOperation | None:
        """The output ``SenseOperation`` that triggered, or the final one."""
        return self._output_operation

    @property
    def output_result(self) -> SenseResult | None:
        """Shortcut to ``output_operation.payload.sense_result``."""
        return self._output_result

    @property
    def output_error(self) -> Exception | None:
        """Exception from an output sense call, if one failed."""
        return self._output_error

    @property
    def output_operations(self) -> list[SenseOperation]:
        """All output ``SenseOperation`` results (periodic + final).

        In final-only mode (``output_check_interval=None``), contains only the
        final check.
        """
        return list(self._output_operations)

    # -- Combined property --

    @property
    def triggered(self) -> bool:
        """``True`` if either input or output check triggered."""
        return self._input_triggered or self._output_triggered

    # -- Internal helpers --

    def _should_trigger(self, payload: SignalPayload) -> bool:
        """Centralized trigger evaluation for a signal payload."""
        return _severity_meets_threshold(payload.severity, self._min_severity)

    async def _fire_on_trigger(self, source: str, operation: SenseOperation | None) -> None:
        """Call the on_trigger callback if set."""
        if self._on_trigger is not None:
            result = self._on_trigger(source, operation)
            if asyncio.iscoroutine(result):
                await result

    def _apply_post_processors[T](self, chunk: T) -> T:
        """Apply all post-processors to *chunk* in order."""
        for processor in self._post_processors:
            chunk = processor(chunk)
        return chunk

    def _process_input_task(self, task: asyncio.Task[SenseOperation]) -> None:
        # If _input_error already set (e.g. timeout), skip task.result()
        if self._input_error is not None:
            if not self._fail_open:
                self._input_triggered = True
            return
        try:
            operation = task.result()
        except Exception as exc:
            logger.warning("Sense API error in SenseGuard (input): %s", exc)
            self._input_error = exc
            if not self._fail_open:
                self._input_triggered = True
            return

        self._input_operation = operation
        if operation.payload and operation.payload.sense_result:
            self._input_result = operation.payload.sense_result
            if self._should_trigger(operation.payload.sense_result.aggregated_signal.payload):
                self._input_triggered = True

    def _evaluate_output_operation(self, operation: SenseOperation) -> bool:
        """Evaluate an output operation. Returns True if triggered."""
        self._output_operations.append(operation)
        if operation.payload and operation.payload.sense_result:
            result = operation.payload.sense_result
            if self._should_trigger(result.aggregated_signal.payload):
                self._output_triggered = True
                self._output_operation = operation
                self._output_result = result
                return True
        return False

    def _process_output_task(self, task: asyncio.Task[SenseOperation]) -> None:
        try:
            operation = task.result()
        except Exception as exc:
            logger.warning("Sense API error in SenseGuard (output): %s", exc)
            self._output_error = exc
            if not self._fail_open:
                self._output_triggered = True
            return
        self._evaluate_output_operation(operation)

    async def _await_output_check(self, accumulated_text: str) -> None:
        """Run an output sense check and block until it completes.

        Sets ``_output_triggered`` / ``_output_operation`` / ``_output_result``
        on trigger, or ``_output_error`` on API failure.
        """
        assert self._output_sensor is not None  # callers guard for None
        try:
            operation = await self._client.asense(
                messages=self._build_output_messages(accumulated_text),
                sensor=self._output_sensor,
                **self._sense_kwargs,
            )
            self._evaluate_output_operation(operation)
        except Exception as exc:
            logger.warning("Sense API error in SenseGuard (output): %s", exc)
            self._output_error = exc
            if not self._fail_open:
                self._output_triggered = True

    def _build_output_messages(self, accumulated_text: str) -> list[dict[str, str]] | list[Message]:
        msgs: list[dict[str, str]] = []
        for m in self._messages:
            if isinstance(m, dict):
                msgs.append(m)
            else:
                msgs.append({"role": m.role, "content": m.content})
        msgs.append({"role": "assistant", "content": accumulated_text})
        return msgs

    async def _await_input_task(self, input_task: asyncio.Task[SenseOperation]) -> None:
        """Await the input task, applying ``input_timeout`` if set."""
        try:
            if self._input_timeout is not None:
                await asyncio.wait_for(asyncio.shield(input_task), timeout=self._input_timeout)
            else:
                await input_task
        except TimeoutError:
            self._input_error = TimeoutError()
            input_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await input_task
        except Exception:
            pass  # _process_input_task handles errors via task.result()

    async def shield[T](self, stream: AsyncIterable[T]) -> AsyncIterator[T]:
        """Wrap *stream* with concurrent input/output guardrails.

        The input sense check runs concurrently with the stream but is
        awaited before the first chunk is yielded (gate first chunk). This
        guarantees zero chunks leak before the input is validated while
        maximising concurrency. Can only be called once per ``SenseGuard``
        instance.

        Output checks depend on ``output_check_mode``:

        * **blocking** — when the chunk count reaches the interval, the
          output sense API call is fired and the stream is **paused**. While
          the API call is in-flight, the underlying LLM stream continues to
          be read into an internal buffer. On a green light the buffered
          chunks are burst-released. If a threat is detected, the stream
          terminates immediately. When ``output_check_interval`` is ``None``,
          **all** chunks are buffered internally and delivered only after the
          final post-stream check passes.
        * **parallel** — periodic checks run concurrently (fire-and-forget)
          without pausing chunk delivery. All chunks are yielded immediately.
          After the stream completes, pending periodic results are collected.
          If any detected a threat, the exception is raised post-stream.

        After the stream completes, a final output check runs on the full
        accumulated text. Remaining buffered chunks are withheld until the
        final check passes. If the final check detects a threat, those
        chunks are never delivered.

        Args:
            stream: Async iterable of LLM chunks (e.g. ``llm.astream(...)``).

        Yields:
            Each chunk from *stream*, after applying ``post_processors``.

        Raises:
            RuntimeError: If called more than once on the same instance.
            StihiaThreatDetectedError: If a threat is detected mid-stream
                or in the final check and ``raise_on_trigger`` is ``True``.
            StihiaError: If guardrail API is unavailable and
                ``fail_open=False`` with ``raise_on_trigger=True``.

        Example::

            async for chunk in guard.shield(llm.astream(prompt)):
                response += chunk
            if guard.triggered:
                handle_threat(guard.input_result or guard.output_result)
        """
        if self._shield_called:
            raise RuntimeError("shield() can only be called once per SenseGuard instance")
        self._shield_called = True

        input_task: asyncio.Task[SenseOperation] | None = None
        if self._input_sensor is not None:
            input_task = asyncio.create_task(
                self._client.asense(
                    messages=self._messages,
                    sensor=self._input_sensor,
                    **self._sense_kwargs,
                )
            )

        accumulated_text = ""
        chunk_count = 0
        first_chunk = True
        buffer: list[T] = []
        _sentinel = object()
        aiter = stream.__aiter__()
        pending_output_tasks: list[asyncio.Task[Any]] = []

        try:
            while True:
                nxt = await anext(aiter, _sentinel)
                if nxt is _sentinel:
                    break
                item: T = nxt  # type: ignore[assignment]

                if self._output_sensor is not None:
                    accumulated_text += self._chunk_to_text(item)
                    chunk_count += 1

                if first_chunk and input_task is not None:
                    await self._await_input_task(input_task)
                    self._process_input_task(input_task)
                    if self._input_triggered:
                        await self._fire_on_trigger("input", self._input_operation)
                        if self._raise_on_trigger:
                            if self._input_operation is not None:
                                raise StihiaThreatDetectedError(self._input_operation, source="input")
                            raise StihiaError("Guardrail unavailable (fail_open=False)")
                        return
                first_chunk = False

                if (
                    self._output_sensor is not None
                    and self._output_check_interval is not None
                    and chunk_count % self._output_check_interval == 0
                ):
                    if self._output_check_mode == "blocking":
                        check_task = asyncio.create_task(
                            self._await_output_check(accumulated_text),
                        )

                        # Buffer stream chunks while waiting for the API
                        # check. We race anext() against the check_task;
                        # only one caller touches the async iterator at a
                        # time, avoiding "already running" errors.
                        stream_done = False
                        pending_next: asyncio.Task[Any] | None = None
                        while not check_task.done():
                            if pending_next is None:
                                pending_next = asyncio.create_task(
                                    anext(aiter, _sentinel),  # type: ignore[arg-type]
                                )
                            done, _ = await asyncio.wait(
                                {check_task, pending_next},
                                return_when=asyncio.FIRST_COMPLETED,
                            )
                            if pending_next in done:
                                chunk_or_sentinel = pending_next.result()
                                pending_next = None
                                if chunk_or_sentinel is _sentinel:
                                    stream_done = True
                                    break
                                if self._output_sensor is not None:
                                    accumulated_text += self._chunk_to_text(chunk_or_sentinel)
                                    chunk_count += 1
                                buffer.append(chunk_or_sentinel)

                        if not check_task.done():
                            await check_task

                        # Collect any in-flight anext() that was pending
                        # when the API check completed.
                        if pending_next is not None and not stream_done:
                            chunk_or_sentinel = await pending_next
                            if chunk_or_sentinel is _sentinel:
                                stream_done = True
                            else:
                                if self._output_sensor is not None:
                                    accumulated_text += self._chunk_to_text(chunk_or_sentinel)
                                    chunk_count += 1
                                buffer.append(chunk_or_sentinel)

                        if self._output_triggered:
                            await self._fire_on_trigger("output", self._output_operation)
                            if self._raise_on_trigger:
                                if self._output_operation is not None:
                                    raise StihiaThreatDetectedError(
                                        self._output_operation,
                                        source="output",
                                    )
                                raise StihiaError("Guardrail unavailable (fail_open=False)")
                            return

                        yield self._apply_post_processors(item)
                        for buffered in buffer:
                            yield self._apply_post_processors(buffered)
                        buffer.clear()

                        if stream_done:
                            break
                        continue

                    # parallel mode: fire-and-forget output check
                    pending_output_tasks.append(
                        asyncio.create_task(
                            self._client.asense(
                                messages=self._build_output_messages(accumulated_text),
                                sensor=self._output_sensor,
                                **self._sense_kwargs,
                            )
                        )
                    )

                if (
                    self._output_sensor is not None
                    and self._output_check_interval is None
                    and self._output_check_mode == "blocking"
                ):
                    buffer.append(item)
                else:
                    yield self._apply_post_processors(item)

            if first_chunk and input_task is not None:
                await self._await_input_task(input_task)
                self._process_input_task(input_task)

            for ptask in pending_output_tasks:
                if not ptask.done():
                    with contextlib.suppress(Exception):
                        await ptask
                if not ptask.cancelled():
                    self._process_output_task(ptask)

            if self._output_triggered:
                await self._fire_on_trigger("output", self._output_operation)
                if self._raise_on_trigger:
                    if self._output_operation is not None:
                        raise StihiaThreatDetectedError(self._output_operation, source="output")
                    raise StihiaError("Guardrail unavailable (fail_open=False)")
                return

            if self._output_sensor is not None:
                await self._await_output_check(accumulated_text)
                if self._output_triggered:
                    await self._fire_on_trigger("output", self._output_operation)
                    if self._raise_on_trigger:
                        if self._output_operation is not None:
                            raise StihiaThreatDetectedError(self._output_operation, source="output")
                        raise StihiaError("Guardrail unavailable (fail_open=False)")
                    return

                if self._output_operations:
                    last_op = self._output_operations[-1]
                    if not self._output_triggered:
                        self._output_operation = last_op
                        if last_op.payload and last_op.payload.sense_result:
                            self._output_result = last_op.payload.sense_result

            for buffered in buffer:
                yield self._apply_post_processors(buffered)
            buffer.clear()

        finally:
            if input_task is not None and not input_task.done():
                input_task.cancel()
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await input_task
            for ptask in pending_output_tasks:
                if not ptask.done():
                    ptask.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await ptask

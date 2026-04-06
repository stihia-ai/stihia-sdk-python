"""Tests for SenseGuard."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from stihia.exceptions import StihiaError, StihiaThreatDetectedError
from stihia.guard import SenseGuard, _severity_meets_threshold
from stihia.models import SenseOperation, SignalSeverity


def _make_sense_operation(severity: str = "low") -> SenseOperation:
    return SenseOperation(
        uid="op-123",
        metadata={
            "status": "done",
            "errors": [],
            "org_uid": "org-123",
            "org_name": "Test Org",
            "project_key": "test-project",
            "user_key": "test-user",
            "process_key": "test-process",
            "thread_key": "test-thread",
            "run_key": "test-run",
            "start_timestamp": datetime.now(UTC).isoformat(),
            "end_timestamp": datetime.now(UTC).isoformat(),
            "processing_time_ms": 50,
        },
        payload={
            "messages": [{"role": "user", "content": "Hello"}],
            "sensor": {
                "uid": "s1",
                "key": "default",
                "classifiers": [],
                "aggregation_strategy": "max_severity",
                "execution_mode": "parallel",
                "timeout_ms": 3000,
            },
            "sense_result": {
                "aggregated_signal": {
                    "uid": "sig-001",
                    "latency_ms": 40,
                    "payload": {
                        "severity": severity,
                        "categories": ["prompt_injection"] if severity != "low" else ["neutral"],
                        "confidence": 0.9,
                        "details": {},
                    },
                    "aggregation_strategy": "max_severity",
                    "classifiers": [],
                },
                "signals": [],
                "errors": [],
            },
        },
    )


def _make_client(
    sense_op: SenseOperation | None = None,
    delay: float = 0.0,
    error: Exception | None = None,
) -> MagicMock:
    client = MagicMock()

    async def mock_asense(**kwargs):
        if delay:
            await asyncio.sleep(delay)
        if error:
            raise error
        return sense_op or _make_sense_operation()

    client.asense = AsyncMock(side_effect=mock_asense)
    return client


def _make_split_client(
    *,
    input_op: SenseOperation | None = None,
    input_delay: float = 0.0,
    input_error: Exception | None = None,
    output_op: SenseOperation | None = None,
    output_delay: float = 0.0,
    output_error: Exception | None = None,
) -> MagicMock:
    """Client that returns different results for input vs output sensor."""
    client = MagicMock()
    call_count = 0

    async def mock_asense(**kwargs):
        nonlocal call_count
        call_count += 1
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor" or (isinstance(sensor, dict) and sensor.get("key") == "output-sensor")
        if is_output:
            if output_delay:
                await asyncio.sleep(output_delay)
            if output_error:
                raise output_error
            return output_op or _make_sense_operation()
        else:
            if input_delay:
                await asyncio.sleep(input_delay)
            if input_error:
                raise input_error
            return input_op or _make_sense_operation()

    client.asense = AsyncMock(side_effect=mock_asense)
    return client


async def _async_iter(items, delay: float = 0.0):
    for item in items:
        if delay:
            await asyncio.sleep(delay)
        yield item


COMMON_KWARGS = {
    "messages": [{"role": "user", "content": "test"}],
    "input_sensor": "default-input",
    "project_key": "p",
    "user_key": "u",
    "process_key": "proc",
    "thread_key": "t",
    "run_key": "r",
}

# ── Existing tests (updated property names) ──


@pytest.mark.asyncio
async def test_shield_yields_all_no_threat():
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


@pytest.mark.asyncio
async def test_shield_raises_on_high():
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass


@pytest.mark.asyncio
async def test_shield_raises_on_critical():
    client = _make_client(_make_sense_operation("critical"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass


@pytest.mark.asyncio
async def test_shield_silent_mode():
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, raise_on_trigger=False, **COMMON_KWARGS)
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3])):
        result.append(item)
    # Blocked at first chunk — zero chunks yielded
    assert len(result) == 0
    assert guard.triggered


@pytest.mark.asyncio
async def test_custom_threshold_medium():
    client = _make_client(_make_sense_operation("medium"))
    guard = SenseGuard(client, min_severity=SignalSeverity.MEDIUM, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass


@pytest.mark.asyncio
async def test_threshold_high_ignores_medium():
    client = _make_client(_make_sense_operation("medium"))
    guard = SenseGuard(client, min_severity=SignalSeverity.HIGH, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


@pytest.mark.asyncio
async def test_high_input_raises_before_first_chunk():
    """HIGH input (even with delay) raises before yielding any chunks."""
    client = _make_client(_make_sense_operation("high"), delay=0.1)
    guard = SenseGuard(client, **COMMON_KWARGS)
    collected = []
    with pytest.raises(StihiaThreatDetectedError):
        async for item in guard.shield(_async_iter([1, 2, 3])):
            collected.append(item)
    assert collected == []
    assert guard.input_triggered
    assert guard.input_operation is not None


@pytest.mark.asyncio
async def test_low_severity_no_trigger():
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


@pytest.mark.asyncio
async def test_properties_after_iteration():
    op = _make_sense_operation("low")
    client = _make_client(op)
    guard = SenseGuard(client, **COMMON_KWARGS)
    _ = [item async for item in guard.shield(_async_iter([1]))]
    assert guard.input_operation is not None
    assert guard.input_result is not None
    assert not guard.triggered
    assert guard.input_error is None


@pytest.mark.asyncio
async def test_input_check_completes_then_break_works():
    """Input (no delay) completes at first chunk, break at chunk 2 works."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    collected = []
    async for item in guard.shield(_async_iter([1, 2, 3])):
        collected.append(item)
        if item == 2:
            break
    assert collected == [1, 2]
    assert guard.input_operation is not None


@pytest.mark.asyncio
async def test_sense_api_error():
    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(client, fail_open=True, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered
    assert guard.input_error is not None
    assert "API down" in str(guard.input_error)


@pytest.mark.asyncio
async def test_shield_called_twice_raises():
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    _ = [item async for item in guard.shield(_async_iter([1]))]
    with pytest.raises(RuntimeError, match=r"shield.*only.*once"):
        async for _ in guard.shield(_async_iter([1])):
            pass


def test_severity_meets_threshold():
    assert not _severity_meets_threshold(SignalSeverity.LOW, SignalSeverity.MEDIUM)
    assert not _severity_meets_threshold(SignalSeverity.LOW, SignalSeverity.HIGH)
    assert not _severity_meets_threshold(SignalSeverity.LOW, SignalSeverity.CRITICAL)
    assert not _severity_meets_threshold(SignalSeverity.MEDIUM, SignalSeverity.HIGH)
    assert not _severity_meets_threshold(SignalSeverity.MEDIUM, SignalSeverity.CRITICAL)
    assert not _severity_meets_threshold(SignalSeverity.HIGH, SignalSeverity.CRITICAL)

    assert _severity_meets_threshold(SignalSeverity.LOW, SignalSeverity.LOW)
    assert _severity_meets_threshold(SignalSeverity.MEDIUM, SignalSeverity.LOW)
    assert _severity_meets_threshold(SignalSeverity.MEDIUM, SignalSeverity.MEDIUM)
    assert _severity_meets_threshold(SignalSeverity.HIGH, SignalSeverity.LOW)
    assert _severity_meets_threshold(SignalSeverity.HIGH, SignalSeverity.MEDIUM)
    assert _severity_meets_threshold(SignalSeverity.HIGH, SignalSeverity.HIGH)
    assert _severity_meets_threshold(SignalSeverity.CRITICAL, SignalSeverity.LOW)
    assert _severity_meets_threshold(SignalSeverity.CRITICAL, SignalSeverity.MEDIUM)
    assert _severity_meets_threshold(SignalSeverity.CRITICAL, SignalSeverity.HIGH)
    assert _severity_meets_threshold(SignalSeverity.CRITICAL, SignalSeverity.CRITICAL)


# ── Output sensing tests ──


@pytest.mark.asyncio
async def test_no_output_check_when_sensor_none():
    """Default: no output tasks fired when output_sensor not set."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert guard.output_operation is None
    assert guard.output_result is None
    assert not guard.output_triggered
    assert guard.output_operations == []
    # Only 1 call — the input sense
    assert client.asense.call_count == 1


@pytest.mark.asyncio
async def test_output_final_check_after_stream():
    """output_sensor set: final output check populates output_operation/result."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,  # no periodic checks
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert guard.output_operation is not None
    assert guard.output_result is not None
    assert not guard.output_triggered
    assert len(guard.output_operations) == 1  # only final


@pytest.mark.asyncio
async def test_output_trigger_mid_stream_raises():
    """Periodic output check returns HIGH — stream interrupted with raise."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,  # fire quickly
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
            pass
    assert exc_info.value.source == "output"
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_output_trigger_mid_stream_silent():
    """raise_on_trigger=False: output trigger stops stream silently."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
        result.append(item)
    assert len(result) < 5
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_output_final_check_blocks_and_raises():
    """Final output check returns HIGH — blocks output, raises exception."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert exc_info.value.source == "output"
    assert guard.output_triggered
    assert guard.output_operation is not None


@pytest.mark.asyncio
async def test_periodic_output_checks_fire():
    """Short interval causes multiple output sense calls."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=2,
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.03))]
    assert result == [1, 2, 3, 4, 5]
    # At least 1 periodic + 1 final = 2 output calls, plus 1 input call
    assert client.asense.call_count >= 3
    assert len(guard.output_operations) >= 2  # periodic + final


@pytest.mark.asyncio
async def test_chunk_to_text_callback():
    """Custom chunk_to_text callback used to extract text."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    chunks = [{"text": "Hello "}, {"text": "world"}]

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        chunk_to_text=lambda c: c["text"],
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(chunks))]
    assert result == chunks

    # Verify the output sense call included accumulated text
    output_calls = [c for c in client.asense.call_args_list if c.kwargs.get("sensor") == "output-sensor"]
    assert len(output_calls) >= 1
    messages = output_calls[-1].kwargs["messages"]
    assistant_msg = messages[-1]
    assert assistant_msg["role"] == "assistant"
    assert assistant_msg["content"] == "Hello world"


@pytest.mark.asyncio
async def test_output_messages_include_input():
    """Output sense messages = input messages + assistant message."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    _ = [item async for item in guard.shield(_async_iter(["a", "b"]))]

    output_calls = [c for c in client.asense.call_args_list if c.kwargs.get("sensor") == "output-sensor"]
    assert len(output_calls) >= 1
    messages = output_calls[-1].kwargs["messages"]
    # First message is the input, last is assistant
    assert messages[0] == {"role": "user", "content": "test"}
    assert messages[-1]["role"] == "assistant"
    assert messages[-1]["content"] == "ab"


@pytest.mark.asyncio
async def test_combined_triggered_property():
    """`triggered` is True if either input or output triggered."""
    # Input triggered — raises at first chunk
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        _ = [item async for item in guard.shield(_async_iter([1]))]
    assert guard.input_triggered
    assert not guard.output_triggered
    assert guard.triggered

    # Output triggered (via final check) — now blocks and raises
    client2 = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard2 = SenseGuard(
        client2,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError):
        _ = [item async for item in guard2.shield(_async_iter([1]))]
    assert not guard2.input_triggered
    assert guard2.output_triggered
    assert guard2.triggered


@pytest.mark.asyncio
async def test_output_api_error():
    """Output sense error stored, stream continues when fail_open=True."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_error=RuntimeError("Output API down"),
    )
    guard = SenseGuard(
        client,
        fail_open=True,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.output_triggered
    assert guard.output_error is not None
    assert "Output API down" in str(guard.output_error)


@pytest.mark.asyncio
async def test_threat_error_has_source_input():
    """StihiaThreatDetectedError.source == 'input' for input triggers."""
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    assert exc_info.value.source == "input"


@pytest.mark.asyncio
async def test_threat_error_has_source_output():
    """StihiaThreatDetectedError.source == 'output' for output triggers."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
            pass
    assert exc_info.value.source == "output"


# ── Final-only output check mode tests ──


@pytest.mark.asyncio
async def test_final_only_mode_no_periodic_checks():
    """interval=None → only 2 API calls (input + final), 1 output operation."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.03))]
    assert result == [1, 2, 3, 4, 5]
    assert client.asense.call_count == 2  # input + final only
    assert len(guard.output_operations) == 1  # final only


@pytest.mark.asyncio
async def test_final_only_mode_detects_threat():
    """Final check detects HIGH severity in final-only mode — blocks and raises."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert exc_info.value.source == "output"
    assert guard.output_triggered
    assert guard.output_operation is not None


@pytest.mark.asyncio
async def test_final_only_mode_accumulates_text():
    """chunk_to_text still works in final-only mode, final check gets full text."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    chunks = [{"text": "Hello "}, {"text": "world"}]
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        chunk_to_text=lambda c: c["text"],
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(chunks))]
    assert result == chunks

    output_calls = [c for c in client.asense.call_args_list if c.kwargs.get("sensor") == "output-sensor"]
    assert len(output_calls) == 1  # final only
    messages = output_calls[0].kwargs["messages"]
    assert messages[-1]["content"] == "Hello world"


@pytest.mark.asyncio
async def test_final_only_no_mid_stream_interruption():
    """Final-only mode: chunks buffer during stream, final check blocks and raises on HIGH."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.03))]
    assert exc_info.value.source == "output"
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_final_only_blocking_withholds_chunks_until_check():
    """Blocking + interval=None: no chunks yielded until final check completes."""
    yielded_before_api: list[int] = []
    api_called = asyncio.Event()

    input_op = _make_sense_operation("low")
    output_op = _make_sense_operation("low")

    async def mock_asense(**kwargs):
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor"
        if is_output:
            api_called.set()
            await asyncio.sleep(0.05)
            return output_op
        return input_op

    client = MagicMock()
    client.asense = AsyncMock(side_effect=mock_asense)

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        **COMMON_KWARGS,
    )

    result = []
    async for chunk in guard.shield(_async_iter([1, 2, 3], delay=0.02)):
        if not api_called.is_set():
            yielded_before_api.append(chunk)
        result.append(chunk)

    assert result == [1, 2, 3]
    assert yielded_before_api == [], "chunks must not be yielded before the output API check"


@pytest.mark.asyncio
async def test_final_only_blocking_threat_yields_nothing():
    """Blocking + interval=None + threat: zero chunks reach the caller."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=None,
        **COMMON_KWARGS,
    )
    collected: list[int] = []
    with pytest.raises(StihiaThreatDetectedError):
        async for chunk in guard.shield(_async_iter([1, 2, 3])):
            collected.append(chunk)

    assert collected == [], "no chunks should be yielded when the final check detects a threat"
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_default_interval_unchanged():
    """Regression: default output_check_interval is None."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    assert guard._output_check_interval is None


@pytest.mark.asyncio
async def test_first_chunk_gates_on_slow_input():
    """First chunk waits for slow input check; all chunks delivered after."""
    client = _make_client(_make_sense_operation("low"), delay=0.2)
    guard = SenseGuard(client, **COMMON_KWARGS)
    collected = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert collected == [1, 2, 3]
    assert not guard.triggered
    assert guard.input_operation is not None


# ── fail_open tests ──


@pytest.mark.asyncio
async def test_fail_open_default_blocks_on_error():
    """API error + default fail_open (False) → blocks."""
    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaError, match="Guardrail unavailable"):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_fail_open_false_input_error_raises():
    """API error + fail_open=False + raise_on_trigger → raises StihiaError."""
    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(client, fail_open=False, **COMMON_KWARGS)
    with pytest.raises(StihiaError, match="Guardrail unavailable"):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_fail_open_false_input_error_silent():
    """API error + fail_open=False + raise_on_trigger=False → 0 chunks."""
    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(client, fail_open=False, raise_on_trigger=False, **COMMON_KWARGS)
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3])):
        result.append(item)
    assert len(result) == 0
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_fail_open_true_passes_on_error():
    """API error + fail_open=True → passes through."""
    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(client, fail_open=True, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


@pytest.mark.asyncio
async def test_fail_open_false_output_error_triggers():
    """Output API error + fail_open=False → output_triggered=True."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_error=RuntimeError("Output API down"),
    )
    guard = SenseGuard(
        client,
        fail_open=False,
        raise_on_trigger=False,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3])):
        result.append(item)
    # Blocking mode: chunks buffered until final check; API error + fail_open=False
    # triggers before buffer flush, so zero chunks delivered.
    assert result == []
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_fail_open_false_no_errors_normal():
    """No errors + fail_open=False → normal behavior."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, fail_open=False, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


# ── input_timeout tests ──


@pytest.mark.asyncio
async def test_input_timeout_expires_fail_open_true():
    """Slow API + timeout expires + fail_open=True → passes through."""
    client = _make_client(_make_sense_operation("low"), delay=1.0)
    guard = SenseGuard(client, input_timeout=0.05, fail_open=True, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered
    assert guard.input_error is not None
    assert isinstance(guard.input_error, asyncio.TimeoutError)


@pytest.mark.asyncio
async def test_input_timeout_expires_fail_open_false():
    """Slow API + timeout expires + fail_open=False → triggers."""
    client = _make_client(_make_sense_operation("low"), delay=1.0)
    guard = SenseGuard(client, input_timeout=0.05, fail_open=False, **COMMON_KWARGS)
    with pytest.raises(StihiaError, match="Guardrail unavailable"):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_input_timeout_not_expired():
    """Slow API + timeout does NOT expire → normal behavior."""
    client = _make_client(_make_sense_operation("low"), delay=0.01)
    guard = SenseGuard(client, input_timeout=5.0, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered
    assert guard.input_error is None


@pytest.mark.asyncio
async def test_input_timeout_none_default():
    """input_timeout=None (default) → unchanged behavior, no timeout."""
    client = _make_client(_make_sense_operation("low"), delay=0.1)
    guard = SenseGuard(client, **COMMON_KWARGS)
    assert guard._input_timeout is None
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]


@pytest.mark.asyncio
async def test_input_timeout_empty_stream():
    """Timeout on empty stream + fail_open=False → triggers."""
    client = _make_client(_make_sense_operation("low"), delay=1.0)
    guard = SenseGuard(
        client,
        input_timeout=0.05,
        fail_open=False,
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    result = []
    async for item in guard.shield(_async_iter([])):
        result.append(item)
    assert result == []
    assert guard.input_triggered


# ── on_trigger tests ──


@pytest.mark.asyncio
async def test_on_trigger_sync_callback_input():
    """Sync callback called on input trigger with correct args."""
    callback_calls = []

    def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, on_trigger=my_callback, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass

    assert len(callback_calls) == 1
    assert callback_calls[0][0] == "input"
    assert callback_calls[0][1] is not None  # has operation


@pytest.mark.asyncio
async def test_on_trigger_async_callback_input():
    """Async callback called on input trigger."""
    callback_calls = []

    async def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, on_trigger=my_callback, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass

    assert len(callback_calls) == 1
    assert callback_calls[0][0] == "input"


@pytest.mark.asyncio
async def test_on_trigger_output_periodic():
    """Callback fires on periodic output trigger."""
    callback_calls = []

    def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        on_trigger=my_callback,
        output_sensor="output-sensor",
        output_check_interval=1,
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
        pass
    assert len(callback_calls) >= 1
    assert callback_calls[0][0] == "output"
    assert callback_calls[0][1] is not None


@pytest.mark.asyncio
async def test_on_trigger_output_final():
    """Callback fires on final output trigger, then raises."""
    callback_calls = []

    def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        on_trigger=my_callback,
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError):
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert guard.output_triggered
    assert len(callback_calls) == 1
    assert callback_calls[0][0] == "output"


@pytest.mark.asyncio
async def test_on_trigger_none_operation_on_api_error():
    """Callback receives None operation on API error + fail_open=False."""
    callback_calls = []

    def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_client(error=RuntimeError("API down"))
    guard = SenseGuard(
        client,
        on_trigger=my_callback,
        fail_open=False,
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    async for _ in guard.shield(_async_iter([1, 2, 3])):
        pass
    assert len(callback_calls) == 1
    assert callback_calls[0][0] == "input"
    assert callback_calls[0][1] is None  # no operation on API error


@pytest.mark.asyncio
async def test_on_trigger_fires_before_exception():
    """Callback fires BEFORE exception is raised."""
    order = []

    def my_callback(source, operation):
        order.append("callback")

    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, on_trigger=my_callback, **COMMON_KWARGS)
    try:
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    except StihiaThreatDetectedError:
        order.append("exception")

    assert order == ["callback", "exception"]


@pytest.mark.asyncio
async def test_on_trigger_default_none_no_error():
    """No callback (default) → no error."""
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass


# ── _should_trigger refactoring tests ──


@pytest.mark.asyncio
async def test_should_trigger_respects_min_severity():
    """_should_trigger returns False when severity below threshold."""
    client = _make_client(_make_sense_operation("medium"))
    guard = SenseGuard(client, min_severity=SignalSeverity.HIGH, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered


# ── text_processor decorator tests ──


def _make_openai_chunk(content: str | None = None):
    """Create a mock OpenAI-compatible streaming chunk."""
    delta = MagicMock()
    delta.content = content
    choice = MagicMock()
    choice.delta = delta
    chunk = MagicMock()
    chunk.choices = [choice]
    return chunk


class TestTextProcessor:
    def test_str_passthrough(self):
        from stihia.processors import text_processor

        @text_processor
        def upper(text: str) -> str:
            return text.upper()

        assert upper("hello") == "HELLO"

    def test_chunk_transformation(self):
        from stihia.processors import text_processor

        @text_processor
        def upper(text: str) -> str:
            return text.upper()

        chunk = _make_openai_chunk("hello")
        result = upper(chunk)
        assert result is chunk
        assert result.choices[0].delta.content == "HELLO"

    def test_chunk_no_content_passthrough(self):
        from stihia.processors import text_processor

        @text_processor
        def upper(text: str) -> str:
            return text.upper()

        chunk = _make_openai_chunk(None)
        result = upper(chunk)
        assert result is chunk
        assert result.choices[0].delta.content is None

    def test_chunk_empty_choices_passthrough(self):
        from stihia.processors import text_processor

        @text_processor
        def upper(text: str) -> str:
            return text.upper()

        chunk = MagicMock()
        chunk.choices = []
        result = upper(chunk)
        assert result is chunk
        assert result.choices == []

    def test_non_str_non_chunk_passthrough(self):
        from stihia.processors import text_processor

        @text_processor
        def upper(text: str) -> str:
            return text.upper()

        assert upper(42) == 42
        assert upper(None) is None

    def test_preserves_name(self):
        from stihia.processors import text_processor

        @text_processor
        def my_function(text: str) -> str:
            return text

        assert my_function.__name__ == "my_function"

    def test_preserves_doc(self):
        from stihia.processors import text_processor

        @text_processor
        def my_function(text: str) -> str:
            """My docstring."""
            return text

        assert my_function.__doc__ == "My docstring."


# ── strip_markdown_images on chunks tests ──


class TestStripMarkdownImagesChunks:
    def test_chunk_with_image_content(self):
        from stihia.processors import strip_markdown_images

        chunk = _make_openai_chunk("Check ![logo](http://evil.com/track.png) here")
        result = strip_markdown_images(chunk)
        assert result.choices[0].delta.content == ("Check [logo](http://evil.com/track.png) here")

    def test_chunk_without_images(self):
        from stihia.processors import strip_markdown_images

        chunk = _make_openai_chunk("Hello world")
        result = strip_markdown_images(chunk)
        assert result.choices[0].delta.content == "Hello world"

    def test_chunk_content_none(self):
        from stihia.processors import strip_markdown_images

        chunk = _make_openai_chunk(None)
        result = strip_markdown_images(chunk)
        assert result.choices[0].delta.content is None

    def test_chunk_empty_choices(self):
        from stihia.processors import strip_markdown_images

        chunk = MagicMock()
        chunk.choices = []
        result = strip_markdown_images(chunk)
        assert result.choices == []


# ── strip_markdown_images str unit tests ──


class TestStripMarkdownImages:
    def test_basic_replacement(self):
        from stihia.processors import strip_markdown_images

        assert strip_markdown_images("![alt](url)") == "[alt](url)"

    def test_no_op_plain_text(self):
        from stihia.processors import strip_markdown_images

        assert strip_markdown_images("Hello world") == "Hello world"

    def test_multiple_images(self):
        from stihia.processors import strip_markdown_images

        text = "Look ![img1](a) and ![img2](b)"
        assert strip_markdown_images(text) == "Look [img1](a) and [img2](b)"

    def test_empty_string(self):
        from stihia.processors import strip_markdown_images

        assert strip_markdown_images("") == ""

    def test_preserves_regular_links(self):
        from stihia.processors import strip_markdown_images

        text = "[link](url) and ![image](url)"
        assert strip_markdown_images(text) == "[link](url) and [image](url)"


# ── SenseGuard post_processors integration tests ──


@pytest.mark.asyncio
async def test_single_post_processor_transforms_chunks():
    """Single processor transforms each yielded chunk."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(
        client,
        post_processors=[str.upper],
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(["a", "b", "c"]))]
    assert result == ["A", "B", "C"]


@pytest.mark.asyncio
async def test_multiple_post_processors_applied_in_order():
    """Processors applied left-to-right."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(
        client,
        post_processors=[str.upper, lambda s: s + "!"],
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(["hi"]))]
    assert result == ["HI!"]


@pytest.mark.asyncio
async def test_default_none_passthrough():
    """Default post_processors=None yields chunks unchanged."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter(["a", "b"]))]
    assert result == ["a", "b"]


@pytest.mark.asyncio
async def test_output_sensing_accumulates_raw_text():
    """Output sensing sees raw text, not post-processed text."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        post_processors=[str.upper],
        output_sensor="output-sensor",
        output_check_interval=999,
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(["hello"]))]
    assert result == ["HELLO"]

    # Verify output sense received raw (lowercase) text
    output_calls = [c for c in client.asense.call_args_list if c.kwargs.get("sensor") == "output-sensor"]
    assert len(output_calls) >= 1
    messages = output_calls[-1].kwargs["messages"]
    assert messages[-1]["content"] == "hello"  # raw, not "HELLO"


@pytest.mark.asyncio
async def test_strip_markdown_images_end_to_end():
    """Built-in strip_markdown_images works end-to-end with SenseGuard."""
    from stihia.processors import strip_markdown_images

    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(
        client,
        post_processors=[strip_markdown_images],
        **COMMON_KWARGS,
    )
    chunks = ["Here is ", "![an image](http://evil.com/track.png)", " ok"]
    result = [item async for item in guard.shield(_async_iter(chunks))]
    assert result == ["Here is ", "[an image](http://evil.com/track.png)", " ok"]


@pytest.mark.asyncio
async def test_strip_markdown_images_chunks_end_to_end():
    """strip_markdown_images handles OpenAI-compatible chunks through SenseGuard."""
    from stihia.processors import strip_markdown_images

    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(
        client,
        post_processors=[strip_markdown_images],
        chunk_to_text=lambda c: c.choices[0].delta.content or "",
        **COMMON_KWARGS,
    )
    chunks = [
        _make_openai_chunk("Here is "),
        _make_openai_chunk("![an image](http://evil.com/track.png)"),
        _make_openai_chunk(" ok"),
    ]
    result = [item async for item in guard.shield(_async_iter(chunks))]
    texts = [r.choices[0].delta.content for r in result]
    assert texts == ["Here is ", "[an image](http://evil.com/track.png)", " ok"]


@pytest.mark.asyncio
async def test_post_processors_not_called_on_input_trigger():
    """When input triggers, no chunks yielded so processors never called."""
    call_count = 0

    def counting_processor(chunk):
        nonlocal call_count
        call_count += 1
        return chunk

    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(
        client,
        post_processors=[counting_processor],
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError):
        async for _ in guard.shield(_async_iter([1, 2, 3])):
            pass
    assert call_count == 0


# ── Optional input_sensor tests ──


NO_INPUT_KWARGS = {
    "messages": [{"role": "user", "content": "test"}],
    "project_key": "p",
    "user_key": "u",
    "process_key": "proc",
    "thread_key": "t",
    "run_key": "r",
}


@pytest.mark.asyncio
async def test_output_only_no_input_gate():
    """No input sensor: chunks yielded immediately, output checks still run."""
    client = _make_split_client(
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        **NO_INPUT_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert result == [1, 2, 3]
    assert not guard.triggered
    assert guard.input_operation is None
    assert guard.output_operation is not None
    # Only output calls — no input sense call
    input_calls = [c for c in client.asense.call_args_list if c.kwargs.get("sensor") != "output-sensor"]
    assert len(input_calls) == 0


@pytest.mark.asyncio
async def test_no_sensors_passthrough():
    """No sensors: passthrough mode, no API calls, post-processors applied."""
    client = _make_client()
    guard = SenseGuard(
        client,
        post_processors=[str.upper],
        **NO_INPUT_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter(["a", "b", "c"]))]
    assert result == ["A", "B", "C"]
    assert not guard.triggered
    assert guard.input_operation is None
    assert guard.output_operation is None
    assert client.asense.call_count == 0


@pytest.mark.asyncio
async def test_output_only_with_trigger():
    """Output-only: output threat blocks and raises, input properties remain None."""
    client = _make_split_client(
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        **NO_INPUT_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert exc_info.value.source == "output"
    assert guard.output_triggered
    assert not guard.input_triggered
    assert guard.input_operation is None
    assert guard.input_result is None


@pytest.mark.asyncio
async def test_no_sensors_empty_stream():
    """No sensors + empty stream: no crash, no API calls."""
    client = _make_client()
    guard = SenseGuard(client, **NO_INPUT_KWARGS)
    result = [item async for item in guard.shield(_async_iter([]))]
    assert result == []
    assert not guard.triggered
    assert client.asense.call_count == 0


# ── output_check_mode tests ──


@pytest.mark.asyncio
async def test_parallel_mode_yields_all_chunks_immediately():
    """Parallel mode delivers all chunks without waiting for periodic checks."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
        output_delay=0.2,
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.03))]
    assert result == [1, 2, 3, 4, 5]
    assert not guard.triggered


@pytest.mark.asyncio
async def test_parallel_mode_periodic_threat_raises_post_stream():
    """Parallel: periodic HIGH detected → raises after all chunks delivered."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
            pass
    assert exc_info.value.source == "output"
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_parallel_mode_final_check_raises():
    """Parallel: final check HIGH → raises after all chunks delivered."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=999,
        output_check_mode="parallel",
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([1, 2, 3]))]
    assert exc_info.value.source == "output"
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_parallel_mode_silent_stops_after_stream():
    """Parallel + raise_on_trigger=False: all chunks delivered, triggered set."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
        result.append(item)
    assert result == [1, 2, 3, 4, 5]
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_parallel_mode_fires_periodic_tasks():
    """Parallel mode fires periodic output checks in the background."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=2,
        output_check_mode="parallel",
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.03))]
    assert result == [1, 2, 3, 4, 5]
    # At least 1 periodic + 1 final = 2 output calls, plus 1 input call
    assert client.asense.call_count >= 3
    assert len(guard.output_operations) >= 2


@pytest.mark.asyncio
async def test_parallel_mode_on_trigger_callback():
    """Parallel: on_trigger callback fires for periodic threat after stream."""
    callback_calls = []

    def my_callback(source, operation):
        callback_calls.append((source, operation))

    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        on_trigger=my_callback,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
        pass
    assert len(callback_calls) >= 1
    assert callback_calls[0][0] == "output"


@pytest.mark.asyncio
async def test_parallel_mode_output_api_error_fail_open():
    """Parallel + output API error + fail_open=True → all chunks, no trigger."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_error=RuntimeError("Output API down"),
    )
    guard = SenseGuard(
        client,
        fail_open=True,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3], delay=0.05))]
    assert result == [1, 2, 3]
    assert not guard.output_triggered
    assert guard.output_error is not None


@pytest.mark.asyncio
async def test_parallel_mode_output_api_error_fail_closed():
    """Parallel + output API error + fail_open=False → triggered after stream."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_error=RuntimeError("Output API down"),
    )
    guard = SenseGuard(
        client,
        fail_open=False,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="parallel",
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )
    result = []
    async for item in guard.shield(_async_iter([1, 2, 3], delay=0.05)):
        result.append(item)
    assert result == [1, 2, 3]
    assert guard.output_triggered


@pytest.mark.asyncio
async def test_default_mode_is_blocking():
    """Default output_check_mode is 'blocking'."""
    client = _make_client(_make_sense_operation("low"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    assert guard._output_check_mode == "blocking"


@pytest.mark.asyncio
async def test_invalid_mode_raises():
    """Invalid output_check_mode raises ValueError."""
    client = _make_client(_make_sense_operation("low"))
    with pytest.raises(ValueError, match="output_check_mode"):
        SenseGuard(client, output_check_mode="invalid", **COMMON_KWARGS)


@pytest.mark.asyncio
async def test_invalid_interval_raises_for_zero():
    client = _make_client(_make_sense_operation("low"))
    with pytest.raises(ValueError, match="output_check_interval"):
        SenseGuard(client, output_check_interval=0, **COMMON_KWARGS)


@pytest.mark.asyncio
async def test_invalid_interval_raises_for_negative():
    client = _make_client(_make_sense_operation("low"))
    with pytest.raises(ValueError, match="output_check_interval"):
        SenseGuard(client, output_check_interval=-1, **COMMON_KWARGS)


@pytest.mark.asyncio
async def test_blocking_mode_explicit():
    """Explicitly passing output_check_mode='blocking' uses blocking behavior."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("high"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for _ in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.05)):
            pass
    assert exc_info.value.source == "output"
    assert guard.output_triggered


# ── Blocking interval tail-chunk tests ──


@pytest.mark.asyncio
async def test_blocking_interval_tail_chunks_withheld_until_final_check():
    """Blocking + interval=3 with 5 chunks: tail (chunks 4-5) not yielded before final check."""
    yielded_before_final_api: list[int] = []
    final_api_called = asyncio.Event()

    input_op = _make_sense_operation("low")
    output_op = _make_sense_operation("low")
    call_count = 0

    async def mock_asense(**kwargs):
        nonlocal call_count
        call_count += 1
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor"
        if is_output:
            if call_count > 2:
                # This is the final output check (after periodic)
                final_api_called.set()
                await asyncio.sleep(0.05)
            return output_op
        return input_op

    client = MagicMock()
    client.asense = AsyncMock(side_effect=mock_asense)

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=3,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )

    result = []
    async for chunk in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.02)):
        if not final_api_called.is_set():
            yielded_before_final_api.append(chunk)
        result.append(chunk)

    assert result == [1, 2, 3, 4, 5]
    # Chunks 4 and 5 are tail chunks (after boundary at 3) — they must NOT
    # appear before the final check API was called.
    assert 4 not in yielded_before_final_api, "tail chunk 4 must not be yielded before final check"
    assert 5 not in yielded_before_final_api, "tail chunk 5 must not be yielded before final check"


@pytest.mark.asyncio
async def test_blocking_interval_tail_threat_yields_nothing_after_boundary():
    """Blocking + interval=3 + 5 chunks: final check HIGH → tail chunks never delivered."""
    input_op = _make_sense_operation("low")
    periodic_op = _make_sense_operation("low")
    final_op = _make_sense_operation("high")
    call_count = 0

    async def mock_asense(**kwargs):
        nonlocal call_count
        call_count += 1
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor"
        if is_output:
            # First output call is the periodic check at chunk 3 → green
            # Second output call is the final check → threat
            if call_count <= 2:
                return periodic_op
            return final_op
        return input_op

    client = MagicMock()
    client.asense = AsyncMock(side_effect=mock_asense)

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=3,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )

    collected: list[int] = []
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        async for chunk in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.02)):
            collected.append(chunk)

    assert exc_info.value.source == "output"
    assert guard.output_triggered
    # Chunks 1-3 released after periodic green, but 4-5 must never be delivered
    assert 4 not in collected, "tail chunk 4 must not be yielded when final check detects threat"
    assert 5 not in collected, "tail chunk 5 must not be yielded when final check detects threat"


@pytest.mark.asyncio
async def test_blocking_interval_preserves_chunk_order():
    """Blocking + interval: chunks yielded in correct order through periodic + tail flush."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
        output_delay=0.01,
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=3,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3, 4, 5, 6, 7], delay=0.02))]
    assert result == [1, 2, 3, 4, 5, 6, 7], "chunk ordering must be preserved across periodic + tail flushes"


@pytest.mark.asyncio
async def test_blocking_interval_tail_silent_mode_no_chunks_on_threat():
    """Blocking + interval + raise_on_trigger=False: tail chunks suppressed on threat."""
    input_op = _make_sense_operation("low")
    periodic_op = _make_sense_operation("low")
    final_op = _make_sense_operation("high")
    call_count = 0

    async def mock_asense(**kwargs):
        nonlocal call_count
        call_count += 1
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor"
        if is_output:
            if call_count <= 2:
                return periodic_op
            return final_op
        return input_op

    client = MagicMock()
    client.asense = AsyncMock(side_effect=mock_asense)

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=3,
        output_check_mode="blocking",
        raise_on_trigger=False,
        **COMMON_KWARGS,
    )

    collected: list[int] = []
    async for chunk in guard.shield(_async_iter([1, 2, 3, 4, 5], delay=0.02)):
        collected.append(chunk)

    assert guard.output_triggered
    # Chunks 1-3 released after periodic green, but 4-5 must never appear
    assert 4 not in collected, "tail chunk 4 must not be yielded when final check triggers (silent)"
    assert 5 not in collected, "tail chunk 5 must not be yielded when final check triggers (silent)"


@pytest.mark.asyncio
async def test_blocking_interval_exact_boundary_no_tail():
    """Blocking + interval=3 + exactly 3 chunks: no tail, all released after periodic green."""
    client = _make_split_client(
        input_op=_make_sense_operation("low"),
        output_op=_make_sense_operation("low"),
    )
    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=3,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )
    result = [item async for item in guard.shield(_async_iter([1, 2, 3], delay=0.02))]
    assert result == [1, 2, 3]
    assert not guard.output_triggered


@pytest.mark.asyncio
async def test_empty_stream_input_trigger_raises():
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, **COMMON_KWARGS)
    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        _ = [item async for item in guard.shield(_async_iter([]))]
    assert exc_info.value.source == "input"
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_empty_stream_input_trigger_silent_mode():
    client = _make_client(_make_sense_operation("high"))
    guard = SenseGuard(client, raise_on_trigger=False, **COMMON_KWARGS)
    result = [item async for item in guard.shield(_async_iter([]))]
    assert result == []
    assert guard.input_triggered


@pytest.mark.asyncio
async def test_blocking_periodic_trigger_does_not_wait_for_next_chunk():
    input_op = _make_sense_operation("low")
    output_op = _make_sense_operation("high")

    async def mock_asense(**kwargs):
        sensor = kwargs.get("sensor", "")
        is_output = sensor == "output-sensor"
        if is_output:
            return output_op
        return input_op

    async def delayed_stream():
        yield 1
        await asyncio.sleep(3600)
        yield 2

    client = MagicMock()
    client.asense = AsyncMock(side_effect=mock_asense)

    guard = SenseGuard(
        client,
        output_sensor="output-sensor",
        output_check_interval=1,
        output_check_mode="blocking",
        **COMMON_KWARGS,
    )

    with pytest.raises(StihiaThreatDetectedError) as exc_info:
        await asyncio.wait_for(
            asyncio.create_task(
                anext(guard.shield(delayed_stream()).__aiter__()),
            ),
            timeout=0.2,
        )

    assert exc_info.value.source == "output"
    assert guard.output_triggered

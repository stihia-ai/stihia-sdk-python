"""Tests for StihiaClient."""

import asyncio
from datetime import UTC, datetime

import httpx
import pytest
import respx
from stihia.client import StihiaClient
from stihia.exceptions import StihiaAPIError
from stihia.models import Message, OperationStatus, SenseRequest


@pytest.fixture
def mock_sense_response():
    """Mock sense API response."""
    return {
        "uid": "op-123",
        "metadata": {
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
            "processing_time_ms": 100,
        },
        "payload": {
            "messages": [
                {"role": "user", "content": "Hello"},
            ],
            "sensor": {
                "uid": "sensor-001",
                "key": "default",
                "classifiers": [],
                "aggregation_strategy": "max_severity",
                "execution_mode": "parallel",
                "timeout_ms": 3000,
            },
            "sense_result": {
                "aggregated_signal": {
                    "uid": "sig-agg-001",
                    "latency_ms": 90,
                    "payload": {
                        "severity": "low",
                        "categories": ["neutral"],
                        "confidence": 0.95,
                        "details": {},
                    },
                    "aggregation_strategy": "max_severity",
                    "classifiers": [],
                },
                "signals": [],
                "errors": [],
            },
        },
    }


def test_client_initialization(api_key, project_key, user_key, process_key, thread_key):
    """Test StihiaClient initialization."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )
    assert client.api_key == api_key
    assert client.project_key == project_key
    assert client.user_key == user_key
    assert client.process_key == process_key
    assert client.thread_key == thread_key
    client.close()


def test_client_initialization_from_env_var(
    monkeypatch, project_key, user_key, process_key, thread_key
):
    """Test StihiaClient reads API key from STIHIA_API_KEY env var."""
    env_api_key = "sk-env-test-456"
    monkeypatch.setenv("STIHIA_API_KEY", env_api_key)

    client = StihiaClient(
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )
    assert client.api_key == env_api_key
    assert client.project_key == project_key
    assert client.user_key == user_key
    assert client.process_key == process_key
    assert client.thread_key == thread_key
    client.close()


def test_client_explicit_api_key_takes_precedence(
    monkeypatch, api_key, project_key, user_key, process_key, thread_key
):
    """Test explicit api_key parameter takes precedence over env var."""
    env_api_key = "sk-env-test-789"
    monkeypatch.setenv("STIHIA_API_KEY", env_api_key)

    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )
    assert client.api_key == api_key  # Should use explicit, not env var
    client.close()


def test_client_raises_error_when_no_api_key(
    monkeypatch, project_key, user_key, process_key, thread_key
):
    """Test client raises ValueError when no API key is provided."""
    # Ensure env var is not set
    monkeypatch.delenv("STIHIA_API_KEY", raising=False)

    with pytest.raises(
        ValueError,
        match="api_key is required. Provide it directly or set STIHIA_API_KEY env var.",
    ):
        StihiaClient(
            project_key=project_key,
            user_key=user_key,
            process_key=process_key,
            thread_key=thread_key,
        )


def test_client_requires_project_key(
    api_key, user_key, process_key, thread_key, test_messages, run_key
):
    """Test client raises error if project_key is missing."""
    client = StihiaClient(
        api_key=api_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    with pytest.raises(ValueError, match="project_key is required"):
        client.sense(
            messages=test_messages,
            sensor="default",
            run_key=run_key,
        )

    client.close()


def test_client_requires_user_key(
    api_key, project_key, process_key, thread_key, test_messages, run_key
):
    """Test client raises error if user_key is missing."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    with pytest.raises(ValueError, match="user_key is required"):
        client.sense(
            messages=test_messages,
            sensor="default",
            run_key=run_key,
        )

    client.close()


def test_client_requires_process_key(
    api_key, project_key, user_key, thread_key, test_messages, run_key
):
    """Test client raises error if process_key is missing."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        thread_key=thread_key,
    )

    with pytest.raises(ValueError, match="process_key is required"):
        client.sense(
            messages=test_messages,
            sensor="default",
            run_key=run_key,
        )

    client.close()


def test_client_requires_thread_key(
    api_key, project_key, user_key, process_key, test_messages, run_key
):
    """Test client raises error if thread_key is missing."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
    )

    with pytest.raises(ValueError, match="thread_key is required"):
        client.sense(
            messages=test_messages,
            sensor="default",
            run_key=run_key,
        )

    client.close()


def test_client_requires_run_key(
    api_key, project_key, user_key, process_key, thread_key, test_messages
):
    """Test client raises error if run_key is missing."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    with pytest.raises(ValueError, match="run_key is required"):
        client.sense(
            messages=test_messages,
            sensor="default",
        )

    client.close()


@respx.mock
def test_client_sense_success(
    api_key,
    project_key,
    user_key,
    process_key,
    thread_key,
    test_messages,
    run_key,
    mock_sense_response,
):
    """Test successful sense call."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    result = client.sense(
        messages=test_messages,
        sensor="default",
        run_key=run_key,
    )

    assert result.uid == "op-123"
    assert result.metadata.status == OperationStatus.DONE
    assert result.payload is not None
    assert result.payload.sense_result.aggregated_signal.payload.severity == "low"

    client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_asense_success(
    api_key,
    project_key,
    user_key,
    process_key,
    thread_key,
    test_messages,
    run_key,
    mock_sense_response,
):
    """Test successful async sense call."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    result = await client.asense(
        messages=test_messages,
        sensor="default",
        run_key=run_key,
    )

    assert result.uid == "op-123"
    assert result.metadata.status == OperationStatus.DONE

    await client.aclose()


@respx.mock
def test_client_sense_api_error(
    api_key, project_key, user_key, process_key, thread_key, test_messages, run_key
):
    """Test sense call with API error."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(400, json={"detail": "Invalid sensor"})
    )

    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    with pytest.raises(StihiaAPIError) as exc_info:
        client.sense(
            messages=test_messages,
            sensor="invalid-sensor",
            run_key=run_key,
        )

    assert exc_info.value.status_code == 400
    assert "Invalid sensor" in str(exc_info.value)

    client.close()


@respx.mock
@pytest.mark.asyncio
async def test_client_sense_background(
    api_key,
    project_key,
    user_key,
    process_key,
    thread_key,
    test_messages,
    run_key,
    mock_sense_response,
):
    """Test background sense call."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    completed = []
    errors = []

    def on_complete(result):
        completed.append(result)

    def on_error(error):
        errors.append(error)

    # Fire-and-forget call
    client.sense_background(
        messages=test_messages,
        sensor="default",
        run_key=run_key,
        on_complete=on_complete,
        on_error=on_error,
    )

    # Give it time to complete
    await asyncio.sleep(0.1)

    assert len(completed) == 1
    assert len(errors) == 0
    assert completed[0].uid == "op-123"

    await client.aclose()


def test_client_converts_message_objects(
    api_key,
    project_key,
    user_key,
    process_key,
    thread_key,
    run_key,
    mock_sense_response,
):
    """Test client converts Message objects to dicts."""
    with respx.mock:
        respx.post("https://api.stihia.ai/v1/sense").mock(
            return_value=httpx.Response(200, json=mock_sense_response)
        )

        client = StihiaClient(
            api_key=api_key,
            project_key=project_key,
            user_key=user_key,
            process_key=process_key,
            thread_key=thread_key,
        )

        messages = [
            Message(role="user", content="Hello"),
            Message(role="assistant", content="Hi"),
        ]

        result = client.sense(
            messages=messages,
            sensor="default",
            run_key=run_key,
        )

        assert result.uid == "op-123"

        client.close()


def test_client_context_manager(
    api_key, project_key, user_key, process_key, thread_key
):
    """Test StihiaClient as context manager."""
    with StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    ) as client:
        assert client.api_key == api_key


@pytest.mark.asyncio
async def test_client_async_context_manager(
    api_key, project_key, user_key, process_key, thread_key
):
    """Test StihiaClient as async context manager."""
    async with StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    ) as client:
        assert client.api_key == api_key


# -- SenseRequest overload tests -----------------------------------------------


@pytest.fixture
def sense_request(
    project_key, user_key, process_key, thread_key, run_key, test_messages
):
    """Pre-built SenseRequest for overload tests."""
    return SenseRequest(
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
        run_key=run_key,
        sensor="default",
        messages=[Message(**m) for m in test_messages],
    )


@respx.mock
def test_sense_with_request_object(api_key, sense_request, mock_sense_response):
    """Test sense() accepts a pre-built SenseRequest (positional)."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    # No client defaults needed — SenseRequest is self-contained
    client = StihiaClient(api_key=api_key)
    result = client.sense(sense_request)

    assert result.uid == "op-123"
    assert result.metadata.status == OperationStatus.DONE
    client.close()


@respx.mock
def test_sense_request_bypasses_key_resolution(api_key, mock_sense_response):
    """SenseRequest path doesn't use client defaults or StihiaContext."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    # Client has NO defaults — would fail with kwargs path
    client = StihiaClient(api_key=api_key)
    req = SenseRequest(
        project_key="override-proj",
        user_key="override-user",
        process_key="override-proc",
        thread_key="override-thread",
        run_key="override-run",
        sensor="prompt-injection",
        messages=[Message(role="user", content="test")],
    )
    result = client.sense(req)
    assert result.uid == "op-123"

    # Verify the request body sent to the API
    sent = respx.calls.last.request.content
    import json

    body = json.loads(sent)
    assert body["project_key"] == "override-proj"
    assert body["user_key"] == "override-user"
    # *_uid fields (None) should be stripped by exclude_none
    assert "project_uid" not in body

    client.close()


@respx.mock
@pytest.mark.asyncio
async def test_asense_with_request_object(api_key, sense_request, mock_sense_response):
    """Test asense() accepts a pre-built SenseRequest."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(api_key=api_key)
    result = await client.asense(sense_request)

    assert result.uid == "op-123"
    assert result.metadata.status == OperationStatus.DONE
    await client.aclose()


@respx.mock
@pytest.mark.asyncio
async def test_sense_background_with_request_object(
    api_key, sense_request, mock_sense_response
):
    """Test sense_background() accepts a pre-built SenseRequest."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(api_key=api_key)
    completed = []

    def on_complete(result):
        completed.append(result)

    client.sense_background(sense_request, on_complete=on_complete)

    await asyncio.sleep(0.1)
    assert len(completed) == 1
    assert completed[0].uid == "op-123"
    await client.aclose()


def test_sense_raises_when_sensor_missing_with_messages(
    api_key, project_key, user_key, process_key, thread_key, test_messages
):
    """sense() raises ValueError if sensor is None when passing messages."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )
    with pytest.raises(ValueError, match="sensor is required"):
        client.sense(test_messages, None, run_key="r1")  # type: ignore[call-overload]
    client.close()


def test_build_sense_request(
    api_key,
    project_key,
    user_key,
    process_key,
    thread_key,
    run_key,
    test_messages,
):
    """build_sense_request() resolves keys and returns a SenseRequest."""
    client = StihiaClient(
        api_key=api_key,
        project_key=project_key,
        user_key=user_key,
        process_key=process_key,
        thread_key=thread_key,
    )

    req = client.build_sense_request(
        messages=test_messages,
        sensor="prompt-injection",
        run_key=run_key,
    )

    assert isinstance(req, SenseRequest)
    assert req.project_key == project_key
    assert req.user_key == user_key
    assert req.process_key == process_key
    assert req.thread_key == thread_key
    assert req.run_key == run_key
    assert req.sensor == "prompt-injection"
    assert len(req.messages) == 2
    client.close()


def test_build_sense_request_raises_missing_key(api_key, test_messages, run_key):
    """build_sense_request() raises ValueError when required keys are missing."""
    client = StihiaClient(api_key=api_key)
    with pytest.raises(ValueError, match="project_key is required"):
        client.build_sense_request(
            messages=test_messages, sensor="default", run_key=run_key
        )
    client.close()


@respx.mock
def test_sense_request_reuse_across_calls(api_key, sense_request, mock_sense_response):
    """Same SenseRequest can be used for multiple sense() calls."""
    respx.post("https://api.stihia.ai/v1/sense").mock(
        return_value=httpx.Response(200, json=mock_sense_response)
    )

    client = StihiaClient(api_key=api_key)
    r1 = client.sense(sense_request)
    r2 = client.sense(sense_request)

    assert r1.uid == r2.uid == "op-123"
    assert len(respx.calls) == 2
    client.close()

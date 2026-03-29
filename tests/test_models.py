"""Tests for SDK models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from stihia.models import (
    Message,
    MessageRole,
    OperationMetadata,
    OperationStatus,
    SenseRequest,
    SignalSeverity,
)


def test_message_creation():
    """Test Message model creation."""
    msg = Message(role=MessageRole.USER, content="Hello")
    assert msg.role == MessageRole.USER
    assert msg.content == "Hello"


def test_message_with_string_role():
    """Test Message accepts string roles."""
    msg = Message(role="user", content="Hello")
    assert msg.content == "Hello"


def test_message_content_length_validation():
    """Test Message content length validation."""
    # Should work
    msg = Message(role="user", content="x" * 100000)
    assert len(msg.content) == 100000

    # Should fail
    with pytest.raises(ValidationError):
        Message(role="user", content="x" * 100001)


def test_sense_request_creation(test_messages):
    """Test SenseRequest model creation."""
    request = SenseRequest(
        project_key="test-project",
        user_key="test-user",
        process_key="test-process",
        thread_key="test-thread",
        run_key="test-run",
        sensor="default",
        messages=test_messages,
    )
    assert request.project_key == "test-project"
    assert request.user_key == "test-user"
    assert request.process_key == "test-process"
    assert request.thread_key == "test-thread"
    assert request.run_key == "test-run"
    assert request.sensor == "default"
    assert len(request.messages) == 2


def test_sense_request_with_sensor_dict(test_messages):
    """Test SenseRequest with sensor config dict."""
    request = SenseRequest(
        project_key="test-project",
        user_key="test-user",
        process_key="test-process",
        thread_key="test-thread",
        run_key="test-run",
        sensor={"type": "prompt-injection", "timeout_ms": 5000},
        messages=test_messages,
    )
    assert isinstance(request.sensor, dict)
    assert request.sensor["type"] == "prompt-injection"


def test_sense_request_messages_validation():
    """Test SenseRequest messages validation."""
    # Should fail - no messages
    with pytest.raises(ValidationError):
        SenseRequest(
            project_key="test",
            user_key="test",
            process_key="test",
            thread_key="test",
            run_key="test",
            sensor="default",
            messages=[],
        )

    # Should fail - too many messages
    with pytest.raises(ValidationError):
        SenseRequest(
            project_key="test",
            user_key="test",
            process_key="test",
            thread_key="test",
            run_key="test",
            sensor="default",
            messages=[{"role": "user", "content": "test"}] * 101,
        )


def test_operation_metadata_utc_validation():
    """Test OperationMetadata ensures UTC timestamps."""
    now_utc = datetime.now(UTC)

    metadata = OperationMetadata(
        status=OperationStatus.DONE,
        org_uid="org-123",
        org_name="Test Org",
        project_key="test-project",
        user_key="test-user",
        process_key="test-process",
        thread_key="test-thread",
        run_key="test-run",
        start_timestamp=now_utc,
        end_timestamp=now_utc,
    )

    assert metadata.start_timestamp.tzinfo == UTC
    assert metadata.end_timestamp.tzinfo == UTC


def test_operation_metadata_requires_aware_datetime():
    """Test OperationMetadata requires timezone-aware datetimes."""
    now_naive = datetime.now()  # No timezone

    with pytest.raises(ValidationError):
        OperationMetadata(
            status=OperationStatus.DONE,
            org_uid="org-123",
            org_name="Test Org",
            project_key="test-project",
            user_key="test-user",
            process_key="test-process",
            thread_key="test-thread",
            run_key="test-run",
            start_timestamp=now_naive,
            end_timestamp=now_naive,
        )


def test_signal_severity_enum():
    """Test SignalSeverity enum values."""
    assert SignalSeverity.LOW == "low"
    assert SignalSeverity.MEDIUM == "medium"
    assert SignalSeverity.HIGH == "high"
    assert SignalSeverity.CRITICAL == "critical"

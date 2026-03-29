"""Stihia SDK response and request models.

Response hierarchy returned by ``client.sense()``::

    SenseOperation  (= Operation[SenseOperationPayload])
    ├── uid
    ├── metadata          → OperationMetadata (status, tracing, timing)
    └── payload           → SenseOperationPayload
        ├── messages      → list[Message]
        ├── sensor
        └── sense_result  → SenseResult
            ├── aggregated_signal → AggregatedSignal
            │   └── payload       → SignalPayload (severity, categories, confidence)
            ├── signals           → list[ClassifierSignal]
            │   └── payload       → SignalPayload
            └── errors

Typical usage::

    op = client.sense(messages=..., sensor="prompt-injection", ...)
    result = op.payload.sense_result
    if result.aggregated_signal.payload.severity in ("high", "critical"):
        print(result.aggregated_signal.payload.categories)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AwareDatetime, BaseModel, Field, field_validator


class MessageRole(StrEnum):
    """Role of a message in a conversation (user, assistant, system, etc.)."""

    USER = "user"
    HUMAN = "human"
    AI = "ai"
    ASSISTANT = "assistant"
    SYSTEM = "system"
    TOOL = "tool"
    FUNCTION = "function"


class Message(BaseModel):
    """Single message in a conversation. Pass to ``client.sense(messages=...)``."""

    role: MessageRole | str
    content: Annotated[
        str,
        Field(max_length=100000, description="Message content (max 100KB)"),
    ]


class SenseRequest(BaseModel):
    """Request body sent to ``/v1/sense``. Built automatically by ``StihiaClient``."""

    # Required for tracing: Client-provided keys
    project_key: Annotated[
        str, Field(..., description="Unique project key defined by the client")
    ]
    user_key: Annotated[
        str,
        Field(
            ...,
            description="User who triggered the run. User key defined by the client.",
        ),
    ]
    process_key: Annotated[
        str, Field(..., description="Unique process key defined by the client")
    ]
    thread_key: Annotated[
        str,
        Field(
            ...,
            description=(
                "Groups consecutive runs with shared context. "
                "Thread key defined by the client."
            ),
        ),
    ]
    run_key: Annotated[
        str, Field(..., description="Unique run key defined by the client")
    ]

    # Optional for future compatibility: Server-generated IDs
    project_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Project ID"),
    ]
    user_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated User ID"),
    ]
    process_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Process ID"),
    ]
    thread_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Thread ID"),
    ]
    run_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Run ID"),
    ]

    # Required for sense operation: Sensor configuration and messages to analyze
    sensor: Annotated[
        str | dict[str, Any],
        Field(
            ...,
            description=(
                "Sensor configuration: preset name (string) or Sensor config object. "
                "Examples: 'prompt-injection' or "
                "{'type': 'prompt-injection', 'timeout_ms': 5000}"
            ),
        ),
    ]
    messages: Annotated[
        list[Message],
        Field(
            min_length=1,
            max_length=100,
            description="Messages to analyze (max 100)",
        ),
    ]


class OperationStatus(StrEnum):
    """Lifecycle status of a sense operation. Check via ``op.metadata.status``."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


class OperationMetadata(BaseModel):
    """Status, tracing keys, and timing for a sense operation (``op.metadata``)."""

    # Status Metadata
    status: Annotated[
        OperationStatus, Field(..., description="Status of the operation")
    ]
    errors: Annotated[
        list[str], Field(default_factory=list, description="List of errors")
    ]

    # Tracing Metadata
    org_uid: Annotated[
        str,
        Field(..., description="Unique Organization ID"),
    ]
    org_name: Annotated[
        str,
        Field(..., description="Name of the organization"),
    ]
    project_key: Annotated[
        str, Field(..., description="Project key provided by the client")
    ]
    project_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Project ID"),
    ]
    user_key: Annotated[
        str,
        Field(
            ...,
            description="User who triggered the run. User key defined by the client.",
        ),
    ]
    user_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated User ID"),
    ]
    process_key: Annotated[
        str, Field(..., description="Process key provided by the client")
    ]
    process_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Process ID"),
    ]
    thread_key: Annotated[
        str,
        Field(
            ...,
            description=(
                "Groups consecutive runs with shared context. "
                "Thread key defined by the client."
            ),
        ),
    ]
    thread_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Thread ID"),
    ]
    run_key: Annotated[str, Field(..., description="Run key provided by the client")]
    run_uid: Annotated[
        str | None,
        Field(default=None, description="Internally generated Run ID"),
    ]

    # Performance Metadata (always UTC)
    start_timestamp: Annotated[
        AwareDatetime, Field(..., description="Start timestamp of the operation (UTC)")
    ]
    end_timestamp: Annotated[
        AwareDatetime, Field(..., description="End timestamp of the operation (UTC)")
    ]
    processing_time_ms: Annotated[
        int | None,
        Field(default=None, description="Processing time in milliseconds"),
    ]

    @field_validator("start_timestamp", "end_timestamp", mode="after")
    @classmethod
    def ensure_utc(cls, v: datetime) -> datetime:
        """Ensure datetime is in UTC timezone."""
        if v.tzinfo is None:
            raise ValueError("Datetime must be timezone-aware")
        return v.astimezone(UTC)


class SignalCategory(StrEnum):
    """Threat category detected by a classifier or the aggregated signal."""

    # Default categories (no threat detected or classification failed)
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"

    # Threat categories
    PROMPT_INJECTION = "prompt_injection"
    SENSITIVE_DATA = "sensitive_data"
    TOXIC_CONTENT = "toxic_content"


class SignalSeverity(StrEnum):
    """Severity level. HIGH and CRITICAL are typically treated as threats."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SignalPayload(BaseModel):
    """Core detection data: severity, categories, and confidence score."""

    severity: Annotated[
        SignalSeverity, Field(..., description="Severity of the signal")
    ]
    categories: Annotated[
        list[SignalCategory], Field(..., description="Categories of the signal")
    ]
    subcategory: Annotated[
        str | None, Field(default=None, description="Subcategory of the signal")
    ]
    details: Annotated[
        dict[str, Any], Field(default_factory=dict, description="Details of the signal")
    ]
    confidence: Annotated[
        float, Field(ge=0.0, le=1.0, description="Confidence of the signal")
    ]


class AggregatedSignal(BaseModel):
    """Combined signal across all classifiers — primary field for threat decisions.

    Access via ``op.payload.sense_result.aggregated_signal``.
    """

    uid: Annotated[str, Field(..., description="Unique internal signal ID")]
    payload: Annotated[SignalPayload, Field(..., description="Payload of the signal")]
    latency_ms: Annotated[int, Field(default=0, description="Latency in milliseconds")]
    aggregation_strategy: Annotated[
        str,
        Field(..., description="Aggregation strategy used"),
    ]
    classifiers: Annotated[
        list[dict[str, Any]],
        Field(..., description="Classifiers that produced signals"),
    ]


class ClassifierSignal(BaseModel):
    """Signal from a single classifier. See ``op.payload.sense_result.signals``."""

    uid: Annotated[str, Field(..., description="Unique internal signal ID")]
    payload: Annotated[SignalPayload, Field(..., description="Payload of the signal")]
    latency_ms: Annotated[int, Field(default=0, description="Latency in milliseconds")]
    classifier: Annotated[
        dict[str, Any], Field(..., description="Classifier that produced the signal")
    ]


class SenseResult(BaseModel):
    """Full sense result containing aggregated and per-classifier signals."""

    aggregated_signal: Annotated[
        AggregatedSignal, Field(..., description="Aggregated signal")
    ]
    signals: Annotated[
        list[ClassifierSignal], Field(..., description="Individual signals")
    ]
    errors: Annotated[
        list[str],
        Field(default_factory=list, description="Classifier errors during execution"),
    ]


class SenseOperationPayload(BaseModel):
    """Payload of a sense operation (``op.payload``).

    Contains analyzed messages, sensor config, and the sense result.
    """

    messages: Annotated[
        list[Message],
        Field(
            ...,
            min_length=1,
            max_length=100,
            description="Messages analyzed in the operation (max 100)",
        ),
    ]
    sense_result: Annotated[
        SenseResult | None,
        Field(default=None, description="Result of the sense operation"),
    ]
    sensor: Annotated[
        dict[str, Any], Field(..., description="Sensor that was used for the operation")
    ]


class Operation[PayloadT](BaseModel):
    """Generic operation envelope.

    ``SenseOperation`` is the concrete alias used in practice.
    """

    uid: Annotated[str, Field(..., description="Unique internal operation ID")]
    metadata: Annotated[
        OperationMetadata, Field(..., description="Metadata of the operation")
    ]
    payload: Annotated[
        PayloadT | None, Field(default=None, description="Payload of the operation")
    ]


#: Concrete type returned by ``StihiaClient.sense()`` / ``asense()``.
SenseOperation = Operation[SenseOperationPayload]

"""Stihia SDK for Python — Real-time threat detection for AI systems.

Provides ``StihiaClient`` for threat detection on LLM interactions and
``StihiaContext`` for automatic key propagation across calls.

Quickstart::

    from stihia import StihiaClient, StihiaContext

    with StihiaClient(api_key="sk-...") as client:
        with StihiaContext(process_key="onboarding", thread_key="conv-1"):
            op = client.sense(
                messages=[{"role": "user", "content": "Hello"}],
                sensor="prompt-injection",
                project_key="my-project",
                user_key="user-42",
            )
            severity = op.payload.sense_result.aggregated_signal.payload.severity
            print(f"Severity: {severity}")
"""

from stihia.client import StihiaClient
from stihia.context import (
    StihiaContext,
    get_current_process_key,
    get_current_run_key,
    get_current_thread_key,
)
from stihia.exceptions import (
    StihiaAPIError,
    StihiaError,
    StihiaThreatDetectedError,
)
from stihia.guard import SenseGuard
from stihia.models import (
    AggregatedSignal,
    ClassifierSignal,
    Message,
    MessageRole,
    Operation,
    OperationMetadata,
    OperationStatus,
    SenseOperation,
    SenseOperationPayload,
    SenseRequest,
    SenseResult,
    SignalCategory,
    SignalPayload,
    SignalSeverity,
)
from stihia.processors import PostProcessor, strip_markdown_images, text_processor

__all__ = [
    "AggregatedSignal",
    "ClassifierSignal",
    # Models
    "Message",
    "MessageRole",
    "Operation",
    "OperationMetadata",
    "OperationStatus",
    # Processors
    "PostProcessor",
    # Guard
    "SenseGuard",
    "SenseOperation",
    "SenseOperationPayload",
    "SenseRequest",
    "SenseResult",
    "SignalCategory",
    "SignalPayload",
    "SignalSeverity",
    "StihiaAPIError",
    # Client
    "StihiaClient",
    # Context
    "StihiaContext",
    # Exceptions
    "StihiaError",
    "StihiaThreatDetectedError",
    "get_current_process_key",
    "get_current_run_key",
    "get_current_thread_key",
    "strip_markdown_images",
    "text_processor",
]

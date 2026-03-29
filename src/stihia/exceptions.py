"""Stihia SDK exceptions."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from stihia.models import SenseOperation


class StihiaError(Exception):
    """Base exception for Stihia SDK."""


class StihiaThreatDetectedError(StihiaError):
    """Raised when a threat is detected in blocking/raise mode.

    Attributes:
        operation: The full ``SenseOperation`` that triggered the error.
        source: ``"input"``, ``"output"``, or ``"unknown"``.
        severity: Aggregated ``SignalSeverity`` (e.g. ``"high"``).
        categories: List of ``SignalCategory`` values detected.
    """

    def __init__(self, operation: SenseOperation, source: str | None = None):
        """Initialize with the triggering operation.

        Args:
            operation: ``SenseOperation`` containing the threat details.
            source: Where the threat was detected (``"input"``/``"output"``).
        """
        self.operation = operation
        self.source = source or "unknown"
        assert operation.payload is not None
        assert operation.payload.sense_result is not None
        self.severity = operation.payload.sense_result.aggregated_signal.payload.severity
        self.categories = operation.payload.sense_result.aggregated_signal.payload.categories
        super().__init__(f"Threat detected: {self.severity} severity, categories: {self.categories}")


class StihiaAPIError(StihiaError):
    """Raised when the Stihia API returns an error.

    Attributes:
        status_code: HTTP status code (``0`` for connection errors).
        detail: Error message from the API response body.
    """

    def __init__(self, status_code: int, detail: str):
        """Initialize with status code and detail.

        Args:
            status_code: HTTP status code.
            detail: Error detail string.
        """
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")

"""Pytest configuration for the Stihia SDK for Python tests."""

import pytest


@pytest.fixture
def api_key():
    """Test API key."""
    return "sk-test-123"


@pytest.fixture
def project_key():
    """Test project key."""
    return "test-project"


@pytest.fixture
def user_key():
    """Test user key."""
    return "test-user"


@pytest.fixture
def process_key():
    """Test process key."""
    return "test-process"


@pytest.fixture
def thread_key():
    """Test thread key."""
    return "test-thread"


@pytest.fixture
def run_key():
    """Test run key."""
    return "test-run-123"


@pytest.fixture
def test_messages():
    """Test messages."""
    return [
        {"role": "user", "content": "Hello, world!"},
        {"role": "assistant", "content": "Hi there!"},
    ]

"""Tests for BackgroundTaskManager."""

import asyncio
import time

import pytest

from stihia.background import BackgroundTaskManager


@pytest.mark.asyncio
async def test_background_manager_async_context():
    """Test BackgroundTaskManager in async context."""
    manager = BackgroundTaskManager(max_workers=2)
    results = []

    async def test_coro(value):
        await asyncio.sleep(0.01)
        return value

    def on_complete(result):
        results.append(result)

    # Submit multiple tasks
    for i in range(5):
        manager.submit(test_coro(i), on_complete=on_complete)

    # Give tasks time to complete
    await asyncio.sleep(0.1)

    assert len(results) == 5
    assert set(results) == {0, 1, 2, 3, 4}

    await manager.ashutdown()


@pytest.mark.asyncio
async def test_background_manager_error_handling():
    """Test BackgroundTaskManager handles errors."""
    manager = BackgroundTaskManager()
    errors = []

    async def failing_coro():
        await asyncio.sleep(0.01)
        raise ValueError("Test error")

    def on_error(error):
        errors.append(error)

    manager.submit(failing_coro(), on_error=on_error)

    await asyncio.sleep(0.05)
    assert len(errors) == 1
    assert isinstance(errors[0], ValueError)
    assert str(errors[0]) == "Test error"

    await manager.ashutdown()


@pytest.mark.asyncio
async def test_background_manager_shutdown():
    """Test BackgroundTaskManager graceful shutdown."""
    manager = BackgroundTaskManager()
    completed = []

    async def slow_coro(value):
        await asyncio.sleep(0.05)
        return value

    def on_complete(result):
        completed.append(result)

    # Submit tasks
    for i in range(3):
        manager.submit(slow_coro(i), on_complete=on_complete)

    # Shutdown and wait
    await manager.ashutdown(timeout=1.0)

    # All tasks should complete
    assert len(completed) == 3


def test_background_manager_sync_context():
    """Test BackgroundTaskManager in sync context."""
    manager = BackgroundTaskManager(max_workers=2)
    results = []

    async def test_coro(value):
        await asyncio.sleep(0.01)
        return value

    def on_complete(result):
        results.append(result)

    # Submit tasks from sync context
    for i in range(3):
        manager.submit(test_coro(i), on_complete=on_complete)

    # Give tasks time to complete in thread pool
    time.sleep(0.2)

    assert len(results) == 3
    assert set(results) == {0, 1, 2}

    manager.shutdown()


@pytest.mark.asyncio
async def test_background_manager_ignores_after_shutdown():
    """Test BackgroundTaskManager ignores tasks after shutdown."""
    manager = BackgroundTaskManager()
    results = []

    async def test_coro(value):
        return value

    def on_complete(result):
        results.append(result)

    # Shutdown first
    await manager.ashutdown()

    # Try to submit after shutdown
    manager.submit(test_coro(42), on_complete=on_complete)

    await asyncio.sleep(0.05)

    # Should not have been executed
    assert len(results) == 0

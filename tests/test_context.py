"""Tests for StihiaContext."""

import asyncio

import pytest
from stihia import (
    StihiaContext,
    get_current_process_key,
    get_current_run_key,
    get_current_thread_key,
)


def test_context_auto_generates_thread_key():
    """Test that thread_key is auto-generated when omitted."""
    with StihiaContext() as ctx:
        assert ctx.thread_key is not None
        assert isinstance(ctx.thread_key, str)
        assert len(ctx.thread_key) > 0


def test_context_auto_generated_thread_key_set_in_context_vars():
    """Test that auto-generated thread_key is set in context vars."""
    with StihiaContext() as ctx:
        assert get_current_thread_key() == ctx.thread_key


def test_different_invocations_get_different_auto_generated_thread_keys():
    """Test that different invocations get different auto-generated thread_keys."""
    with StihiaContext() as ctx1:
        key1 = ctx1.thread_key
    with StihiaContext() as ctx2:
        key2 = ctx2.thread_key
    assert key1 != key2


def test_context_generates_run_key():
    """Test that context generates a run_key."""
    with StihiaContext(thread_key="test-thread") as ctx:
        assert ctx.run_key is not None
        assert isinstance(ctx.run_key, str)
        assert len(ctx.run_key) > 0


def test_context_uses_custom_run_key():
    """Test that context uses provided run_key."""
    custom_key = "my-custom-key"
    with StihiaContext(thread_key="test-thread", run_key=custom_key) as ctx:
        assert ctx.run_key == custom_key


def test_context_sets_process_key():
    """Test that context sets process_key."""
    with StihiaContext(process_key="my-process", thread_key="test-thread") as ctx:
        assert ctx.process_key == "my-process"
        assert get_current_process_key() == "my-process"
        assert ctx.thread_key == "test-thread"
        assert get_current_thread_key() == "test-thread"


def test_context_sets_both_keys():
    """Test that context sets both run_key and process_key."""
    with StihiaContext(
        process_key="my-process", thread_key="test-thread", run_key="my-run"
    ) as ctx:
        assert ctx.process_key == "my-process"
        assert get_current_process_key() == "my-process"
        assert ctx.thread_key == "test-thread"
        assert get_current_thread_key() == "test-thread"
        assert ctx.run_key == "my-run"
        assert get_current_run_key() == "my-run"


def test_context_sets_thread_key():
    """Test that context sets thread_key."""
    with StihiaContext(thread_key="my-thread") as ctx:
        assert ctx.thread_key == "my-thread"
        assert get_current_thread_key() == "my-thread"


def test_context_sets_all_keys():
    """Test that context sets run_key, process_key, and thread_key."""
    with StihiaContext(
        process_key="my-process", thread_key="my-thread", run_key="my-run"
    ) as ctx:
        assert ctx.process_key == "my-process"
        assert get_current_process_key() == "my-process"
        assert ctx.thread_key == "my-thread"
        assert get_current_thread_key() == "my-thread"
        assert ctx.run_key == "my-run"
        assert get_current_run_key() == "my-run"


def test_get_current_run_key_returns_none_outside_context():
    """Test that get_current_run_key returns None outside context."""
    assert get_current_run_key() is None


def test_get_current_process_key_returns_none_outside_context():
    """Test that get_current_process_key returns None outside context."""
    assert get_current_process_key() is None


def test_get_current_thread_key_returns_none_outside_context():
    """Test that get_current_thread_key returns None outside context."""
    assert get_current_thread_key() is None


def test_get_current_run_key_returns_key_inside_context():
    """Test that get_current_run_key returns key inside context."""
    with StihiaContext(thread_key="test-thread") as ctx:
        assert get_current_run_key() == ctx.run_key


def test_context_restores_previous_state():
    """Test that context restores previous state on exit."""
    assert get_current_run_key() is None
    assert get_current_process_key() is None
    assert get_current_thread_key() is None

    with StihiaContext(process_key="test", thread_key="test-thread"):
        assert get_current_process_key() == "test"
        assert get_current_thread_key() == "test-thread"
        assert get_current_run_key() is not None

    assert get_current_process_key() is None
    assert get_current_thread_key() is None
    assert get_current_run_key() is None


def test_nested_contexts():
    """Test nested contexts work correctly."""
    with StihiaContext(
        process_key="outer-process", thread_key="outer-thread", run_key="outer"
    ) as outer:
        assert get_current_process_key() == "outer-process"
        assert get_current_thread_key() == "outer-thread"
        assert get_current_run_key() == "outer"

        with StihiaContext(
            process_key="inner-process", thread_key="inner-thread", run_key="inner"
        ) as inner:
            assert inner.process_key == "inner-process"
            assert get_current_process_key() == "inner-process"
            assert inner.thread_key == "inner-thread"
            assert get_current_thread_key() == "inner-thread"
            assert inner.run_key == "inner"
            assert get_current_run_key() == "inner"

        # Restored to outer
        assert get_current_process_key() == "outer-process"
        assert get_current_thread_key() == "outer-thread"
        assert get_current_run_key() == "outer"
        assert outer.run_key == "outer"

    # Restored to None
    assert get_current_process_key() is None
    assert get_current_thread_key() is None
    assert get_current_run_key() is None


def test_different_invocations_get_different_keys():
    """Test that different context invocations get different keys."""
    with StihiaContext(thread_key="test-thread") as ctx1:
        key1 = ctx1.run_key

    with StihiaContext(thread_key="test-thread") as ctx2:
        key2 = ctx2.run_key

    assert key1 != key2


def test_process_key_optional():
    """Test that process_key is optional."""
    with StihiaContext(thread_key="test-thread") as ctx:
        assert ctx.run_key is not None
        assert ctx.process_key is None
        assert ctx.thread_key == "test-thread"
        assert get_current_process_key() is None
        assert get_current_thread_key() == "test-thread"


@pytest.mark.asyncio
async def test_async_context():
    """Test async context manager."""
    async with StihiaContext(
        process_key="async-process", thread_key="async-thread"
    ) as ctx:
        assert ctx.process_key == "async-process"
        assert get_current_process_key() == "async-process"
        assert ctx.thread_key == "async-thread"
        assert get_current_thread_key() == "async-thread"
        assert ctx.run_key is not None
        assert get_current_run_key() == ctx.run_key

    assert get_current_process_key() is None
    assert get_current_thread_key() is None
    assert get_current_run_key() is None


@pytest.mark.asyncio
async def test_async_context_with_custom_keys():
    """Test async context with custom keys."""
    async with StihiaContext(
        process_key="async-process", thread_key="async-thread", run_key="async-run"
    ) as ctx:
        assert ctx.process_key == "async-process"
        assert get_current_process_key() == "async-process"
        assert ctx.thread_key == "async-thread"
        assert get_current_thread_key() == "async-thread"
        assert ctx.run_key == "async-run"
        assert get_current_run_key() == "async-run"


@pytest.mark.asyncio
async def test_context_isolated_across_async_tasks():
    """Test that context is isolated across concurrent async tasks."""
    results = []

    async def task_with_context(task_id: str):
        async with StihiaContext(
            process_key=f"process-{task_id}",
            thread_key=f"thread-{task_id}",
            run_key=task_id,
        ):
            await asyncio.sleep(0.01)  # Simulate some async work
            results.append(
                (
                    get_current_process_key(),
                    get_current_thread_key(),
                    get_current_run_key(),
                    task_id,
                )
            )

    # Run multiple tasks concurrently
    await asyncio.gather(
        task_with_context("task-1"),
        task_with_context("task-2"),
        task_with_context("task-3"),
    )

    # Each task should have seen its own keys
    assert len(results) == 3
    assert ("process-task-1", "thread-task-1", "task-1", "task-1") in results
    assert ("process-task-2", "thread-task-2", "task-2", "task-2") in results
    assert ("process-task-3", "thread-task-3", "task-3", "task-3") in results


def test_exception_in_context_restores_state():
    """Test that exception in context still restores state."""
    assert get_current_run_key() is None
    assert get_current_process_key() is None
    assert get_current_thread_key() is None

    try:
        with StihiaContext(
            process_key="test-process", thread_key="test-thread", run_key="test"
        ):
            assert get_current_process_key() == "test-process"
            assert get_current_thread_key() == "test-thread"
            assert get_current_run_key() == "test"
            raise ValueError("Test exception")
    except ValueError:
        pass

    # Should still restore to None
    assert get_current_process_key() is None
    assert get_current_thread_key() is None
    assert get_current_run_key() is None

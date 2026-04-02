# Stihia SDK for Python

[![Website](https://img.shields.io/badge/stihia.ai-website-blue)](https://stihia.ai)
[![CI](https://github.com/stihia-ai/stihia-sdk-python/actions/workflows/ci.yml/badge.svg)](https://github.com/stihia-ai/stihia-sdk-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/stihia)](https://pypi.org/project/stihia/)
[![Python](https://img.shields.io/pypi/pyversions/stihia)](https://pypi.org/project/stihia/)
[![License](https://img.shields.io/github/license/stihia-ai/stihia-sdk-python)](LICENSE)

Python SDK for the Stihia real-time threat detection API for AI systems.

## Getting Started

This guide walks you through everything you need to start protecting your AI application with Stihia — from creating your account to seeing your first threat detection trace.

### 1. Create your Stihia account

Sign up for a free account at **[app.stihia.ai](https://app.stihia.ai)**. You can register with your email or use a social login.

### 2. Set up your organization

Once logged in, create a new **organization** — this is the workspace where your projects and team members live.

After creating the organization, head to **[Organization](https://app.stihia.ai/organization) → Notification Settings** to configure email alerts. This way, you'll be notified whenever Stihia detects a threat in any of your projects.

### 3. Create an API key

Navigate to **[Organization](https://app.stihia.ai/organization) → API Keys** and click **Create API Key**. Copy the generated key (it starts with `sk_`) — you'll need it in the next step.

> **Keep your API key safe.** Treat it like a password. Don't commit it to version control — use environment variables instead (see [Configuration](#configuration) below).

### 4. Install the SDK

```bash
pip install stihia
```

### 5. Run your first threat detection

Create a file called `quickstart.py` and paste the following:

```python
import os
from stihia import StihiaClient

# Best practice: load your API key from an environment variable
# export STIHIA_API_KEY="sk_..."
client = StihiaClient(
    api_key=os.environ["STIHIA_API_KEY"],
    project_key="my-first-project",
    user_key="user-1",
    process_key="quickstart",
)

# Send a message for threat detection
result = client.sense(
    messages=[{"role": "user", "content": "Hello, world!"}],
    sensor="default",
)

severity = result.payload.sense_result.aggregated_signal.payload.severity
print(f"Threat severity: {severity}")
```

Run it:

```bash
export STIHIA_API_KEY="sk_..."
python quickstart.py
```

That's it — you just ran your first Stihia sense operation! 🎉

### 6. View your traces in the Stihia Console

Every sense call is recorded as an OpenTelemetry trace. Open the **[Stihia Console Threads page](https://app.stihia.ai/threads)** to see a real-time timeline of all detections, drill into individual traces, and review threat severity details across your projects.

### 7. Explore the API reference

For the full list of endpoints, parameters, and response schemas, check out the **[API Reference](https://stihia.ai/api/reference/)**.

### 8. Need custom sensor configurations?

The default sensors cover general threats. If your use case requires more specialized detection — such as industry-specific compliance, custom threat categories, or fine-tuned sensitivity — **contact us at [support@stihia.ai](mailto:support@stihia.ai)** and we'll work with you to configure sensors tailored to your needs.

---

## Installation

```bash
pip install stihia
```

## Configuration

The SDK requires a Stihia API key for authentication. You can provide it in two ways:

### Option 1: Direct parameter (recommended for explicit control)

```python
from stihia import StihiaClient

client = StihiaClient(
    api_key="sk_...",
    project_key="my-app",
    user_key="user-123",
    process_key="chat",
)
```

### Option 2: Environment variable (recommended for security)

Set the `STIHIA_API_KEY` environment variable:

```bash
export STIHIA_API_KEY="sk_..."
```

Then initialize the client without passing the API key:

```python
from stihia import StihiaClient

client = StihiaClient(
    project_key="my-app",
    user_key="user-123",
    process_key="chat",
)
```

**Precedence**: If you provide both, the explicit `api_key` parameter takes precedence over the environment variable.

## Quick Start

```python
from stihia import StihiaClient

# Initialize client
client = StihiaClient(
    api_key="sk-...",
    project_key="my-app",
    user_key="user-123",
    process_key="chat",
)

# Non-blocking monitoring
client.sense_background(
    messages=[{"role": "user", "content": "Hello, world!"}],
    sensor="default",
    run_key="session-123",
)

# Blocking call (waits for result)
result = client.sense(
    messages=[{"role": "user", "content": "Hello, world!"}],
    sensor="default",
    run_key="session-123",
)
print(result.payload.sense_result.aggregated_signal.payload.severity)
```

## Execution Modes

### Background (Non-Blocking)

Fire-and-forget calls that don't add latency:

```python
client.sense_background(
    messages=messages,
    sensor="prompt-injection",
    run_key="session-123",
    on_complete=lambda op: print(f"Completed: {op.uid}"),
    on_error=lambda e: print(f"Error: {e}"),
)
```

### Sync Blocking

Waits for the API response:

```python
result = client.sense(
    messages=messages,
    sensor="prompt-injection",
    run_key="session-123",
)
```

### Async Blocking

For async contexts:

```python
result = await client.asense(
    messages=messages,
    sensor="prompt-injection",
    run_key="session-123",
)
```

## Stihia Context

Use `StihiaContext` to scope `thread_key`, `run_key`, and `process_key` for
sense operations. One context = one run within a thread.

```python
from stihia import StihiaClient, StihiaContext

client = StihiaClient(
    api_key="sk-...",
    project_key="my-app",
    user_key="user-123",
)

# thread_key auto-generates if omitted; run_key auto-generates if omitted
with StihiaContext(process_key="my-workflow", thread_key="conv-123") as ctx:
    client.sense(
        messages=[{"role": "user", "content": "First message"}],
        sensor="prompt-injection",
    )
    client.sense(
        messages=[{"role": "assistant", "content": "Response"}],
        sensor="sensitive-data",
    )
```

### Custom Keys

Provide your own run_key:

```python
with StihiaContext(process_key="my-process", thread_key="conv-123", run_key="custom-trace-id") as ctx:
    client.sense(messages=messages, sensor="...")
```

### Async Support

Works seamlessly with async code:

```python
async with StihiaContext(process_key="async-workflow", thread_key="conv-123") as ctx:
    await client.asense(messages=messages, sensor="...")
```

## SenseGuard

`SenseGuard` wraps an async LLM stream with concurrent input/output guardrails.
Both `input_sensor` and `output_sensor` are optional (`None` by default). When
a sensor is `None`, the corresponding API call is skipped entirely. This
enables input+output, input-only, output-only, or passthrough (post-processors
only) configurations.

When `input_sensor` is set, the input check runs concurrently with the stream
but completes before the first chunk is yielded (gate first chunk). When
`input_sensor` is `None`, chunks flow immediately with no input gate.

### Basic Usage

```python
from stihia import StihiaClient
from stihia.guard import SenseGuard

client = StihiaClient(api_key="sk-...", project_key="my-app", user_key="u1")

# Input + output guardrails
guard = SenseGuard(
    client,
    messages=[{"role": "user", "content": user_input}],
    input_sensor="default-input",
    output_sensor="default-output",
    output_check_interval=5.0,
    project_key="my-app",
    user_key="u1",
)

chunks = []
async for chunk in guard.shield(llm.astream(prompt)):
    chunks.append(chunk)

if guard.triggered:
    print("Threat source:", "input" if guard.input_triggered else "output")
```

### Output-Only (No Input Gate)

```python
guard = SenseGuard(
    client,
    messages=[{"role": "user", "content": user_input}],
    output_sensor="toxic-content",
    output_check_interval=3.0,
    project_key="my-app",
    user_key="u1",
)

async for chunk in guard.shield(llm.astream(prompt)):
    print(chunk, end="")  # chunks flow immediately — no input gate
```

### Passthrough (Post-Processors Only)

```python
from stihia import strip_markdown_images

guard = SenseGuard(
    client,
    messages=[{"role": "user", "content": user_input}],
    post_processors=[strip_markdown_images],
    project_key="my-app",
    user_key="u1",
)

async for chunk in guard.shield(llm.astream(prompt)):
    print(chunk, end="")  # no API calls, only post-processing
```

### Final-Only Output Check

Set `output_check_interval=None` to skip periodic mid-stream checks and only
run the final post-stream check. This reduces API calls and avoids mid-stream
interruptions while still validating the complete output.

```python
guard = SenseGuard(
    client,
    messages=[{"role": "user", "content": user_input}],
    input_sensor="default-input",
    output_sensor="default-output",
    output_check_interval=None,  # final check only
    project_key="my-app",
    user_key="u1",
)

async for chunk in guard.shield(llm.astream(prompt)):
    print(chunk, end="")  # all chunks delivered without interruption

if guard.output_triggered:
    print("\nOutput flagged after completion")
```

### Post-Processors

SenseGuard supports `post_processors` — callables that transform each chunk
before it is yielded to the caller. Sensors always see unmodified output.

The built-in `strip_markdown_images` processor converts `![alt](url)` to
`[alt](url)` to prevent indirect prompt injection via auto-fetched image
URLs. It is decorated with `@text_processor` so it works on both plain
strings and OpenAI-compatible streaming chunks:

```python
from stihia import SenseGuard, strip_markdown_images

guard = SenseGuard(
    client,
    messages=messages,
    input_sensor="default-input",
    post_processors=[strip_markdown_images],
    # ...
)

async for chunk in guard.shield(llm_stream):
    print(chunk)  # markdown images replaced with plain links
```

Use the `@text_processor` decorator to create your own chunk-aware
processors from simple `str -> str` functions:

```python
from stihia import text_processor

@text_processor
def redact_emails(text: str) -> str:
    """Replace email addresses with [REDACTED]."""
    import re
    return re.sub(r"\S+@\S+", "[REDACTED]", text)

guard = SenseGuard(
    client,
    messages=messages,
    input_sensor="default-input",
    post_processors=[redact_emails],
    # ...
)
```

The decorator lifts the function so that:

- `str` inputs are passed directly to the function
- OpenAI-compatible chunk objects have `choices[0].delta.content` extracted,
  transformed, and written back
- Anything else passes through unchanged

## Sensor Types

- `default` - Standard threat detection (prompt injection + PII)
- `default-input` - Input-focused comprehensive threat detection
- `default-output` - Output-focused comprehensive threat detection
- `default-input-think` - Input-focused comprehensive threat detection with additional reasoning

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development setup and guidelines.

```bash
git clone https://github.com/stihia-ai/stihia-sdk-python.git
cd stihia-sdk-python
uv sync --all-extras
uv run pytest
```

## Security

To report a security vulnerability, please see [SECURITY.md](SECURITY.md). **Do not open a public issue for security reports.**

## Contributing

Contributions are welcome! Please read the [Contributing Guide](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md) before submitting a pull request.

## License

This project is licensed under the [Apache License 2.0](LICENSE).

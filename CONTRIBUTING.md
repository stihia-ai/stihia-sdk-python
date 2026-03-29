# Contributing to Stihia SDK for Python

Thank you for your interest in contributing! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager

### Getting Started

1. Fork and clone the repository:

```bash
git clone https://github.com/stihia-ai/stihia-sdk-python.git
cd stihia-sdk-python
```

2. Install dependencies:

```bash
uv sync --all-extras
```

3. Run the test suite:

```bash
uv run pytest
```

4. Run linting and formatting checks:

```bash
uv run ruff check .
uv run ruff format --check .
```

5. Run type checking:

```bash
uv run mypy src/
```

### Auto-formatting

```bash
uv run ruff format .
uv run ruff check --fix .
```

## Making Changes

1. Create a branch from `main`:

```bash
git checkout -b your-branch-name
```

2. Make your changes, ensuring:
   - All tests pass (`uv run pytest`)
   - Code passes linting (`uv run ruff check .`)
   - Code is formatted (`uv run ruff format --check .`)
   - Type checks pass (`uv run mypy src/`)

3. Write tests for new functionality.

4. Commit with a clear, descriptive message.

## Pull Requests

- Open PRs against the `main` branch.
- Include a clear description of what the PR does and why.
- Link any related issues.
- Ensure CI passes before requesting review.

## Reporting Issues

- Use [GitHub Issues](https://github.com/stihia-ai/stihia-sdk-python/issues) for bug reports and feature requests.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## v0.1.1 - 2026-04-05

### Added

- Getting Started guide in README with step-by-step onboarding (account setup, API key creation, first sense call, console traces).

### Security

- Added `exclude-newer = "7 days"` to `[tool.uv]` to reject recently-published packages and reduce supply-chain risk.

## v0.1.0 - 2026-03-29

### Added

- Initial public release of the Stihia Python SDK.
- `StihiaClient` with sync, async, and background execution modes.
- `SenseGuard` for streaming input/output guardrails.
- `StihiaContext` for scoping sense operations.
- Post-processor support with `@text_processor` decorator.
- Built-in `strip_markdown_images` post-processor.

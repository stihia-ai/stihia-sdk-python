# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## v0.2.1 - 2026-04-06

### Added

- `SignalCategory.DESTRUCTIVE_ACTION` enum value.

### Changed

- `SenseGuard` blocking mode now withholds tail chunks (chunks received after the last periodic boundary) until the final post-stream output check passes.

### Fixed

- `SenseGuard` now validates `output_check_interval` and raises `ValueError` for non-positive values (must be a positive integer or `None`).
- Blocking output checks now terminate promptly on detected threats without waiting for the next stream chunk.
- Empty-stream input trigger handling now correctly triggers guard behavior in both raising and silent modes.

## v0.2.0 - 2026-04-06

### Added

- `output_check_mode` parameter on `SenseGuard` with two modes:
  - `"blocking"` (default) — pauses chunk delivery during periodic output checks; buffered chunks are burst-released on green light, stream terminates immediately on threat. When `output_check_interval` is `None`, all chunks are buffered and only delivered after the final post-stream check passes.
  - `"parallel"` — periodic output checks run concurrently without pausing delivery (fire-and-forget), matching the previous behaviour.

### Changed

- `output_check_interval` is now a chunk count (`int`) instead of a time-based interval (`float` seconds). For example, `30` fires a check every 30 chunks.
- Final post-stream output check now raises `StihiaThreatDetectedError` when `raise_on_trigger=True` (previously threats were only surfaced via `output_triggered`).

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

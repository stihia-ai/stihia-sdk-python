"""Post-processors for SenseGuard output chunks.

A post-processor is any sync callable ``T -> T`` that transforms a chunk
before it is yielded to the caller. Processors run **after** the raw chunk
has been accumulated for output sensing, so sensors always see unmodified
model output.

The ``@text_processor`` decorator lifts a plain ``str -> str`` function so
it also handles OpenAI-compatible streaming chunk objects (e.g. LiteLLM
``ModelResponseStream``).  For chunks, text is extracted from
``choices[0].delta.content``, transformed, and written back; non-text
chunks pass through unchanged.

Built-in processors:

* ``strip_markdown_images`` — converts ``![alt](url)`` to ``[alt](url)``
  to prevent indirect prompt injection via auto-fetched image URLs.
  Decorated with ``@text_processor`` so it works on both raw strings and
  OpenAI-compatible chunks.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

PostProcessor = Callable[[Any], Any]
"""Type alias for a post-processor: a sync callable that transforms a chunk."""


def text_processor(fn: Callable[[str], str]) -> PostProcessor:
    """Lift a ``str -> str`` function to also handle OpenAI-compatible chunks.

    The returned wrapper:

    * Passes ``str`` inputs directly to *fn* (backward compatible).
    * For objects with ``choices[0].delta.content``, extracts the text,
      applies *fn*, and writes the result back.
    * Falls through gracefully for anything else (no-op).

    Args:
        fn: A pure text transformation function.

    Returns:
        A ``PostProcessor`` that handles both strings and chunk objects.
    """

    @functools.wraps(fn)
    def wrapper(chunk: Any) -> Any:
        if isinstance(chunk, str):
            return fn(chunk)
        try:
            choices = chunk.choices
            if choices and choices[0].delta and choices[0].delta.content:
                choices[0].delta.content = fn(choices[0].delta.content)
        except (AttributeError, IndexError, TypeError):
            pass
        return chunk

    return wrapper


@text_processor
def strip_markdown_images(text: str) -> str:
    """Replace markdown images ``![`` with plain links ``[``.

    This prevents clients that auto-fetch image URLs from being exploited
    via indirect prompt injection (e.g. tracking pixels, SSRF).

    Decorated with ``@text_processor`` so it works on both raw strings and
    OpenAI-compatible streaming chunks.

    Args:
        text: A text chunk from the LLM stream.

    Returns:
        The text with ``![`` replaced by ``[``.
    """
    return text.replace("![", "[")

"""Inbound scanner — streaming-aware LLM response scanning.

Accumulates LLM response content as it streams through the proxy
and runs Guard policies incrementally against the accumulated window.
When a policy violation is detected mid-stream, the scanner signals
denial so the proxy can terminate the stream early.

Usage::

    scanner = InboundScanner(guard)

    # Feed chunks as they arrive from the SSE stream
    for chunk in sse_chunks:
        result = scanner.feed(chunk)
        if result is not None:
            # Policy violation — stop streaming
            break

    # Get final summary
    summary = scanner.finalize()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentguard.proxy.outbound import estimate_tokens

if TYPE_CHECKING:
    from agentguard.policies.guard import Guard


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning accumulated response content.

    Attributes:
        denied: Whether the content was denied by a policy.
        denied_by: Name of the policy that denied it (if denied).
        reason: Human-readable explanation (if denied).
        scanned_length: Number of characters scanned so far.
        token_estimate: Estimated token count of scanned content.
    """

    denied: bool
    denied_by: str | None
    reason: str | None
    scanned_length: int
    token_estimate: int


class InboundScanner:
    """Streaming-aware inbound response scanner.

    Accumulates response text and runs Guard policies against the
    full accumulated window after each chunk.  This ensures patterns
    spanning chunk boundaries are detected.

    Args:
        guard: The Guard instance with loaded policies.
    """

    def __init__(self, guard: Guard) -> None:
        self._guard = guard
        self._buffer: list[str] = []
        self._denied_result: ScanResult | None = None

    @property
    def accumulated_content(self) -> str:
        """Return all content fed so far."""
        return "".join(self._buffer)

    def feed(self, text: str) -> ScanResult | None:
        """Feed a chunk of response text to the scanner.

        Appends the text to the accumulated window and runs all
        loaded Guard policies against the full window.

        Args:
            text: A chunk of response content.

        Returns:
            ``None`` if the content is allowed so far.
            A :class:`ScanResult` with ``denied=True`` if a policy
            violation was detected.  Once denied, all subsequent
            ``feed()`` calls return the denied result immediately.
        """
        if self._denied_result is not None:
            return self._denied_result

        if text:
            self._buffer.append(text)

        window = self.accumulated_content
        if not window:
            return None

        decision = self._guard.check("llm_response", content=window)
        if decision.denied:
            self._denied_result = ScanResult(
                denied=True,
                denied_by=decision.denied_by,
                reason=decision.reason,
                scanned_length=len(window),
                token_estimate=estimate_tokens(window),
            )
            return self._denied_result

        return None

    def finalize(self) -> ScanResult:
        """Produce the final scan result at end of stream.

        Returns:
            A :class:`ScanResult` summarising the full stream.
            If a denial was triggered earlier, the denied result
            is returned.  Otherwise an allowed result with content
            statistics is returned.
        """
        if self._denied_result is not None:
            return self._denied_result

        window = self.accumulated_content
        return ScanResult(
            denied=False,
            denied_by=None,
            reason=None,
            scanned_length=len(window),
            token_estimate=estimate_tokens(window),
        )

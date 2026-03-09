"""Shared fixtures for integration tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from pathlib import Path

from agentguard.policies.guard import Guard

# ---------------------------------------------------------------------------
# Helper: OpenAI-format request body
# ---------------------------------------------------------------------------


def openai_request_body(
    messages: list[dict[str, str]],
    *,
    model: str = "gpt-4",
    stream: bool = False,
) -> dict[str, Any]:
    """Build an OpenAI-compatible chat completions request body."""
    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    if stream:
        body["stream"] = True
    return body


def openai_response_body(
    content: str,
    *,
    model: str = "gpt-4",
) -> dict[str, Any]:
    """Build an OpenAI-compatible chat completions response body."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }


def openai_sse_chunk(content: str, *, index: int = 0) -> str:
    """Build one SSE data line with an OpenAI streaming delta."""
    chunk = {
        "id": "chatcmpl-test",
        "object": "chat.completion.chunk",
        "choices": [
            {
                "index": index,
                "delta": {"content": content},
                "finish_reason": None,
            }
        ],
    }
    return f"data: {json.dumps(chunk)}\n"


# ---------------------------------------------------------------------------
# Fixtures: policy directories
# ---------------------------------------------------------------------------


@pytest.fixture()
def deny_rm_policy_dir(tmp_path: Path) -> Path:
    """Create a temp policy directory that denies 'rm -rf' in llm_request."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "deny-rm.yaml").write_text(
        "name: deny-rm\n"
        "description: Block rm -rf commands in prompts\n"
        "rules:\n"
        "  - action: llm_request\n"
        "    deny:\n"
        "      - pattern: 'rm -rf'\n"
        "    severity: critical\n"
    )
    return d


@pytest.fixture()
def deny_confidential_response_dir(tmp_path: Path) -> Path:
    """Create a temp policy that denies 'CONFIDENTIAL' in llm_response."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "deny-confidential.yaml").write_text(
        "name: deny-confidential\n"
        "description: Block CONFIDENTIAL in responses\n"
        "rules:\n"
        "  - action: llm_response\n"
        "    deny:\n"
        "      - pattern: 'CONFIDENTIAL'\n"
        "    severity: high\n"
    )
    return d


@pytest.fixture()
def guard_with_builtins() -> Guard:
    """Create a Guard with all built-in policies loaded."""
    return Guard.with_auto_discovery(include_builtins=True)


# ---------------------------------------------------------------------------
# Fixtures: mock upstream via httpx transport
# ---------------------------------------------------------------------------


def make_mock_transport(
    response_body: bytes | None = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    *,
    sse_lines: list[str] | None = None,
) -> Any:
    """Create an httpx MockTransport that returns a fixed response.

    For SSE streaming, pass ``sse_lines`` — each element becomes a line
    in the response body separated by newlines.
    """
    import httpx

    if sse_lines is not None:
        body = "\n".join(sse_lines).encode()
        final_headers = {"content-type": "text/event-stream"}
    elif response_body is not None:
        body = response_body
        final_headers = {"content-type": "application/json"}
    else:
        body = b"{}"
        final_headers = {"content-type": "application/json"}

    if headers:
        final_headers.update(headers)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=status_code,
            content=body,
            headers=final_headers,
        )

    return httpx.MockTransport(handler)

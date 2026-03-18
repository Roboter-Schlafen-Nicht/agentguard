"""Phase 2: Local model summarization via Ollama.

Summarizes old conversation segments using a local LLM (Ollama)
to reduce token usage while preserving key context.
"""

from __future__ import annotations

from typing import Any

from agentguard.proxy.compaction.config import CompactionConfig


def build_summary_prompt(messages: list[dict[str, Any]]) -> str:
    """Build a summarization prompt from conversation messages.

    Formats the messages into a readable conversation transcript
    and prepends instructions for the summarizer model.

    Args:
        messages: OpenAI-format message array to summarize.

    Returns:
        A prompt string ready to send to the summarizer model.
    """
    if not messages:
        return ""

    parts: list[str] = []
    parts.append(
        "Summarize the following conversation history into a concise summary. "
        "Preserve: key decisions, file paths mentioned, current task state, "
        "error messages, and important code snippets. "
        "Drop: verbose tool outputs, repeated information, resolved issues. "
        "Format as a brief narrative with bullet points for key facts.\n\n"
        "--- CONVERSATION ---\n"
    )

    for msg in messages:
        role = msg.get("role", "unknown")
        content = msg.get("content", "")

        if role == "tool":
            tool_id = msg.get("tool_call_id", "")
            parts.append(f"[Tool result ({tool_id})]: {content}\n")
        elif role == "assistant" and msg.get("tool_calls"):
            tool_calls = msg["tool_calls"]
            call_descs = []
            for tc in tool_calls:
                if isinstance(tc, dict):
                    fn = tc.get("function", {})
                    name = fn.get("name", "?") if isinstance(fn, dict) else "?"
                    call_descs.append(name)
            parts.append(f"Assistant: [called tools: {', '.join(call_descs)}]\n")
        else:
            label = role.capitalize() if role != "system" else "System"
            if isinstance(content, str) and content:
                parts.append(f"{label}: {content}\n")

    parts.append("\n--- END CONVERSATION ---\n")
    parts.append("Summary:")

    return "".join(parts)


async def summarize_segment(
    messages: list[dict[str, Any]],
    config: CompactionConfig,
) -> str:
    """Summarize a segment of conversation messages using Ollama.

    Sends the messages to a local LLM for summarization. Falls back
    to a basic text-based summary if the LLM is unavailable.

    Args:
        messages: Messages to summarize.
        config: Compaction configuration with Ollama settings.

    Returns:
        A summary string. Never raises — returns a fallback on error.
    """
    if not messages:
        return ""

    prompt = build_summary_prompt(messages)

    try:
        summary = await _call_ollama(
            prompt=prompt,
            base_url=config.summarizer_url,
            model=config.summarizer_model,
            timeout=config.summarizer_timeout,
        )
        return summary
    except Exception:
        # Fallback: basic extractive summary
        return _fallback_summary(messages)


def _fallback_summary(messages: list[dict[str, Any]]) -> str:
    """Create a basic fallback summary without an LLM.

    Extracts key information from messages when Ollama is unavailable.

    Args:
        messages: Messages to summarize.

    Returns:
        A basic summary string.
    """
    user_msgs = [m for m in messages if m.get("role") == "user"]
    assistant_msgs = [m for m in messages if m.get("role") == "assistant"]

    parts = [
        f"[Previous conversation history: {len(messages)} messages, "
        f"{len(user_msgs)} user, {len(assistant_msgs)} assistant]"
    ]

    # Extract user topics
    for msg in user_msgs[:3]:
        content = msg.get("content", "")
        if isinstance(content, str) and content:
            truncated = content[:200] + "..." if len(content) > 200 else content
            parts.append(f"- User asked: {truncated}")

    if len(user_msgs) > 3:
        parts.append(f"- ... and {len(user_msgs) - 3} more user messages")

    return "\n".join(parts)


async def _call_ollama(
    *,
    prompt: str,
    base_url: str,
    model: str,
    timeout: float,
) -> str:
    """Call the Ollama API for chat completion.

    Args:
        prompt: The prompt to send.
        base_url: Ollama API base URL (e.g. http://localhost:11434).
        model: Model name to use.
        timeout: Request timeout in seconds.

    Returns:
        The model's response text.

    Raises:
        Exception: If the API call fails.
    """
    import httpx

    url = f"{base_url.rstrip('/')}/api/chat"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(url=url, json=payload)
        response.raise_for_status()
        data = response.json()

    message = data.get("message", {})
    return message.get("content", "")

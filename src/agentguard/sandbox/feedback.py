"""Feedback loop detection for policy sandbox.

Simulates multi-turn conversations where denial messages from the
Guard get re-injected as subsequent LLM requests, detecting context
poisoning patterns that make policies unworkable in production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.policies.guard import Guard


# Threshold for considering consecutive denials a feedback loop.
_FEEDBACK_LOOP_THRESHOLD = 3


@dataclass
class FeedbackLoopResult:
    """Result of a feedback loop simulation for a single prompt.

    Attributes:
        scenario_name: Name/label for this simulation.
        turns: Number of turns simulated.
        denials_per_turn: Number of denials at each turn (0 or 1).
        max_consecutive_denials: Longest streak of consecutive denials.
        has_feedback_loop: Whether a feedback loop was detected.
    """

    scenario_name: str
    turns: int
    denials_per_turn: list[int]
    max_consecutive_denials: int
    has_feedback_loop: bool


def _build_retry_prompt(
    original_prompt: str,
    denial_reason: str,
    turn: int,
) -> str:
    """Build the prompt an LLM agent would construct after a denial.

    In practice, when a tool call is denied, the LLM sees an error
    message in its context and retries. The retry includes both the
    error message and context from the original prompt.
    """
    return (
        f"[Turn {turn}] Previous request was denied: {denial_reason}. "
        f"Original task: {original_prompt}"
    )


def simulate_conversation(
    scenario_name: str,
    initial_prompt: str,
    guard: Guard,
    max_turns: int = 5,
) -> FeedbackLoopResult:
    """Simulate a multi-turn conversation to detect feedback loops.

    Starting with an initial prompt, each turn:
    1. Sends the prompt through the Guard as an llm_request
    2. If denied, constructs the next prompt including the denial message
    3. If allowed, subsequent turns use the same prompt (no escalation)

    A feedback loop is detected when there are 3+ consecutive denials,
    meaning the denial messages themselves keep triggering denials.

    Args:
        scenario_name: Label for this simulation.
        initial_prompt: The initial user prompt.
        guard: The Guard with loaded policies.
        max_turns: Maximum number of turns to simulate.

    Returns:
        A FeedbackLoopResult describing the conversation dynamics.
    """
    denials_per_turn: list[int] = []
    current_prompt = initial_prompt

    for turn in range(max_turns):
        decision = guard.check("llm_request", messages=current_prompt)
        if decision.denied:
            denials_per_turn.append(1)
            # Simulate the LLM receiving the denial and retrying
            current_prompt = _build_retry_prompt(
                initial_prompt,
                decision.reason or "Blocked by policy",
                turn + 1,
            )
        else:
            denials_per_turn.append(0)
            # No denial — subsequent turns use the original prompt
            # (simulates the agent continuing normally)

    # Compute max consecutive denials
    max_consecutive = 0
    current_streak = 0
    for d in denials_per_turn:
        if d > 0:
            current_streak += 1
            max_consecutive = max(max_consecutive, current_streak)
        else:
            current_streak = 0

    has_loop = max_consecutive >= _FEEDBACK_LOOP_THRESHOLD

    return FeedbackLoopResult(
        scenario_name=scenario_name,
        turns=max_turns,
        denials_per_turn=denials_per_turn,
        max_consecutive_denials=max_consecutive,
        has_feedback_loop=has_loop,
    )


def check_feedback_loops(
    prompts: dict[str, str],
    guard: Guard,
    max_turns: int = 5,
) -> dict[str, FeedbackLoopResult]:
    """Check multiple prompts for feedback loops.

    Args:
        prompts: Mapping of scenario name to initial prompt text.
        guard: The Guard with loaded policies.
        max_turns: Maximum turns per simulation.

    Returns:
        Mapping of scenario name to FeedbackLoopResult.
    """
    results: dict[str, FeedbackLoopResult] = {}
    for name, prompt in prompts.items():
        results[name] = simulate_conversation(
            scenario_name=name,
            initial_prompt=prompt,
            guard=guard,
            max_turns=max_turns,
        )
    return results

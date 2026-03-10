"""Protection level presets — curated policy bundles.

Provides named presets that load specific subsets of built-in policies:

- ``permissive``: Critical-only policies. Blocks the most dangerous
  operations (data deletion, force push, secrets in prompts) while
  allowing maximum flexibility. For experienced users.
- ``balanced``: Adds operational safety policies on top of permissive.
  Good default for daily use.
- ``strict``: Loads all 11 built-in policies. Maximum protection
  including internal path blocking, persona jailbreak detection,
  and drift monitoring.

Usage::

    from agentguard.policies.presets import Preset, load_preset

    policies = load_preset(Preset.BALANCED)
    guard = Guard(policies=policies)

CLI::

    agentguard serve --preset balanced --audit-dir audit/
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from agentguard.policies.builtins import load_builtin

if TYPE_CHECKING:
    from agentguard.policies.models import Policy


class Preset(enum.Enum):
    """Named protection level preset.

    Values:
        PERMISSIVE: Critical-only policies. Minimal friction.
        BALANCED: Operational safety. Good for daily use.
        STRICT: All built-in policies. Maximum protection.
    """

    PERMISSIVE = "permissive"
    BALANCED = "balanced"
    STRICT = "strict"


#: Mapping from preset to the built-in policy names it includes.
#: Order matters: permissive is a subset of balanced, which is a
#: subset of strict.
PRESET_POLICIES: dict[Preset, list[str]] = {
    Preset.PERMISSIVE: [
        # Tool-layer: block the most destructive operations
        "no-data-deletion",
        "no-force-push",
        # Proxy-layer: block secrets leaking to LLMs
        "no-secret-in-prompt",
    ],
    Preset.BALANCED: [
        # Everything in permissive
        "no-data-deletion",
        "no-force-push",
        "no-secret-in-prompt",
        # Tool-layer: operational safety
        "no-secret-exposure",
        "no-env-commit",
        "no-hook-bypass",
        # Proxy-layer: PII and injection protection
        "no-pii-leak",
        "no-prompt-injection",
    ],
    Preset.STRICT: [
        # Everything in balanced
        "no-data-deletion",
        "no-force-push",
        "no-secret-in-prompt",
        "no-secret-exposure",
        "no-env-commit",
        "no-hook-bypass",
        "no-pii-leak",
        "no-prompt-injection",
        # Full protection
        "no-internal-paths",
        "no-persona-jailbreak",
        "detect-drift-triggers",
    ],
}


def list_presets() -> list[str]:
    """List available preset names.

    Returns:
        Sorted list of preset names.
    """
    return sorted(p.value for p in Preset)


def load_preset(preset: Preset | str) -> list[Policy]:
    """Load all policies for a named preset.

    Args:
        preset: A Preset enum value or its string name
            (e.g. ``"balanced"``).

    Returns:
        List of Policy objects for the preset.

    Raises:
        ValueError: If the preset name is not recognized.
    """
    if isinstance(preset, str):
        try:
            preset = Preset(preset.lower())
        except ValueError:
            available = ", ".join(list_presets())
            msg = f"Unknown preset '{preset}'. Available: {available}"
            raise ValueError(msg) from None

    policy_names = PRESET_POLICIES[preset]
    return [load_builtin(name) for name in policy_names]

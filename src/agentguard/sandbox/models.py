"""Sandbox data models: Scenario, ScenarioAction, ScenarioResult.

These are the core types for the policy sandbox. Scenarios describe
sequences of actions with expected outcomes. Results capture what
actually happened when the scenario was run through the Guard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

if TYPE_CHECKING:
    from agentguard.policies.models import Decision


@dataclass
class ScenarioAction:
    """A single action within a scenario.

    Attributes:
        kind: The action type (e.g., "file_write", "llm_request").
        params: Key-value parameters for the action.
    """

    kind: str
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class Scenario:
    """A test scenario for policy validation.

    A scenario defines a sequence of actions and the expected outcome
    when those actions are evaluated by the Guard.

    Attributes:
        name: Unique identifier for the scenario.
        description: Human-readable description.
        expected_outcome: Either "allow" or "deny".
        actions: Sequence of actions to evaluate.
        tags: Optional tags for filtering scenarios.
    """

    name: str
    description: str
    expected_outcome: str
    actions: list[ScenarioAction]
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.expected_outcome not in ("allow", "deny"):
            msg = (
                f"expected_outcome must be 'allow' or 'deny', "
                f"got {self.expected_outcome!r}"
            )
            raise ValueError(msg)
        if not self.actions:
            msg = "actions must contain at least one action"
            raise ValueError(msg)


@dataclass
class ScenarioResult:
    """Result of running a single scenario through the Guard.

    Attributes:
        scenario_name: Name of the scenario that was run.
        expected: The expected outcome ("allow" or "deny").
        actual: The actual outcome ("allow" or "deny").
        passed: Whether the actual matched the expected.
        decisions: The Decision objects for each action.
        failure_reason: Human-readable reason if the scenario failed.
    """

    scenario_name: str
    expected: str
    actual: str
    passed: bool
    decisions: list[Decision]
    failure_reason: str | None = None

    @property
    def is_false_positive(self) -> bool:
        """True if expected allow but got deny."""
        return self.expected == "allow" and self.actual == "deny"

    @property
    def is_false_negative(self) -> bool:
        """True if expected deny but got allow."""
        return self.expected == "deny" and self.actual == "allow"


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------


def _parse_scenario_dict(data: dict[str, Any]) -> Scenario:
    """Parse a scenario from a dictionary (loaded from YAML)."""
    actions = []
    for action_data in data.get("actions", []):
        params = action_data.get("params", {})
        # Ensure all param values are strings
        str_params = {k: str(v) for k, v in params.items()}
        actions.append(ScenarioAction(kind=action_data["kind"], params=str_params))

    return Scenario(
        name=data["name"],
        description=data["description"],
        expected_outcome=data["expected_outcome"],
        actions=actions,
        tags=data.get("tags", []),
    )


def load_scenario_from_string(yaml_str: str) -> Scenario:
    """Load a scenario from a YAML string.

    Args:
        yaml_str: YAML-formatted scenario definition.

    Returns:
        A Scenario instance.

    Raises:
        ValueError: If the YAML is invalid or missing required fields.
    """
    try:
        data = yaml.safe_load(yaml_str)
    except yaml.YAMLError as e:
        msg = f"Invalid YAML: {e}"
        raise ValueError(msg) from e

    if not isinstance(data, dict):
        msg = "Scenario YAML must be a mapping"
        raise ValueError(msg)

    try:
        return _parse_scenario_dict(data)
    except KeyError as e:
        msg = f"Missing required field: {e}"
        raise ValueError(msg) from e


def load_scenario_from_file(path: str | Path) -> Scenario:
    """Load a single scenario from a YAML file.

    The file must contain exactly one YAML document. For files with
    multiple documents (separated by ``---``), use
    :func:`load_scenarios_from_file`.

    Args:
        path: Path to the YAML file.

    Returns:
        A Scenario instance.
    """
    path = Path(path)
    return load_scenario_from_string(path.read_text())


def load_scenarios_from_file(path: str | Path) -> list[Scenario]:
    """Load one or more scenarios from a YAML file.

    Supports multi-document YAML files (separated by ``---``).
    Single-document files return a list with one element.

    Args:
        path: Path to the YAML file.

    Returns:
        List of Scenario instances.

    Raises:
        ValueError: If any document is invalid.
    """
    path = Path(path)
    text = path.read_text()
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        msg = f"Invalid YAML in {path}: {e}"
        raise ValueError(msg) from e

    scenarios: list[Scenario] = []
    for doc in docs:
        if doc is None:
            continue  # skip empty documents
        if not isinstance(doc, dict):
            msg = f"Each YAML document in {path} must be a mapping"
            raise ValueError(msg)
        try:
            scenarios.append(_parse_scenario_dict(doc))
        except KeyError as e:
            msg = f"Missing required field in {path}: {e}"
            raise ValueError(msg) from e
    return scenarios


def load_scenarios_from_directory(directory: str | Path) -> list[Scenario]:
    """Load all scenarios from YAML files in a directory.

    Supports both single-document and multi-document YAML files.

    Args:
        directory: Path to the directory containing scenario YAML files.

    Returns:
        List of Scenario instances, sorted by name.
    """
    directory = Path(directory)
    scenarios: list[Scenario] = []
    for path in sorted(directory.glob("*.yaml")):
        scenarios.extend(load_scenarios_from_file(path))
    return scenarios

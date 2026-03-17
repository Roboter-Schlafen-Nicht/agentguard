"""Tests for sandbox scenario models.

Covers Scenario, ScenarioAction, ScenarioResult, and YAML loading.
"""

from __future__ import annotations

import textwrap
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


class TestScenarioAction:
    """Tests for the ScenarioAction data model."""

    def test_create_with_kind_and_params(self) -> None:
        from agentguard.sandbox.models import ScenarioAction

        action = ScenarioAction(
            kind="file_write", params={"path": "/tmp/test.txt", "content": "hello"}
        )
        assert action.kind == "file_write"
        assert action.params == {"path": "/tmp/test.txt", "content": "hello"}

    def test_create_with_empty_params(self) -> None:
        from agentguard.sandbox.models import ScenarioAction

        action = ScenarioAction(kind="shell_execute", params={})
        assert action.params == {}

    def test_defaults_to_empty_params(self) -> None:
        from agentguard.sandbox.models import ScenarioAction

        action = ScenarioAction(kind="file_read")
        assert action.params == {}


class TestScenario:
    """Tests for the Scenario data model."""

    def test_create_basic(self) -> None:
        from agentguard.sandbox.models import Scenario, ScenarioAction

        scenario = Scenario(
            name="test-scenario",
            description="A test scenario",
            expected_outcome="allow",
            actions=[
                ScenarioAction(kind="file_read", params={"path": "/tmp/file.txt"}),
            ],
        )
        assert scenario.name == "test-scenario"
        assert scenario.description == "A test scenario"
        assert scenario.expected_outcome == "allow"
        assert len(scenario.actions) == 1

    def test_expected_outcome_must_be_allow_or_deny(self) -> None:
        from agentguard.sandbox.models import Scenario, ScenarioAction

        with pytest.raises(ValueError, match="expected_outcome"):
            Scenario(
                name="bad",
                description="bad outcome",
                expected_outcome="maybe",
                actions=[ScenarioAction(kind="file_read")],
            )

    def test_must_have_at_least_one_action(self) -> None:
        from agentguard.sandbox.models import Scenario

        with pytest.raises(ValueError, match="actions"):
            Scenario(
                name="empty",
                description="no actions",
                expected_outcome="allow",
                actions=[],
            )

    def test_optional_tags(self) -> None:
        from agentguard.sandbox.models import Scenario, ScenarioAction

        scenario = Scenario(
            name="tagged",
            description="tagged scenario",
            expected_outcome="deny",
            actions=[ScenarioAction(kind="llm_request", params={"messages": "test"})],
            tags=["secrets", "bearer"],
        )
        assert scenario.tags == ["secrets", "bearer"]

    def test_tags_default_to_empty(self) -> None:
        from agentguard.sandbox.models import Scenario, ScenarioAction

        scenario = Scenario(
            name="no-tags",
            description="no tags",
            expected_outcome="allow",
            actions=[ScenarioAction(kind="file_read")],
        )
        assert scenario.tags == []


class TestScenarioResult:
    """Tests for the ScenarioResult data model."""

    def test_create_passed_result(self) -> None:
        from agentguard.sandbox.models import ScenarioResult

        result = ScenarioResult(
            scenario_name="test",
            expected="allow",
            actual="allow",
            passed=True,
            decisions=[],
        )
        assert result.passed is True
        assert result.expected == "allow"
        assert result.actual == "allow"

    def test_create_failed_result_false_positive(self) -> None:
        from agentguard.sandbox.models import ScenarioResult

        result = ScenarioResult(
            scenario_name="test",
            expected="allow",
            actual="deny",
            passed=False,
            decisions=[],
            failure_reason="False positive: blocked by no-secret-exposure",
        )
        assert result.passed is False
        assert result.is_false_positive is True
        assert result.is_false_negative is False

    def test_create_failed_result_false_negative(self) -> None:
        from agentguard.sandbox.models import ScenarioResult

        result = ScenarioResult(
            scenario_name="test",
            expected="deny",
            actual="allow",
            passed=False,
            decisions=[],
        )
        assert result.is_false_negative is True
        assert result.is_false_positive is False


class TestLoadScenarioFromYaml:
    """Tests for loading scenarios from YAML strings and files."""

    def test_load_from_yaml_string(self) -> None:
        from agentguard.sandbox.models import load_scenario_from_string

        yaml_str = textwrap.dedent("""\
            name: bearer-docs
            description: Discussion of Bearer authentication
            expected_outcome: allow
            actions:
              - kind: llm_request
                params:
                  messages: "Explain how Bearer token authentication works"
        """)
        scenario = load_scenario_from_string(yaml_str)
        assert scenario.name == "bearer-docs"
        assert scenario.expected_outcome == "allow"
        assert len(scenario.actions) == 1
        assert scenario.actions[0].kind == "llm_request"

    def test_load_from_yaml_file(self, tmp_path: Path) -> None:
        from agentguard.sandbox.models import load_scenario_from_file

        yaml_file = tmp_path / "test-scenario.yaml"
        yaml_file.write_text(
            textwrap.dedent("""\
            name: real-api-key
            description: Prompt containing a real API key
            expected_outcome: deny
            actions:
              - kind: llm_request
                params:
                  messages: "Use this key: sk-abcdefghijklmnopqrstuvwxyz1234567890"
        """)
        )
        scenario = load_scenario_from_file(yaml_file)
        assert scenario.name == "real-api-key"
        assert scenario.expected_outcome == "deny"

    def test_load_multiple_actions(self) -> None:
        from agentguard.sandbox.models import load_scenario_from_string

        yaml_str = textwrap.dedent("""\
            name: multi-action
            description: Multiple actions in sequence
            expected_outcome: allow
            actions:
              - kind: file_read
                params:
                  path: /tmp/config.yaml
              - kind: llm_request
                params:
                  messages: "Analyze this config file"
              - kind: file_write
                params:
                  path: /tmp/output.txt
                  content: "Analysis result"
        """)
        scenario = load_scenario_from_string(yaml_str)
        assert len(scenario.actions) == 3
        assert scenario.actions[0].kind == "file_read"
        assert scenario.actions[1].kind == "llm_request"
        assert scenario.actions[2].kind == "file_write"

    def test_load_with_tags(self) -> None:
        from agentguard.sandbox.models import load_scenario_from_string

        yaml_str = textwrap.dedent("""\
            name: tagged-scenario
            description: A tagged scenario
            expected_outcome: deny
            tags:
              - secrets
              - bearer
            actions:
              - kind: llm_request
                params:
                  messages: "test"
        """)
        scenario = load_scenario_from_string(yaml_str)
        assert scenario.tags == ["secrets", "bearer"]

    def test_load_directory_of_scenarios(self, tmp_path: Path) -> None:
        from agentguard.sandbox.models import load_scenarios_from_directory

        for i, outcome in enumerate(["allow", "deny", "allow"]):
            (tmp_path / f"scenario-{i}.yaml").write_text(
                textwrap.dedent(f"""\
                name: scenario-{i}
                description: Scenario {i}
                expected_outcome: {outcome}
                actions:
                  - kind: file_read
                    params:
                      path: /tmp/test
            """)
            )

        scenarios = load_scenarios_from_directory(tmp_path)
        assert len(scenarios) == 3

    def test_invalid_yaml_raises_error(self) -> None:
        from agentguard.sandbox.models import load_scenario_from_string

        with pytest.raises(ValueError):
            load_scenario_from_string("not: valid: yaml: [[[")

    def test_missing_required_fields_raises_error(self) -> None:
        from agentguard.sandbox.models import load_scenario_from_string

        with pytest.raises((ValueError, KeyError)):
            load_scenario_from_string("name: incomplete\n")

    def test_load_multi_document_yaml_file(self, tmp_path: Path) -> None:
        """Multi-document YAML files (separated by ---) load multiple scenarios."""
        from agentguard.sandbox.models import load_scenarios_from_file

        yaml_file = tmp_path / "multi.yaml"
        yaml_file.write_text(
            textwrap.dedent("""\
            name: first
            description: First scenario
            expected_outcome: allow
            actions:
              - kind: file_read
                params:
                  path: /tmp/a
            ---
            name: second
            description: Second scenario
            expected_outcome: deny
            actions:
              - kind: llm_request
                params:
                  messages: "test secret"
        """)
        )
        scenarios = load_scenarios_from_file(yaml_file)
        assert len(scenarios) == 2
        assert scenarios[0].name == "first"
        assert scenarios[1].name == "second"

    def test_load_directory_with_multi_document_files(self, tmp_path: Path) -> None:
        """Directory loader handles both single and multi-document files."""
        from agentguard.sandbox.models import load_scenarios_from_directory

        (tmp_path / "single.yaml").write_text(
            textwrap.dedent("""\
            name: solo
            description: Single scenario
            expected_outcome: allow
            actions:
              - kind: file_read
                params:
                  path: /tmp/x
        """)
        )
        (tmp_path / "multi.yaml").write_text(
            textwrap.dedent("""\
            name: multi-a
            description: Multi A
            expected_outcome: deny
            actions:
              - kind: llm_request
                params:
                  messages: "test"
            ---
            name: multi-b
            description: Multi B
            expected_outcome: allow
            actions:
              - kind: file_read
                params:
                  path: /tmp/y
        """)
        )
        scenarios = load_scenarios_from_directory(tmp_path)
        assert len(scenarios) == 3
        names = {s.name for s in scenarios}
        assert names == {"solo", "multi-a", "multi-b"}

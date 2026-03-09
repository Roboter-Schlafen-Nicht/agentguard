"""Tests for YAML policy loader."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from agentguard.policies.loader import load_policy_from_string, load_policy_from_yaml
from agentguard.policies.models import Policy, ScanTarget, Severity


class TestLoadPolicyFromString:
    def test_minimal_policy(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: test-policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm -rf /"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert isinstance(policy, Policy)
        assert policy.name == "test-policy"
        assert len(policy.rules) == 1
        assert policy.rules[0].severity == Severity.CRITICAL

    def test_policy_with_description(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: my-policy
            description: A test policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "dangerous"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.description == "A test policy"

    def test_multiple_rules(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: multi-rule
            rules:
              - action: shell_command
                deny:
                  - pattern: "git push.*--force"
                severity: critical
              - action: file_write
                deny:
                  - pattern: '\\.env$'
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert len(policy.rules) == 2
        assert policy.rules[0].action_kind == "shell_command"
        assert policy.rules[1].action_kind == "file_write"

    def test_multiple_deny_patterns(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: multi-pattern
            rules:
              - action: shell_command
                deny:
                  - pattern: "git push.*--force"
                  - pattern: "git reset --hard"
                  - pattern: "git branch -D"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert len(policy.rules[0].deny_patterns) == 3

    def test_rule_with_description(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: desc-policy
            rules:
              - action: shell_command
                description: Block force pushes
                deny:
                  - pattern: "git push.*--force"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].description == "Block force pushes"

    def test_missing_name_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
                severity: low
        """)
        with pytest.raises(ValueError, match="name"):
            load_policy_from_string(yaml_str)

    def test_missing_rules_raises(self) -> None:
        yaml_str = "name: no-rules\n"
        with pytest.raises(ValueError, match="rules"):
            load_policy_from_string(yaml_str)

    def test_empty_rules_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: empty-rules
            rules: []
        """)
        with pytest.raises(ValueError, match="rules"):
            load_policy_from_string(yaml_str)

    def test_rule_missing_action_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-rule
            rules:
              - deny:
                  - pattern: "rm"
                severity: low
        """)
        with pytest.raises(ValueError, match="action"):
            load_policy_from_string(yaml_str)

    def test_rule_missing_deny_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-rule
            rules:
              - action: shell_command
                severity: low
        """)
        with pytest.raises(ValueError, match="deny"):
            load_policy_from_string(yaml_str)

    def test_rule_missing_severity_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-rule
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
        """)
        with pytest.raises(ValueError, match="severity"):
            load_policy_from_string(yaml_str)

    def test_invalid_severity_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-severity
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
                severity: extreme
        """)
        with pytest.raises(ValueError, match="severity"):
            load_policy_from_string(yaml_str)

    def test_invalid_regex_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-regex
            rules:
              - action: shell_command
                deny:
                  - pattern: "[invalid"
                severity: low
        """)
        with pytest.raises(ValueError, match="pattern"):
            load_policy_from_string(yaml_str)

    def test_deny_pattern_missing_pattern_key_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: no-pattern-key
            rules:
              - action: shell_command
                deny:
                  - regex: "something"
                severity: low
        """)
        with pytest.raises(ValueError, match="pattern"):
            load_policy_from_string(yaml_str)


class TestLoadPolicyFromFile:
    def test_load_from_yaml_file(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            name: file-policy
            description: Loaded from file
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
                severity: low
        """)
        )
        policy = load_policy_from_yaml(policy_file)
        assert policy.name == "file-policy"
        assert policy.description == "Loaded from file"

    def test_load_from_yml_extension(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "test.yml"
        policy_file.write_text(
            textwrap.dedent("""\
            name: yml-policy
            rules:
              - action: file_write
                deny:
                  - pattern: "secret"
                severity: medium
        """)
        )
        policy = load_policy_from_yaml(policy_file)
        assert policy.name == "yml-policy"

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_policy_from_yaml(Path("/nonexistent/policy.yaml"))

    def test_load_from_string_path(self, tmp_path: Path) -> None:
        policy_file = tmp_path / "str-path.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            name: str-path-policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "test"
                severity: low
        """)
        )
        policy = load_policy_from_yaml(str(policy_file))
        assert policy.name == "str-path-policy"


# === Scan field parsing ===


class TestLoadPolicyScanField:
    def test_rule_without_scan_has_none(self) -> None:
        """Backward compat: rules without scan field get scan=None."""
        yaml_str = textwrap.dedent("""\
            name: no-scan
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm"
                severity: low
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan is None

    def test_rule_with_scan_messages(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: llm-scan
            rules:
              - action: llm_request
                scan: messages
                deny:
                  - pattern: "API_KEY"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.MESSAGES

    def test_rule_with_scan_system(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: llm-scan-system
            rules:
              - action: llm_request
                scan: system
                deny:
                  - pattern: "ignore previous"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.SYSTEM

    def test_rule_with_scan_content(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: llm-scan-content
            rules:
              - action: llm_response
                scan: content
                deny:
                  - pattern: "rm -rf"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.CONTENT

    def test_rule_with_scan_all(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: llm-scan-all
            rules:
              - action: llm_request
                scan: all
                deny:
                  - pattern: "secret"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.ALL

    def test_invalid_scan_value_raises(self) -> None:
        yaml_str = textwrap.dedent("""\
            name: bad-scan
            rules:
              - action: llm_request
                scan: invalid_target
                deny:
                  - pattern: "test"
                severity: low
        """)
        with pytest.raises(ValueError, match="scan target"):
            load_policy_from_string(yaml_str)

    def test_llm_request_action_kind_accepted(self) -> None:
        """llm_request is a valid action kind (no special validation)."""
        yaml_str = textwrap.dedent("""\
            name: llm-policy
            rules:
              - action: llm_request
                deny:
                  - pattern: "API_KEY"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].action_kind == "llm_request"

    def test_llm_response_action_kind_accepted(self) -> None:
        """llm_response is a valid action kind (no special validation)."""
        yaml_str = textwrap.dedent("""\
            name: llm-response-policy
            rules:
              - action: llm_response
                scan: content
                deny:
                  - pattern: "ignore previous instructions"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].action_kind == "llm_response"
        assert policy.rules[0].scan == ScanTarget.CONTENT

    def test_mixed_rules_with_and_without_scan(self) -> None:
        """Policy can mix tool-call rules (no scan) and proxy rules (with scan)."""
        yaml_str = textwrap.dedent("""\
            name: mixed-policy
            rules:
              - action: shell_command
                deny:
                  - pattern: "rm -rf"
                severity: critical
              - action: llm_request
                scan: messages
                deny:
                  - pattern: "API_KEY"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert len(policy.rules) == 2
        assert policy.rules[0].scan is None
        assert policy.rules[1].scan == ScanTarget.MESSAGES

    def test_rule_with_scan_command(self) -> None:
        """scan: command is valid for shell_execute rules."""
        yaml_str = textwrap.dedent("""\
            name: shell-scan-command
            rules:
              - action: shell_execute
                scan: command
                deny:
                  - pattern: "rm -rf"
                severity: critical
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.COMMAND

    def test_rule_with_scan_new_string(self) -> None:
        """scan: new_string is valid for file_edit rules."""
        yaml_str = textwrap.dedent("""\
            name: edit-scan-new-string
            rules:
              - action: file_edit
                scan: new_string
                deny:
                  - pattern: "/mnt/f/work/"
                severity: high
        """)
        policy = load_policy_from_string(yaml_str)
        assert policy.rules[0].scan == ScanTarget.NEW_STRING

"""E2E tests for policy engine presets and auto-discovery (SG-6).

Tests cover:
- SG-6.1: Permissive preset loads exactly 3 policies
- SG-6.2: Balanced preset loads exactly 8 policies
- SG-6.3: Strict preset loads exactly 11 policies
- SG-6.4: Auto-discover project-local policies (.agentguard/policies/)
- SG-6.5: Auto-discover user-global policies (~/.agentguard/policies/)
- SG-6.6: Custom YAML policy loaded via policy_dir
- SG-6.7: Combined sources (preset + custom policy_dir)
- SG-6.8: Malformed YAML is gracefully skipped
- SG-6.9: Invalid regex in policy raises ValueError
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession

import pytest

from agentguard.policies.discovery import discover_policies
from agentguard.policies.guard import Guard
from agentguard.policies.loader import load_policy_from_string
from agentguard.policies.presets import PRESET_POLICIES, Preset
from tests.e2e.conftest import _get_text, _with_server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_POLICY_YAML = """\
name: test-custom-echo-deny
description: Deny echo commands for testing
rules:
  - action: shell_command
    deny:
      - pattern: "^echo secret$"
    severity: high
    description: Block echo of secrets
"""

_MALFORMED_YAML_SYNTAX = """\
name: broken
rules:
  - this is not valid YAML for a rule
  - [[[
"""

_MALFORMED_YAML_SCHEMA = """\
description: missing name field
rules:
  - this is just a string
"""

_INVALID_REGEX_YAML = """\
name: bad-regex
rules:
  - action: shell_command
    deny:
      - pattern: "[unclosed"
    severity: high
"""


def _write_policy_file(directory: Path, filename: str, content: str) -> Path:
    """Write a policy YAML file into a directory."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_text(content)
    return path


# ---------------------------------------------------------------------------
# SG-6.1: Permissive preset loads 3 policies
# ---------------------------------------------------------------------------


class TestPermissivePreset:
    """Permissive preset loads exactly the expected policies."""

    @pytest.mark.anyio()
    async def test_permissive_preset_loads_three_policies(
        self, audit_dir: Path
    ) -> None:
        """SG-6.1: create_server with permissive preset reports 3 policies."""
        expected_names = sorted(PRESET_POLICIES[Preset.PERMISSIVE])

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))
            assert data["policies_loaded"] == 3
            assert sorted(data["policy_names"]) == expected_names

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


# ---------------------------------------------------------------------------
# SG-6.2: Balanced preset loads 8 policies
# ---------------------------------------------------------------------------


class TestBalancedPreset:
    """Balanced preset loads exactly the expected policies."""

    @pytest.mark.anyio()
    async def test_balanced_preset_loads_eight_policies(self, audit_dir: Path) -> None:
        """SG-6.2: create_server with balanced preset reports 8 policies."""
        expected_names = sorted(PRESET_POLICIES[Preset.BALANCED])

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))
            assert data["policies_loaded"] == 8
            assert sorted(data["policy_names"]) == expected_names

        await _with_server(check, audit_dir=audit_dir, preset="balanced")


# ---------------------------------------------------------------------------
# SG-6.3: Strict preset loads 11 policies
# ---------------------------------------------------------------------------


class TestStrictPreset:
    """Strict preset loads exactly the expected policies."""

    @pytest.mark.anyio()
    async def test_strict_preset_loads_eleven_policies(self, audit_dir: Path) -> None:
        """SG-6.3: create_server with strict preset reports 11 policies."""
        expected_names = sorted(PRESET_POLICIES[Preset.STRICT])

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))
            assert data["policies_loaded"] == 11
            assert sorted(data["policy_names"]) == expected_names

        await _with_server(check, audit_dir=audit_dir, preset="strict")


# ---------------------------------------------------------------------------
# SG-6.4: Auto-discover project-local policies
# ---------------------------------------------------------------------------


class TestAutoDiscoverProjectLocal:
    """Auto-discover loads policies from .agentguard/policies/ in CWD."""

    def test_project_local_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SG-6.4: Policies in .agentguard/policies/ under CWD are discovered."""
        project_policy_dir = tmp_path / ".agentguard" / "policies"
        _write_policy_file(project_policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        monkeypatch.chdir(tmp_path)

        policies = discover_policies(project_dir=project_policy_dir)

        assert len(policies) == 1
        assert policies[0].name == "test-custom-echo-deny"

    def test_project_local_via_guard(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SG-6.4: Guard.with_auto_discovery picks up project-local policies."""
        project_policy_dir = tmp_path / ".agentguard" / "policies"
        _write_policy_file(project_policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        monkeypatch.chdir(tmp_path)

        guard = Guard.with_auto_discovery()
        policy_names = {p.name for p in guard.policies}

        assert "test-custom-echo-deny" in policy_names


# ---------------------------------------------------------------------------
# SG-6.5: Auto-discover user-global policies
# ---------------------------------------------------------------------------


class TestAutoDiscoverUserGlobal:
    """Auto-discover loads policies from ~/.agentguard/policies/."""

    def test_user_global_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SG-6.5: Policies in ~/.agentguard/policies/ are discovered."""
        fake_home = tmp_path / "fakehome"
        fake_home.mkdir()
        user_policy_dir = fake_home / ".agentguard" / "policies"
        _write_policy_file(user_policy_dir, "user-policy.yaml", _VALID_POLICY_YAML)

        monkeypatch.setenv("HOME", str(fake_home))
        # Clear CWD-based discovery by setting CWD to a dir with no policies
        no_policies = tmp_path / "empty_project"
        no_policies.mkdir()
        monkeypatch.chdir(no_policies)

        guard = Guard.with_auto_discovery()
        policy_names = {p.name for p in guard.policies}

        assert "test-custom-echo-deny" in policy_names

    def test_user_global_via_discover_policies(self, tmp_path: Path) -> None:
        """SG-6.5: discover_policies with user_dir finds policies."""
        user_policy_dir = tmp_path / "user_policies"
        _write_policy_file(user_policy_dir, "user.yaml", _VALID_POLICY_YAML)

        policies = discover_policies(user_dir=user_policy_dir)

        assert len(policies) == 1
        assert policies[0].name == "test-custom-echo-deny"


# ---------------------------------------------------------------------------
# SG-6.6: Custom YAML policy via policy_dir
# ---------------------------------------------------------------------------


class TestCustomPolicyFile:
    """Custom YAML policy loaded via policy_dir in create_server."""

    @pytest.mark.anyio()
    async def test_custom_policy_appears_in_status(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-6.6: create_server with policy_dir lists custom policy in status."""
        policy_dir = tmp_path / "custom_policies"
        _write_policy_file(policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))
            assert "test-custom-echo-deny" in data["policy_names"]

        await _with_server(check, audit_dir=audit_dir, policy_dir=str(policy_dir))

    @pytest.mark.anyio()
    async def test_custom_policy_denies_matching_command(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-6.6: Custom policy actually enforces its deny rules via MCP."""
        policy_dir = tmp_path / "custom_policies"
        _write_policy_file(policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute", {"command": "echo secret"}
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "test-custom-echo-deny" in text

        await _with_server(check, audit_dir=audit_dir, policy_dir=str(policy_dir))


# ---------------------------------------------------------------------------
# SG-6.7: Combined sources (preset + custom policy_dir)
# ---------------------------------------------------------------------------


class TestCombinedSources:
    """Preset policies combined with custom policy_dir."""

    @pytest.mark.anyio()
    async def test_preset_plus_custom_dir(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-6.7: create_server with preset + policy_dir loads both."""
        policy_dir = tmp_path / "custom_policies"
        _write_policy_file(policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))

            names = data["policy_names"]
            # Must have the 3 permissive policies + 1 custom
            assert data["policies_loaded"] == 4
            assert "test-custom-echo-deny" in names
            for expected in PRESET_POLICIES[Preset.PERMISSIVE]:
                assert expected in names

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            policy_dir=str(policy_dir),
        )

    @pytest.mark.anyio()
    async def test_combined_enforces_both_rulesets(
        self, tmp_path: Path, audit_dir: Path
    ) -> None:
        """SG-6.7: Both preset and custom policies are enforced."""
        policy_dir = tmp_path / "custom_policies"
        _write_policy_file(policy_dir, "custom.yaml", _VALID_POLICY_YAML)

        async def check(session: ClientSession) -> None:
            # Custom policy denies "echo secret"
            r1 = await session.call_tool("shell_execute", {"command": "echo secret"})
            assert r1.isError
            assert "test-custom-echo-deny" in _get_text(r1)

            # Preset no-force-push denies "git push --force"
            r2 = await session.call_tool(
                "shell_execute", {"command": "git push --force origin main"}
            )
            assert r2.isError
            assert "no-force-push" in _get_text(r2)

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            policy_dir=str(policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-6.8: Malformed YAML graceful error
# ---------------------------------------------------------------------------


class TestMalformedYaml:
    """Malformed YAML files are handled gracefully."""

    def test_malformed_yaml_skipped_in_discovery(self, tmp_path: Path) -> None:
        """SG-6.8: Malformed YAML in discovery dir is silently skipped."""
        policy_dir = tmp_path / "policies"
        _write_policy_file(policy_dir, "broken.yaml", _MALFORMED_YAML_SYNTAX)
        _write_policy_file(policy_dir, "valid.yaml", _VALID_POLICY_YAML)

        policies = discover_policies(project_dir=policy_dir)

        # Only the valid policy should be loaded; broken is skipped
        assert len(policies) == 1
        assert policies[0].name == "test-custom-echo-deny"

    def test_malformed_yaml_raises_in_direct_load(self) -> None:
        """SG-6.8: load_policy_from_string raises ValueError for malformed YAML."""
        with pytest.raises(ValueError):
            load_policy_from_string(_MALFORMED_YAML_SCHEMA)


# ---------------------------------------------------------------------------
# SG-6.9: Invalid regex graceful error
# ---------------------------------------------------------------------------


class TestInvalidRegex:
    """Invalid regex patterns in policies raise clear errors."""

    def test_invalid_regex_raises_valueerror(self) -> None:
        """SG-6.9: Policy with unclosed bracket regex raises ValueError."""
        with pytest.raises(ValueError, match="pattern"):
            load_policy_from_string(_INVALID_REGEX_YAML)

    def test_invalid_regex_skipped_in_discovery(self, tmp_path: Path) -> None:
        """SG-6.9: Invalid regex policy in discovery dir is silently skipped."""
        policy_dir = tmp_path / "policies"
        _write_policy_file(policy_dir, "bad-regex.yaml", _INVALID_REGEX_YAML)
        _write_policy_file(policy_dir, "valid.yaml", _VALID_POLICY_YAML)

        policies = discover_policies(project_dir=policy_dir)

        # Only the valid policy should be loaded
        assert len(policies) == 1
        assert policies[0].name == "test-custom-echo-deny"

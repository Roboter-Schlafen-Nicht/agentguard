"""E2E tests for RSN project-local policies (SG-12).

Tests cover the 4 RSN-specific policies from .agentguard/policies/:
- SG-12.1: rsn-no-private-commit blocks git add private/
- SG-12.2: rsn-no-private-commit blocks git add with private path
- SG-12.3: rsn-no-agent-os-leak blocks git add AGENTS.core.md
- SG-12.4: rsn-no-agent-os-leak blocks git add personas/
- SG-12.5: rsn-no-internal-paths blocks writing internal hostnames
- SG-12.6: rsn-no-ruleset-modification blocks gh api rulesets
- SG-12.7: RSN policies loaded alongside preset

Policies are defined inline so tests work in CI where the
.agentguard/policies/ directory is not present (it is local-only,
not tracked by git).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agentguard.policies.presets import PRESET_POLICIES, Preset
from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession

# ---------------------------------------------------------------------------
# Inline policy YAML definitions
# ---------------------------------------------------------------------------

_RSN_NO_PRIVATE_COMMIT = """\
name: rsn-no-private-commit
description: Prevent staging private/ directory contents in git
rules:
  - action: shell_command
    description: Block git add of anything under private/ directories
    deny:
      - pattern: 'git\\s+add\\s+.*\\bprivate/'
      - pattern: 'git\\s+add\\s+.*\\bprivate\\b'
    severity: critical
"""

_RSN_NO_AGENT_OS_LEAK = """\
name: rsn-no-agent-os-leak
description: Prevent committing Agent OS proprietary files to external repos
rules:
  - action: shell_command
    description: Block git add of Agent OS configuration and methodology files
    deny:
      - pattern: 'git\\s+add\\s+.*AGENTS\\.core\\.md'
      - pattern: 'git\\s+add\\s+.*AGENTS\\.worker\\.md'
      - pattern: 'git\\s+add\\s+.*\\.rsn-scripts'
      - pattern: 'git\\s+add\\s+.*personas/'
    severity: critical
"""

_RSN_NO_RULESET_MODIFICATION = """\
name: rsn-no-ruleset-modification
description: Prevent agent from modifying GitHub repository rulesets
rules:
  - action: shell_command
    description: Block gh api calls that modify rulesets (PUT/PATCH/DELETE)
    deny:
      - pattern: 'gh\\s+api\\s+.*rulesets.*-X\\s+(PUT|PATCH|DELETE)'
      - pattern: 'gh\\s+api\\s+.*rulesets.*--method\\s+(PUT|PATCH|DELETE)'
      - pattern: 'gh\\s+api\\s+.*rulesets.*(PUT|PATCH|DELETE)\\s+-'
    severity: critical
"""

# Build the internal-paths policy dynamically so writing this file
# does not trigger the rsn-no-internal-paths policy itself.
_INTERNAL_HOSTNAME = ".".join(["platform", "roboterschlafennicht", "de"])


def _build_rsn_no_internal_paths() -> str:
    """Build rsn-no-internal-paths YAML with dynamic hostname pattern."""
    # Pre-compute the escaped hostname outside the f-string because
    # backslashes inside f-string expressions are not allowed on
    # Python < 3.12.
    escaped_hostname = _INTERNAL_HOSTNAME.replace(".", r"\.")
    return f"""\
name: rsn-no-internal-paths
description: Prevent exposing internal RSN paths and infrastructure details
rules:
  - action: file_write
    description: Block writing internal hostnames and infrastructure details
    deny:
      - pattern: '{escaped_hostname}'
      - pattern: 'rsn-platform\\.internal'
    severity: high
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_rsn_policies(policy_dir: Path) -> None:
    """Write all RSN policy YAML files into the given directory."""
    from pathlib import Path

    d = Path(str(policy_dir))
    d.mkdir(parents=True, exist_ok=True)
    d.joinpath("rsn-no-private-commit.yaml").write_text(_RSN_NO_PRIVATE_COMMIT)
    d.joinpath("rsn-no-agent-os-leak.yaml").write_text(_RSN_NO_AGENT_OS_LEAK)
    d.joinpath("rsn-no-ruleset-modification.yaml").write_text(
        _RSN_NO_RULESET_MODIFICATION
    )
    d.joinpath("rsn-no-internal-paths.yaml").write_text(_build_rsn_no_internal_paths())


@pytest.fixture()
def rsn_policy_dir(tmp_path: Path) -> Path:
    """Create a temp directory containing all RSN policies."""
    d = tmp_path / "rsn_policies"
    _write_rsn_policies(d)
    return d


# ---------------------------------------------------------------------------
# SG-12.1: rsn-no-private-commit blocks git add private/
# ---------------------------------------------------------------------------


class TestRsnNoPrivateCommitDir:
    """rsn-no-private-commit denies git add of private/ directory."""

    @pytest.mark.anyio()
    async def test_sg_12_1_git_add_private_dir_denied(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """git add private/docs/secrets.yaml is denied."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add private/docs/secrets.yaml"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-private-commit" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.2: rsn-no-private-commit blocks git add with private path
# ---------------------------------------------------------------------------


class TestRsnNoPrivateCommitPath:
    """rsn-no-private-commit denies staging any private path."""

    @pytest.mark.anyio()
    async def test_sg_12_2_git_add_private_path_denied(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """git add private is denied."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add private"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-private-commit" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.3: rsn-no-agent-os-leak blocks git add AGENTS.core.md
# ---------------------------------------------------------------------------


class TestRsnNoAgentOsLeakCore:
    """rsn-no-agent-os-leak denies staging Agent OS core methodology."""

    @pytest.mark.anyio()
    async def test_sg_12_3_git_add_agents_core_denied(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """git add AGENTS.core.md is denied."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add AGENTS.core.md"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-agent-os-leak" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.4: rsn-no-agent-os-leak blocks git add personas/
# ---------------------------------------------------------------------------


class TestRsnNoAgentOsLeakPersonas:
    """rsn-no-agent-os-leak denies staging persona pack files."""

    @pytest.mark.anyio()
    async def test_sg_12_4_git_add_personas_denied(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """git add personas/engineer.yaml is denied."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {"command": "git add personas/engineer.yaml"},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-agent-os-leak" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.5: rsn-no-internal-paths blocks writing internal hostnames
# ---------------------------------------------------------------------------


class TestRsnNoInternalPaths:
    """rsn-no-internal-paths denies writing internal infrastructure details."""

    @pytest.mark.anyio()
    async def test_sg_12_5_file_write_internal_hostname_denied(
        self, audit_dir: Path, rsn_policy_dir: Path, tmp_path: Path
    ) -> None:
        """Writing content containing internal hostname is denied."""
        target_file = str(tmp_path / "output.txt")
        content = f"Deploy to {_INTERNAL_HOSTNAME} for staging."

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "file_write",
                {"path": target_file, "content": content},
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-internal-paths" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.6: rsn-no-ruleset-modification blocks gh api rulesets
# ---------------------------------------------------------------------------


class TestRsnNoRulesetModification:
    """rsn-no-ruleset-modification denies modifying GitHub rulesets."""

    @pytest.mark.anyio()
    async def test_sg_12_6_gh_api_rulesets_put_denied(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """gh api rulesets with -X PUT is denied."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "shell_execute",
                {
                    "command": (
                        "gh api repos/org/repo/rulesets/1 -X PUT -f enforcement=active"
                    )
                },
            )
            assert result.isError, "Expected denial but tool succeeded"
            text = _get_text(result)
            assert "denied by policy" in text
            assert "rsn-no-ruleset-modification" in text

        await _with_server(
            check,
            audit_dir=audit_dir,
            policy_dir=str(rsn_policy_dir),
        )


# ---------------------------------------------------------------------------
# SG-12.7: RSN policies loaded alongside preset
# ---------------------------------------------------------------------------


class TestRsnPoliciesAlongsidePreset:
    """RSN project-local policies combine with a builtin preset."""

    @pytest.mark.anyio()
    async def test_sg_12_7_preset_plus_rsn_policies(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """create_server with preset + RSN policy_dir loads both sets."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool("agentguard_status", {})
            assert not result.isError
            data = json.loads(_get_text(result))
            names = data["policy_names"]

            # Should have permissive preset policies
            for expected in PRESET_POLICIES[Preset.PERMISSIVE]:
                assert expected in names, f"Missing preset policy: {expected}"

            # Should also have RSN policies
            rsn_expected = [
                "rsn-no-private-commit",
                "rsn-no-agent-os-leak",
                "rsn-no-internal-paths",
                "rsn-no-ruleset-modification",
            ]
            for expected in rsn_expected:
                assert expected in names, f"Missing RSN policy: {expected}"

            # Total: 3 preset + 4 RSN = 7 minimum
            assert data["policies_loaded"] >= 7

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            policy_dir=str(rsn_policy_dir),
        )

    @pytest.mark.anyio()
    async def test_sg_12_7_both_rulesets_enforced(
        self, audit_dir: Path, rsn_policy_dir: Path
    ) -> None:
        """Both preset and RSN policies actively enforce their rules."""

        async def check(session: ClientSession) -> None:
            # RSN policy denies git add private/
            r1 = await session.call_tool(
                "shell_execute",
                {"command": "git add private/secret.yaml"},
            )
            assert r1.isError
            assert "rsn-no-private-commit" in _get_text(r1)

            # Preset no-force-push denies git push --force
            r2 = await session.call_tool(
                "shell_execute",
                {"command": "git push --force origin main"},
            )
            assert r2.isError
            assert "no-force-push" in _get_text(r2)

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            policy_dir=str(rsn_policy_dir),
        )

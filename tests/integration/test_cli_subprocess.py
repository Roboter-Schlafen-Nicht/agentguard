"""SG-8: CLI Subprocess Integration.

Integration tests that invoke the AgentGuard CLI via subprocess
to validate argument parsing, exit codes, and output.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration


# ===========================================================================
# SG-8.1: agentguard --version exits 0 with version string
# ===========================================================================


class TestCliVersion:
    """SG-8.1: CLI --version outputs version and exits 0."""

    def test_version_flag(self) -> None:
        """agentguard --version exits 0 with version string."""
        result = subprocess.run(
            [sys.executable, "-m", "agentguard", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "agentguard" in result.stdout
        # Version should be a dotted number like 0.2.0
        assert "." in result.stdout

    def test_version_subcommand(self) -> None:
        """agentguard version subcommand also works."""
        result = subprocess.run(
            [sys.executable, "-m", "agentguard", "version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert "agentguard" in result.stdout


# ===========================================================================
# SG-8.2: agentguard proxy --help shows proxy options
# ===========================================================================


class TestCliProxyHelp:
    """SG-8.2: proxy subcommand help shows expected options."""

    def test_proxy_help(self) -> None:
        """agentguard proxy --help exits 0 with proxy options."""
        result = subprocess.run(
            [sys.executable, "-m", "agentguard", "proxy", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        # Check for key options
        assert "--host" in result.stdout
        assert "--port" in result.stdout
        assert "--scan-responses" in result.stdout
        assert "--policy-dir" in result.stdout
        assert "--audit-dir" in result.stdout


# ===========================================================================
# SG-8.3: agentguard proxy with missing upstream fails
# ===========================================================================


class TestCliProxyMissingUpstream:
    """SG-8.3: proxy without required upstream argument fails."""

    def test_proxy_no_upstream_fails(self) -> None:
        """agentguard proxy with no upstream exits non-zero."""
        result = subprocess.run(
            [sys.executable, "-m", "agentguard", "proxy"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0
        # argparse should report the missing argument
        assert (
            "upstream" in result.stderr.lower() or "required" in result.stderr.lower()
        )

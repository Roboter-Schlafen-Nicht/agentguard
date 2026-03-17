"""Tests for the sandbox CLI commands.

The sandbox CLI provides commands:
- sandbox run: Run scenarios against policies
- sandbox gate: Check production readiness (pass/fail)
- sandbox report: Generate a detailed report (JSON)
"""

from __future__ import annotations

import json
import textwrap
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI with the given arguments and capture output."""
    import io
    import sys

    from agentguard.cli import main

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        exit_code = main(list(args))
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    finally:
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
        sys.stdout, sys.stderr = old_stdout, old_stderr
    return exit_code, stdout, stderr


def _write_scenario_file(path: Path, *, expected_outcome: str = "deny") -> None:
    """Write a minimal scenario YAML file."""
    if expected_outcome == "deny":
        path.write_text(
            textwrap.dedent("""\
            name: test-secret
            description: Write an API key
            expected_outcome: deny
            tags: [test]
            actions:
              - kind: file_write
                params:
                  content: "API_KEY = sk-abcdefghijklmnopqrstuvwxyz1234567890"
        """),
            encoding="utf-8",
        )
    else:
        path.write_text(
            textwrap.dedent("""\
            name: test-benign
            description: Read a normal file
            expected_outcome: allow
            tags: [test]
            actions:
              - kind: file_read
                params:
                  path: /tmp/readme.txt
        """),
            encoding="utf-8",
        )


class TestSandboxRun:
    """Tests for 'agentguard sandbox run'."""

    def test_run_with_scenario_dir(self, tmp_path: Path) -> None:
        """Run scenarios from a directory against a policy."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")
        _write_scenario_file(scenario_dir / "tn.yaml", expected_outcome="allow")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--scenarios",
            str(scenario_dir),
            "--builtins",
        )
        assert exit_code == 0
        assert "2 scenarios" in stdout.lower() or "passed" in stdout.lower()

    def test_run_with_single_scenario_file(self, tmp_path: Path) -> None:
        """Run a single scenario file."""
        scenario_file = tmp_path / "test.yaml"
        _write_scenario_file(scenario_file, expected_outcome="deny")

        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--scenarios",
            str(scenario_file),
            "--builtins",
        )
        assert exit_code == 0

    def test_run_with_json_format(self, tmp_path: Path) -> None:
        """JSON output should contain results array."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--scenarios",
            str(scenario_dir),
            "--builtins",
            "--format",
            "json",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert "results" in data

    def test_run_with_no_scenarios_errors(self) -> None:
        """Should error when no scenarios are provided."""
        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--builtins",
        )
        assert exit_code != 0

    def test_run_with_policy_file(self, tmp_path: Path) -> None:
        """Run scenarios against a specific policy file."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")

        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--scenarios",
            str(scenario_dir),
            "--policy",
            "src/agentguard/policies/builtin_policies/no-secret-exposure.yaml",
        )
        assert exit_code == 0

    def test_run_reports_failures(self, tmp_path: Path) -> None:
        """When scenarios fail, exit code should be 1."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        # A deny scenario with no policies = false negative
        _write_scenario_file(scenario_dir / "fn.yaml", expected_outcome="deny")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "run",
            "--scenarios",
            str(scenario_dir),
            # No policies loaded = nothing will be denied
        )
        assert exit_code == 1
        assert "fail" in stdout.lower()


class TestSandboxGate:
    """Tests for 'agentguard sandbox gate'."""

    def test_gate_passes_with_good_scenarios(self, tmp_path: Path) -> None:
        """Gate should pass when all scenarios match expectations."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")
        _write_scenario_file(scenario_dir / "tn.yaml", expected_outcome="allow")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "gate",
            "--scenarios",
            str(scenario_dir),
            "--builtins",
        )
        assert exit_code == 0
        assert "pass" in stdout.lower()

    def test_gate_fails_with_poor_metrics(self, tmp_path: Path) -> None:
        """Gate should fail when metrics don't meet thresholds."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        # Deny scenario with no policies = false negative
        _write_scenario_file(scenario_dir / "fn.yaml", expected_outcome="deny")

        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "gate",
            "--scenarios",
            str(scenario_dir),
            # No policies = will fail
        )
        assert exit_code == 1

    def test_gate_json_output(self, tmp_path: Path) -> None:
        """Gate JSON output should contain verdict and metrics."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")
        _write_scenario_file(scenario_dir / "tn.yaml", expected_outcome="allow")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "gate",
            "--scenarios",
            str(scenario_dir),
            "--builtins",
            "--format",
            "json",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert "passed" in data
        assert "metrics" in data

    def test_gate_no_scenarios_errors(self) -> None:
        """Gate should error when no scenarios are provided."""
        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "gate",
            "--builtins",
        )
        assert exit_code != 0


class TestSandboxReport:
    """Tests for 'agentguard sandbox report'."""

    def test_report_produces_json(self, tmp_path: Path) -> None:
        """Report should produce a detailed JSON report."""
        scenario_dir = tmp_path / "scenarios"
        scenario_dir.mkdir()
        _write_scenario_file(scenario_dir / "tp.yaml", expected_outcome="deny")
        _write_scenario_file(scenario_dir / "tn.yaml", expected_outcome="allow")

        exit_code, stdout, _stderr = _run_cli(
            "sandbox",
            "report",
            "--scenarios",
            str(scenario_dir),
            "--builtins",
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert "total" in data
        assert "true_positive_rate" in data
        assert "false_positive_rate" in data

    def test_report_no_scenarios_errors(self) -> None:
        """Report should error when no scenarios provided."""
        exit_code, _stdout, _stderr = _run_cli(
            "sandbox",
            "report",
            "--builtins",
        )
        assert exit_code != 0


class TestSandboxHelp:
    """Tests for sandbox help display."""

    def test_sandbox_no_subcommand_shows_help(self) -> None:
        """Running 'sandbox' alone should show help or error."""
        exit_code, _stdout, _stderr = _run_cli("sandbox")
        # Should either show help (exit 0) or error with help (exit 1)
        assert exit_code in (0, 1)

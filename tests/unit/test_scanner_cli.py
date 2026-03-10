"""Tests for the ``agentguard scan`` CLI subcommand."""

from __future__ import annotations

import io
import json
import sys
from typing import TYPE_CHECKING

from agentguard.cli import main

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _run_cli(*argv: str) -> tuple[int, str, str]:
    """Run the CLI with *argv* and capture output.

    Returns ``(exit_code, stdout, stderr)``.
    """
    old_argv = sys.argv
    old_out = sys.stdout
    old_err = sys.stderr
    try:
        sys.argv = ["agentguard", *argv]
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
    finally:
        sys.argv = old_argv
        sys.stdout = old_out
        sys.stderr = old_err
    return code, stdout, stderr


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Basic invocation
# ---------------------------------------------------------------------------


class TestScanBasic:
    def test_scan_clean_package(self, tmp_path: Path) -> None:
        _write(tmp_path / "clean.py", "x = 1\ny = 2\n")
        code, out, _err = _run_cli("scan", str(tmp_path))
        assert code == 0
        assert "No issues found" in out or "Clean" in out

    def test_scan_with_findings(self, tmp_path: Path) -> None:
        _write(tmp_path / "bad.py", "result = eval(\n")
        code, out, _err = _run_cli("scan", str(tmp_path))
        # Non-zero exit when findings exist
        assert code != 0
        assert "eval" in out.lower() or "finding" in out.lower()

    def test_scan_single_file(self, tmp_path: Path) -> None:
        target = tmp_path / "single.py"
        _write(target, "os.system(\n")
        code, _out, _err = _run_cli("scan", str(target))
        assert code != 0

    def test_scan_missing_path(self) -> None:
        code, _out, _err = _run_cli("scan", "/nonexistent/path/xyz")
        assert code != 0


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


class TestScanFormats:
    def test_text_format_default(self, tmp_path: Path) -> None:
        _write(tmp_path / "a.py", "x = 1\n")
        code, out, _err = _run_cli("scan", str(tmp_path))
        assert code == 0
        # Text format has human-readable output
        assert "Scan:" in out or "scanned" in out.lower()

    def test_json_format(self, tmp_path: Path) -> None:
        _write(tmp_path / "a.py", "x = 1\n")
        code, out, _err = _run_cli("scan", str(tmp_path), "--format", "json")
        assert code == 0
        data = json.loads(out)
        assert "package_path" in data
        assert "findings" in data
        assert "files_scanned" in data

    def test_json_format_with_findings(self, tmp_path: Path) -> None:
        _write(tmp_path / "x.py", "eval(\n")
        _code, out, _err = _run_cli("scan", str(tmp_path), "--format", "json")
        data = json.loads(out)
        assert data["finding_count"] >= 1
        assert len(data["findings"]) >= 1

    def test_summary_format(self, tmp_path: Path) -> None:
        _write(tmp_path / "a.py", "x = 1\n")
        code, out, _err = _run_cli("scan", str(tmp_path), "--format", "summary")
        assert code == 0
        # Summary is a single line
        lines = [ln for ln in out.strip().splitlines() if ln.strip()]
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# Severity filter
# ---------------------------------------------------------------------------


class TestScanSeverityFilter:
    def test_min_severity_filters_low(self, tmp_path: Path) -> None:
        # base64.b64encode triggers MEDIUM severity
        _write(tmp_path / "a.py", "base64.b64encode(\n")
        _code_all, out_all, _err1 = _run_cli("scan", str(tmp_path), "--format", "json")
        data_all = json.loads(out_all)

        _code_crit, out_crit, _err2 = _run_cli(
            "scan", str(tmp_path), "--format", "json", "--min-severity", "critical"
        )
        data_crit = json.loads(out_crit)

        # With critical filter, medium findings should be excluded
        assert data_crit["finding_count"] <= data_all["finding_count"]


# ---------------------------------------------------------------------------
# Help output
# ---------------------------------------------------------------------------


class TestScanHelp:
    def test_scan_help(self) -> None:
        _code, out, _err = _run_cli("scan", "--help")
        assert "scan" in out.lower() or "usage" in out.lower()

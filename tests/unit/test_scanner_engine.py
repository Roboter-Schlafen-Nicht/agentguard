"""Tests for the scanner engine."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agentguard.scanner.engine import _DEFAULT_EXTENSIONS, _SKIP_DIRS, Scanner
from agentguard.scanner.models import RiskCategory, ScanResult, Severity
from agentguard.scanner.rules import Rule

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_rule(
    rule_id: str = "test-rule",
    pattern: str = r"DANGEROUS",
    category: RiskCategory = RiskCategory.CODE_EXECUTION,
    severity: Severity = Severity.HIGH,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        category=category,
        severity=severity,
        pattern=re.compile(pattern, re.IGNORECASE),
        message=f"Matched {rule_id}",
    )


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_default_extensions_includes_py(self) -> None:
        assert ".py" in _DEFAULT_EXTENSIONS

    def test_default_extensions_includes_js(self) -> None:
        assert ".js" in _DEFAULT_EXTENSIONS

    def test_skip_dirs_includes_pycache(self) -> None:
        assert "__pycache__" in _SKIP_DIRS

    def test_skip_dirs_includes_git(self) -> None:
        assert ".git" in _SKIP_DIRS

    def test_skip_dirs_includes_node_modules(self) -> None:
        assert "node_modules" in _SKIP_DIRS


# ---------------------------------------------------------------------------
# Scanner initialisation
# ---------------------------------------------------------------------------


class TestScannerInit:
    def test_defaults(self) -> None:
        scanner = Scanner()
        assert scanner._max_file_size == 1_048_576

    def test_custom_rules(self) -> None:
        rules = [_make_rule()]
        scanner = Scanner(rules=rules)
        assert scanner._rules is rules

    def test_custom_extensions(self) -> None:
        ext = frozenset({".txt"})
        scanner = Scanner(extensions=ext)
        assert scanner._extensions == ext

    def test_custom_max_size(self) -> None:
        scanner = Scanner(max_file_size=512)
        assert scanner._max_file_size == 512


# ---------------------------------------------------------------------------
# Scanning a single file
# ---------------------------------------------------------------------------


class TestScanSingleFile:
    def test_scan_file_with_match(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.py"
        _write(target, "x = DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(target))
        assert result.files_scanned == 1
        assert result.finding_count == 1
        assert result.findings[0].rule_id == "test-rule"

    def test_scan_file_no_match(self, tmp_path: Path) -> None:
        target = tmp_path / "safe.py"
        _write(target, "x = 1\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(target))
        assert result.files_scanned == 1
        assert result.finding_count == 0

    def test_scan_file_line_number(self, tmp_path: Path) -> None:
        target = tmp_path / "code.py"
        _write(target, "safe\nsafe\nDANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(target))
        assert result.findings[0].line_number == 3

    def test_scan_file_matched_text(self, tmp_path: Path) -> None:
        target = tmp_path / "code.py"
        _write(target, "x = DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(target))
        assert result.findings[0].matched_text == "DANGEROUS"


# ---------------------------------------------------------------------------
# Scanning a directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_scan_directory_basic(self, tmp_path: Path) -> None:
        _write(tmp_path / "a.py", "DANGEROUS call\n")
        _write(tmp_path / "b.py", "safe code\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.files_scanned == 2
        assert result.finding_count == 1

    def test_scan_recursive(self, tmp_path: Path) -> None:
        _write(tmp_path / "sub" / "deep.py", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 1
        assert "deep.py" in result.findings[0].file_path

    def test_relative_paths_in_findings(self, tmp_path: Path) -> None:
        _write(tmp_path / "pkg" / "mod.py", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        # file_path should be relative to the scan root
        fp = result.findings[0].file_path
        assert not fp.startswith("/")

    def test_multiple_findings_same_file(self, tmp_path: Path) -> None:
        _write(tmp_path / "x.py", "DANGEROUS\nDANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 2
        assert result.findings[0].line_number == 1
        assert result.findings[1].line_number == 2


# ---------------------------------------------------------------------------
# Filtering behaviour
# ---------------------------------------------------------------------------


class TestFiltering:
    def test_skip_wrong_extension(self, tmp_path: Path) -> None:
        _write(tmp_path / "readme.md", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.files_scanned == 0
        assert result.finding_count == 0

    def test_custom_extensions(self, tmp_path: Path) -> None:
        _write(tmp_path / "data.txt", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()], extensions=frozenset({".txt"}))
        result = scanner.scan(str(tmp_path))
        assert result.files_scanned == 1
        assert result.finding_count == 1

    def test_skip_pycache(self, tmp_path: Path) -> None:
        _write(tmp_path / "__pycache__" / "cached.py", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 0

    def test_skip_git_dir(self, tmp_path: Path) -> None:
        _write(tmp_path / ".git" / "hook.py", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 0

    def test_skip_node_modules(self, tmp_path: Path) -> None:
        _write(tmp_path / "node_modules" / "pkg.js", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 0

    def test_skip_egg_info(self, tmp_path: Path) -> None:
        _write(tmp_path / "mypkg.egg-info" / "info.py", "DANGEROUS\n")
        scanner = Scanner(rules=[_make_rule()])
        result = scanner.scan(str(tmp_path))
        assert result.finding_count == 0

    def test_max_file_size(self, tmp_path: Path) -> None:
        target = tmp_path / "big.py"
        # Write a file larger than max_file_size
        _write(target, "DANGEROUS\n" * 200)
        scanner = Scanner(rules=[_make_rule()], max_file_size=100)
        result = scanner.scan(str(target))
        # File should be skipped entirely (returns None -> not counted)
        assert result.files_scanned == 0
        assert result.finding_count == 0


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_missing_path(self) -> None:
        scanner = Scanner()
        with pytest.raises(FileNotFoundError, match="not found"):
            scanner.scan("/nonexistent/path/to/package")

    def test_unreadable_file_skipped(self, tmp_path: Path) -> None:
        """If a file can't be read, it's silently skipped."""
        target = tmp_path / "noperm.py"
        _write(target, "DANGEROUS\n")
        target.chmod(0o000)
        scanner = Scanner(rules=[_make_rule()])
        try:
            result = scanner.scan(str(tmp_path))
            # Should not crash; file is skipped
            # (On some systems root can still read, so just check no crash)
            assert isinstance(result, ScanResult)
        finally:
            target.chmod(0o644)


# ---------------------------------------------------------------------------
# Multiple rules
# ---------------------------------------------------------------------------


class TestMultipleRules:
    def test_two_rules_same_line(self, tmp_path: Path) -> None:
        r1 = _make_rule(rule_id="r1", pattern="ALPHA")
        r2 = _make_rule(rule_id="r2", pattern="BETA")
        _write(tmp_path / "x.py", "ALPHA and BETA\n")
        scanner = Scanner(rules=[r1, r2])
        result = scanner.scan(str(tmp_path))
        ids = {f.rule_id for f in result.findings}
        assert ids == {"r1", "r2"}

    def test_different_severities(self, tmp_path: Path) -> None:
        r1 = _make_rule(rule_id="r1", pattern="LOW_RISK", severity=Severity.LOW)
        r2 = _make_rule(rule_id="r2", pattern="CRIT_RISK", severity=Severity.CRITICAL)
        _write(tmp_path / "x.py", "LOW_RISK\nCRIT_RISK\n")
        scanner = Scanner(rules=[r1, r2])
        result = scanner.scan(str(tmp_path))
        assert result.max_severity is Severity.CRITICAL


# ---------------------------------------------------------------------------
# Package path in result
# ---------------------------------------------------------------------------


class TestScanResultPath:
    def test_package_path_is_resolved(self, tmp_path: Path) -> None:
        scanner = Scanner(rules=[])
        _write(tmp_path / "empty.py", "")
        result = scanner.scan(str(tmp_path))
        # package_path should be an absolute resolved path
        assert Path(result.package_path).is_absolute()

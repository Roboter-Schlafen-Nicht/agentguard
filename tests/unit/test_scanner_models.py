"""Tests for scanner data models."""

from __future__ import annotations

import pytest

from agentguard.scanner.models import Finding, RiskCategory, ScanResult, Severity

# ---------------------------------------------------------------------------
# RiskCategory enum
# ---------------------------------------------------------------------------


class TestRiskCategory:
    def test_all_categories_count(self) -> None:
        assert len(RiskCategory) == 6

    def test_values(self) -> None:
        assert RiskCategory.DATA_EXFILTRATION.value == "data-exfiltration"
        assert RiskCategory.FILE_SYSTEM_ACCESS.value == "file-system-access"
        assert RiskCategory.CODE_EXECUTION.value == "code-execution"
        assert RiskCategory.CREDENTIAL_ACCESS.value == "credential-access"
        assert RiskCategory.PERSISTENCE.value == "persistence"
        assert RiskCategory.OBFUSCATION.value == "obfuscation"

    def test_from_string(self) -> None:
        assert RiskCategory("data-exfiltration") is RiskCategory.DATA_EXFILTRATION


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class TestSeverity:
    def test_all_levels_count(self) -> None:
        assert len(Severity) == 5

    def test_values(self) -> None:
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------


class TestFinding:
    def test_creation(self) -> None:
        f = Finding(
            rule_id="test-rule",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.HIGH,
            message="Test message",
            file_path="src/main.py",
            line_number=42,
            matched_text="eval(",
        )
        assert f.rule_id == "test-rule"
        assert f.category is RiskCategory.CODE_EXECUTION
        assert f.severity is Severity.HIGH
        assert f.message == "Test message"
        assert f.file_path == "src/main.py"
        assert f.line_number == 42
        assert f.matched_text == "eval("

    def test_defaults(self) -> None:
        f = Finding(
            rule_id="r",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.LOW,
            message="m",
            file_path="f.py",
        )
        assert f.line_number == 0
        assert f.matched_text == ""

    def test_frozen(self) -> None:
        f = Finding(
            rule_id="r",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.LOW,
            message="m",
            file_path="f.py",
        )
        with pytest.raises(AttributeError):
            f.rule_id = "other"  # type: ignore[misc]

    def test_to_dict(self) -> None:
        f = Finding(
            rule_id="r1",
            category=RiskCategory.PERSISTENCE,
            severity=Severity.MEDIUM,
            message="msg",
            file_path="a.py",
            line_number=10,
            matched_text="crontab",
        )
        d = f.to_dict()
        assert d["rule_id"] == "r1"
        assert d["category"] == "persistence"
        assert d["severity"] == "medium"
        assert d["message"] == "msg"
        assert d["file_path"] == "a.py"
        assert d["line_number"] == 10
        assert d["matched_text"] == "crontab"


# ---------------------------------------------------------------------------
# ScanResult
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_empty_result(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        assert r.finding_count == 0
        assert r.has_critical is False
        assert r.has_high is False
        assert r.max_severity is None

    def test_finding_count(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r", RiskCategory.OBFUSCATION, Severity.LOW, "m", "f.py")
        )
        r.findings.append(
            Finding("r2", RiskCategory.OBFUSCATION, Severity.INFO, "m2", "g.py")
        )
        assert r.finding_count == 2

    def test_has_critical(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r", RiskCategory.CODE_EXECUTION, Severity.CRITICAL, "m", "f.py")
        )
        assert r.has_critical is True
        assert r.has_high is True  # critical counts as high-or-above

    def test_has_high_but_not_critical(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r", RiskCategory.CODE_EXECUTION, Severity.HIGH, "m", "f.py")
        )
        assert r.has_critical is False
        assert r.has_high is True

    def test_max_severity(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r1", RiskCategory.OBFUSCATION, Severity.LOW, "m", "a.py")
        )
        r.findings.append(
            Finding("r2", RiskCategory.CODE_EXECUTION, Severity.HIGH, "m", "b.py")
        )
        r.findings.append(
            Finding("r3", RiskCategory.PERSISTENCE, Severity.MEDIUM, "m", "c.py")
        )
        assert r.max_severity is Severity.HIGH

    def test_by_category(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r1", RiskCategory.OBFUSCATION, Severity.LOW, "m", "a.py")
        )
        r.findings.append(
            Finding("r2", RiskCategory.OBFUSCATION, Severity.MEDIUM, "m", "b.py")
        )
        r.findings.append(
            Finding("r3", RiskCategory.CODE_EXECUTION, Severity.HIGH, "m", "c.py")
        )
        grouped = r.by_category()
        assert len(grouped[RiskCategory.OBFUSCATION]) == 2
        assert len(grouped[RiskCategory.CODE_EXECUTION]) == 1

    def test_by_severity(self) -> None:
        r = ScanResult(package_path="/tmp/pkg")
        r.findings.append(
            Finding("r1", RiskCategory.OBFUSCATION, Severity.LOW, "m", "a.py")
        )
        r.findings.append(
            Finding("r2", RiskCategory.CODE_EXECUTION, Severity.LOW, "m", "b.py")
        )
        grouped = r.by_severity()
        assert len(grouped[Severity.LOW]) == 2

    def test_to_dict_empty(self) -> None:
        r = ScanResult(package_path="/tmp/pkg", files_scanned=5)
        d = r.to_dict()
        assert d["package_path"] == "/tmp/pkg"
        assert d["files_scanned"] == 5
        assert d["finding_count"] == 0
        assert d["max_severity"] is None
        assert d["findings"] == []

    def test_to_dict_with_findings(self) -> None:
        r = ScanResult(package_path="/tmp/pkg", files_scanned=3)
        r.findings.append(
            Finding("r1", RiskCategory.PERSISTENCE, Severity.HIGH, "m", "x.py")
        )
        d = r.to_dict()
        assert d["finding_count"] == 1
        assert d["max_severity"] == "high"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["rule_id"] == "r1"

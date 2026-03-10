"""Tests for scanner output formatters."""

from __future__ import annotations

import json

from agentguard.scanner.models import Finding, RiskCategory, ScanResult, Severity
from agentguard.scanner.output import format_json, format_summary, format_text

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str = "test-rule",
    category: RiskCategory = RiskCategory.CODE_EXECUTION,
    severity: Severity = Severity.HIGH,
    message: str = "Test finding",
    file_path: str = "src/main.py",
    line_number: int = 10,
    matched_text: str = "eval(",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        message=message,
        file_path=file_path,
        line_number=line_number,
        matched_text=matched_text,
    )


def _result_clean() -> ScanResult:
    return ScanResult(package_path="/tmp/pkg", files_scanned=5)


def _result_with_findings() -> ScanResult:
    r = ScanResult(package_path="/tmp/pkg", files_scanned=12)
    r.findings.append(_finding())
    r.findings.append(
        _finding(
            rule_id="r2",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            message="HTTP exfil",
            file_path="src/net.py",
            line_number=42,
            matched_text="requests.post(",
        )
    )
    return r


# ---------------------------------------------------------------------------
# format_text
# ---------------------------------------------------------------------------


class TestFormatText:
    def test_header_contains_path(self) -> None:
        output = format_text(_result_clean())
        assert "/tmp/pkg" in output

    def test_files_scanned(self) -> None:
        output = format_text(_result_clean())
        assert "Files scanned: 5" in output

    def test_clean_shows_no_issues(self) -> None:
        output = format_text(_result_clean())
        assert "No issues found" in output

    def test_finding_count(self) -> None:
        output = format_text(_result_with_findings())
        assert "Findings: 2" in output

    def test_max_severity_shown(self) -> None:
        output = format_text(_result_with_findings())
        assert "CRITICAL" in output

    def test_rule_id_shown(self) -> None:
        output = format_text(_result_with_findings())
        assert "test-rule" in output
        assert "r2" in output

    def test_message_shown(self) -> None:
        output = format_text(_result_with_findings())
        assert "Test finding" in output

    def test_location_shown(self) -> None:
        output = format_text(_result_with_findings())
        assert "src/main.py:10" in output

    def test_matched_text_shown(self) -> None:
        output = format_text(_result_with_findings())
        assert "eval(" in output

    def test_colour_off_no_ansi(self) -> None:
        output = format_text(_result_with_findings(), colour=False)
        assert "\033[" not in output

    def test_colour_on_has_ansi(self) -> None:
        output = format_text(_result_with_findings(), colour=True)
        assert "\033[" in output

    def test_long_match_truncated(self) -> None:
        r = ScanResult(package_path="/tmp/p", files_scanned=1)
        r.findings.append(_finding(matched_text="A" * 100))
        output = format_text(r)
        assert "..." in output
        # Should be truncated to 80 chars of display
        for line in output.splitlines():
            if "matched:" in line:
                # The matched portion (after "    matched: ") should be <=80
                text_part = line.split("matched: ", 1)[1]
                assert len(text_part) <= 80


# ---------------------------------------------------------------------------
# format_json
# ---------------------------------------------------------------------------


class TestFormatJson:
    def test_valid_json(self) -> None:
        output = format_json(_result_clean())
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_contains_package_path(self) -> None:
        data = json.loads(format_json(_result_clean()))
        assert data["package_path"] == "/tmp/pkg"

    def test_contains_findings(self) -> None:
        data = json.loads(format_json(_result_with_findings()))
        assert len(data["findings"]) == 2

    def test_finding_count_field(self) -> None:
        data = json.loads(format_json(_result_with_findings()))
        assert data["finding_count"] == 2

    def test_max_severity_field(self) -> None:
        data = json.loads(format_json(_result_with_findings()))
        assert data["max_severity"] == "critical"

    def test_compact_format(self) -> None:
        output = format_json(_result_clean(), indent=None)
        assert "\n" not in output

    def test_indented_format(self) -> None:
        output = format_json(_result_clean(), indent=2)
        assert "\n" in output

    def test_empty_result_null_severity(self) -> None:
        data = json.loads(format_json(_result_clean()))
        assert data["max_severity"] is None


# ---------------------------------------------------------------------------
# format_summary
# ---------------------------------------------------------------------------


class TestFormatSummary:
    def test_clean_result(self) -> None:
        output = format_summary(_result_clean())
        assert "Clean" in output
        assert "0 findings" in output
        assert "5 files" in output

    def test_with_findings(self) -> None:
        output = format_summary(_result_with_findings())
        assert "2 findings" in output
        assert "CRITICAL" in output
        assert "12 files" in output

    def test_single_line(self) -> None:
        output = format_summary(_result_with_findings())
        assert "\n" not in output

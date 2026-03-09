"""Tests for the outbound scanner — secret/PII/path detection.

The outbound scanner provides programmatic detection of secrets,
PII, and internal paths in LLM request content, independent of
the YAML policy engine.  It also provides token estimation for
audit metadata.
"""

from __future__ import annotations

from agentguard.proxy.outbound import (
    Finding,
    FindingCategory,
    estimate_tokens,
    scan_text,
)

# ===========================================================================
# Test: FindingCategory enum
# ===========================================================================


class TestFindingCategory:
    """Test FindingCategory enum values."""

    def test_has_expected_categories(self) -> None:
        assert FindingCategory.SECRET is not None
        assert FindingCategory.PII is not None
        assert FindingCategory.INTERNAL_PATH is not None


# ===========================================================================
# Test: Finding dataclass
# ===========================================================================


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_fields(self) -> None:
        f = Finding(
            category=FindingCategory.SECRET,
            pattern_name="api-key",
            matched_text="sk-abc123",
            start=0,
            end=9,
        )
        assert f.category == FindingCategory.SECRET
        assert f.pattern_name == "api-key"
        assert f.matched_text == "sk-abc123"
        assert f.start == 0
        assert f.end == 9


# ===========================================================================
# Test: Secret detection
# ===========================================================================


class TestSecretDetection:
    """Test detection of secrets in text."""

    def test_detects_openai_api_key(self) -> None:
        text = "Use this key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "openai" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_github_personal_access_token(self) -> None:
        text = "My token is ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "github" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_github_fine_grained_pat(self) -> None:
        text = "Token: github_pat_abcdefghijklmnopqrstuvwxyz"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "github" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_aws_access_key(self) -> None:
        text = "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "aws" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_aws_key_id(self) -> None:
        text = "key id: AKIAIOSFODNN7EXAMPLE"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "aws" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_generic_password_assignment(self) -> None:
        text = "password = hunter2"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET
            and "password" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_bearer_token(self) -> None:
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJz"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "bearer" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_database_connection_string(self) -> None:
        text = "postgresql://user:p4ssw0rd@db.example.com:5432/mydb"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET
            and "connection" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_slack_webhook(self) -> None:
        text = "https://hooks.slack.com/services/T01/B02/abc123"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "webhook" in f.pattern_name.lower()
            for f in findings
        )

    def test_no_false_positive_on_benign_text(self) -> None:
        text = "Hello, how are you? I'd like to discuss the project."
        findings = scan_text(text)
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRET]
        assert len(secret_findings) == 0

    def test_detects_private_key_block(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK..."
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.SECRET and "private" in f.pattern_name.lower()
            for f in findings
        )


# ===========================================================================
# Test: PII detection
# ===========================================================================


class TestPIIDetection:
    """Test detection of PII in text."""

    def test_detects_email_address(self) -> None:
        text = "Contact me at john.doe@example.com for details."
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.PII and "email" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_us_ssn(self) -> None:
        text = "My SSN is 123-45-6789."
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.PII and "ssn" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_credit_card_number(self) -> None:
        text = "Card number: 4111 1111 1111 1111"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.PII and "credit" in f.pattern_name.lower()
            for f in findings
        )

    def test_detects_phone_number(self) -> None:
        text = "Call me at +1 (555) 123-4567"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.PII and "phone" in f.pattern_name.lower()
            for f in findings
        )

    def test_no_false_positive_pii_on_benign_text(self) -> None:
        text = "The weather is nice today."
        findings = scan_text(text)
        pii_findings = [f for f in findings if f.category == FindingCategory.PII]
        assert len(pii_findings) == 0


# ===========================================================================
# Test: Internal path detection
# ===========================================================================


class TestInternalPathDetection:
    """Test detection of internal filesystem paths."""

    def test_detects_unix_home_path(self) -> None:
        text = "The file is at /home/user/.config/secrets.yaml"
        findings = scan_text(text)
        assert any(f.category == FindingCategory.INTERNAL_PATH for f in findings)

    def test_detects_windows_path(self) -> None:
        text = r"Located at C:\Users\john\Documents\project\secrets.env"
        findings = scan_text(text)
        assert any(f.category == FindingCategory.INTERNAL_PATH for f in findings)

    def test_detects_etc_path(self) -> None:
        text = "Config is in /etc/nginx/nginx.conf"
        findings = scan_text(text)
        assert any(f.category == FindingCategory.INTERNAL_PATH for f in findings)

    def test_detects_private_ip(self) -> None:
        text = "Connect to 192.168.1.100:8080"
        findings = scan_text(text)
        assert any(
            f.category == FindingCategory.INTERNAL_PATH
            and "ip" in f.pattern_name.lower()
            for f in findings
        )

    def test_no_false_positive_on_urls(self) -> None:
        """Public URLs should not trigger internal path detection."""
        text = "Visit https://example.com/api/v1/users for the docs."
        findings = scan_text(text)
        path_findings = [
            f for f in findings if f.category == FindingCategory.INTERNAL_PATH
        ]
        assert len(path_findings) == 0


# ===========================================================================
# Test: scan_text with category filter
# ===========================================================================


class TestScanTextFiltering:
    """Test scan_text with category filtering."""

    def test_filter_by_category(self) -> None:
        text = "sk-proj-abc123def456ghi789jkl012 and john@example.com"
        secret_findings = scan_text(text, categories={FindingCategory.SECRET})
        assert all(f.category == FindingCategory.SECRET for f in secret_findings)

    def test_filter_multiple_categories(self) -> None:
        text = "sk-proj-abc123def456ghi789jkl012 and /home/user/file"
        findings = scan_text(
            text,
            categories={FindingCategory.SECRET, FindingCategory.INTERNAL_PATH},
        )
        categories = {f.category for f in findings}
        # Should not contain PII findings
        assert FindingCategory.PII not in categories

    def test_empty_text_returns_no_findings(self) -> None:
        findings = scan_text("")
        assert findings == []


# ===========================================================================
# Test: Token estimation
# ===========================================================================


class TestTokenEstimation:
    """Test token estimation utility."""

    def test_estimate_short_text(self) -> None:
        """Short text should estimate a small number of tokens."""
        tokens = estimate_tokens("Hello world")
        assert isinstance(tokens, int)
        assert tokens > 0
        assert tokens < 10

    def test_estimate_longer_text(self) -> None:
        """Longer text should estimate more tokens."""
        short = estimate_tokens("Hi")
        long_ = estimate_tokens("This is a much longer sentence with many words.")
        assert long_ > short

    def test_estimate_empty_text(self) -> None:
        """Empty text should return 0 tokens."""
        assert estimate_tokens("") == 0

    def test_estimate_consistency(self) -> None:
        """Same text should always return same estimate."""
        text = "The quick brown fox jumps over the lazy dog."
        assert estimate_tokens(text) == estimate_tokens(text)

    def test_estimate_approximately_correct(self) -> None:
        """Rough heuristic: ~4 chars per token for English text."""
        # "Hello world" is 11 chars → ~3 tokens (11/4 ≈ 2.75)
        text = "Hello world how are you doing today"
        tokens = estimate_tokens(text)
        # Should be roughly len(text)/4, allow ±50%
        expected = len(text) // 4
        assert expected * 0.5 <= tokens <= expected * 2.0


# ===========================================================================
# Test: Multiple findings in same text
# ===========================================================================


class TestMultipleFindings:
    """Test that multiple findings are returned from a single scan."""

    def test_multiple_secrets(self) -> None:
        text = "Use ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 and password = hunter2"
        findings = scan_text(text)
        secret_findings = [f for f in findings if f.category == FindingCategory.SECRET]
        assert len(secret_findings) >= 2

    def test_mixed_categories(self) -> None:
        text = (
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890 "
            "john@example.com "
            "/home/user/secrets.yaml"
        )
        findings = scan_text(text)
        categories = {f.category for f in findings}
        assert FindingCategory.SECRET in categories
        assert FindingCategory.PII in categories
        assert FindingCategory.INTERNAL_PATH in categories


# ===========================================================================
# Test: Finding position tracking
# ===========================================================================


class TestFindingPositions:
    """Test that findings track match positions correctly."""

    def test_start_end_within_text(self) -> None:
        text = "prefix sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx suffix"
        findings = scan_text(text)
        for f in findings:
            assert 0 <= f.start < f.end <= len(text)
            assert text[f.start : f.end] == f.matched_text

"""Outbound scanner — detect secrets, PII, and internal paths in text.

Provides programmatic detection of sensitive content in LLM request
payloads, independent of the YAML policy engine.  Used by the proxy
middleware to scan outbound prompts before they reach the LLM.

Each finding includes category, pattern name, matched text, and
position (start/end offsets).  The ``scan_text`` function runs all
detectors and returns a list of findings, optionally filtered by
category.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass


class FindingCategory(enum.Enum):
    """Category of a detected finding.

    Values:
        SECRET: API keys, tokens, credentials, passwords.
        PII: Personally identifiable information (email, SSN, etc.).
        INTERNAL_PATH: Internal filesystem paths, private IPs.
    """

    SECRET = "secret"
    PII = "pii"
    INTERNAL_PATH = "internal_path"


@dataclass(frozen=True)
class Finding:
    """A detected piece of sensitive content.

    Attributes:
        category: The type of sensitive content.
        pattern_name: Name of the pattern that matched.
        matched_text: The actual text that matched.
        start: Start offset in the scanned text.
        end: End offset in the scanned text.
    """

    category: FindingCategory
    pattern_name: str
    matched_text: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

_PatternDef = tuple[FindingCategory, str, re.Pattern[str]]

_PATTERNS: list[_PatternDef] = [
    # --- Secrets ---
    (
        FindingCategory.SECRET,
        "openai-api-key",
        re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{20,}"),
    ),
    (
        FindingCategory.SECRET,
        "github-pat",
        re.compile(r"ghp_[A-Za-z0-9]{36,}"),
    ),
    (
        FindingCategory.SECRET,
        "github-fine-grained-pat",
        re.compile(r"github_pat_[A-Za-z0-9_]{22,}"),
    ),
    (
        FindingCategory.SECRET,
        "aws-access-key-id",
        re.compile(r"AKIA[0-9A-Z]{16}"),
    ),
    (
        FindingCategory.SECRET,
        "aws-secret-key",
        re.compile(r"AWS_SECRET_ACCESS_KEY\s*=\s*\S+"),
    ),
    (
        FindingCategory.SECRET,
        "password-assignment",
        re.compile(r"(?i)password\s*[=:]\s*\S+"),
    ),
    (
        FindingCategory.SECRET,
        "bearer-token",
        re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*"),
    ),
    (
        FindingCategory.SECRET,
        "connection-string",
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)"
            r"://[^:\s]+:[^@\s]+@[^\s]+"
        ),
    ),
    (
        FindingCategory.SECRET,
        "slack-webhook",
        re.compile(r"https?://hooks\.slack\.com/services/\S+"),
    ),
    (
        FindingCategory.SECRET,
        "discord-webhook",
        re.compile(r"https?://discord\.com/api/webhooks/\S+"),
    ),
    (
        FindingCategory.SECRET,
        "private-key-block",
        re.compile(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----"),
    ),
    # --- PII ---
    (
        FindingCategory.PII,
        "email-address",
        re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ),
    (
        FindingCategory.PII,
        "us-ssn",
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    ),
    (
        FindingCategory.PII,
        "credit-card-number",
        re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
    ),
    (
        FindingCategory.PII,
        "phone-number",
        re.compile(r"\+?\d[\d\s()-]{8,}\d"),
    ),
    # --- Internal paths ---
    (
        FindingCategory.INTERNAL_PATH,
        "unix-path",
        re.compile(r"(?:/(?:home|root|etc|var|tmp|opt|usr|mnt|srv)/)\S+"),
    ),
    (
        FindingCategory.INTERNAL_PATH,
        "windows-path",
        re.compile(r"[A-Z]:\\(?:Users|Windows|Program\s+Files)\\\S+"),
    ),
    (
        FindingCategory.INTERNAL_PATH,
        "private-ip-address",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
]


def scan_text(
    text: str,
    *,
    categories: set[FindingCategory] | None = None,
) -> list[Finding]:
    """Scan text for secrets, PII, and internal paths.

    Args:
        text: The text to scan.
        categories: Optional set of categories to scan for.
            If None, all categories are scanned.

    Returns:
        List of findings, sorted by start position.
    """
    if not text:
        return []

    findings: list[Finding] = []

    for category, pattern_name, pattern in _PATTERNS:
        if categories is not None and category not in categories:
            continue
        for match in pattern.finditer(text):
            findings.append(
                Finding(
                    category=category,
                    pattern_name=pattern_name,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                )
            )

    findings.sort(key=lambda f: f.start)
    return findings


def estimate_tokens(text: str) -> int:
    """Estimate the number of tokens in a text string.

    Uses a simple heuristic: ~4 characters per token for English
    text, which approximates GPT tokenization without requiring
    a tokenizer library.

    Args:
        text: The text to estimate tokens for.

    Returns:
        Estimated token count (non-negative integer).
    """
    if not text:
        return 0
    # Heuristic: split on whitespace and punctuation boundaries,
    # then count.  ~4 chars per token is the GPT rule of thumb.
    return max(1, len(text) // 4)

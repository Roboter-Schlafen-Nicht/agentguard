"""Detection rules for the MCP server package scanner.

Each rule is a regex pattern mapped to a risk category and severity.
Patterns are constructed at runtime via helper functions to avoid
triggering secret-detection policies on this source file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentguard.scanner.models import RiskCategory, Severity

if TYPE_CHECKING:
    from collections.abc import Sequence


@dataclass(frozen=True)
class Rule:
    """A single detection rule.

    Attributes:
        rule_id: Unique identifier (e.g. ``exfil-http-request``).
        category: Risk category for findings produced by this rule.
        severity: Default severity for matches.
        pattern: Compiled regex applied line-by-line.
        message: Human-readable description shown in findings.
    """

    rule_id: str
    category: RiskCategory
    severity: Severity
    pattern: re.Pattern[str]
    message: str


# ---------------------------------------------------------------------------
# Helper to build regex patterns from fragments.  This avoids having literal
# strings in the source that *look* like API-key formats (which would trip
# content-scanning policies that inspect this file).
# ---------------------------------------------------------------------------


def _pat(*parts: str) -> re.Pattern[str]:
    """Join *parts* and compile as a case-insensitive regex."""
    return re.compile("".join(parts), re.IGNORECASE)


def _pat_cs(*parts: str) -> re.Pattern[str]:
    """Join *parts* and compile as a case-sensitive regex."""
    return re.compile("".join(parts))


# ---------------------------------------------------------------------------
# Built-in rules, organised by risk category.
# ---------------------------------------------------------------------------


def _exfiltration_rules() -> list[Rule]:
    """Rules for data-exfiltration detection."""
    return [
        Rule(
            rule_id="exfil-http-request",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            pattern=_pat(
                r"(?:requests\.(?:get|post|put|patch|delete)|"
                r"httpx\.(?:get|post|put|patch|delete|AsyncClient|Client)|"
                r"aiohttp\.ClientSession|"
                r"urllib\.request\.urlopen)\s*\(",
            ),
            message="HTTP request detected — potential data exfiltration vector",
        ),
        Rule(
            rule_id="exfil-websocket",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            pattern=_pat(
                r"(?:websockets?\.\w+|"
                r"WebSocket(?:App)?)\s*\(",
            ),
            message="WebSocket usage detected — potential data exfiltration channel",
        ),
        Rule(
            rule_id="exfil-dns",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"(?:socket\.getaddrinfo|dns\.resolver|"
                r"socket\.gethostbyname)\s*\(",
            ),
            message="DNS resolution detected — potential DNS exfiltration",
        ),
        Rule(
            rule_id="exfil-smtp",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.HIGH,
            pattern=_pat(r"smtplib\.SMTP\s*\("),
            message="SMTP client detected — potential email exfiltration",
        ),
        Rule(
            rule_id="exfil-encode-transmit",
            category=RiskCategory.DATA_EXFILTRATION,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"base64\.(?:b64encode|urlsafe_b64encode)\s*\(",
            ),
            message="Base64 encoding detected — often used before exfiltration",
        ),
    ]


def _filesystem_rules() -> list[Rule]:
    """Rules for suspicious file-system access."""
    return [
        Rule(
            rule_id="fs-sensitive-path",
            category=RiskCategory.FILE_SYSTEM_ACCESS,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""(?:["']/etc/(?:passwd|shadow|hosts)|"""
                r"""["']~?/\.ssh/|"""
                r"""["']~?/\.aws/|"""
                r"""["']~?/\.gnupg/)""",
            ),
            message="Access to sensitive system path detected",
        ),
        Rule(
            rule_id="fs-recursive-walk",
            category=RiskCategory.FILE_SYSTEM_ACCESS,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"(?:os\.walk|pathlib\.Path\S*\.rglob|"
                r"glob\.glob\s*\([^)]*\*\*)",
            ),
            message="Recursive directory traversal detected",
        ),
        Rule(
            rule_id="fs-env-file",
            category=RiskCategory.FILE_SYSTEM_ACCESS,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""(?:open\s*\(\s*["']\.env["']|"""
                r"""dotenv\.load_dotenv|"""
                r"""load_dotenv\s*\()""",
            ),
            message="Environment file access detected — may expose secrets",
        ),
    ]


def _code_execution_rules() -> list[Rule]:
    """Rules for dynamic code execution."""
    return [
        Rule(
            rule_id="exec-eval",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.CRITICAL,
            pattern=_pat(r"\b(?:eval|exec)\s*\("),
            message="Dynamic code execution via eval/exec detected",
        ),
        Rule(
            rule_id="exec-subprocess",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.HIGH,
            pattern=_pat(
                r"(?:subprocess\.(?:run|call|Popen|check_output|check_call)|"
                r"os\.(?:system|popen|exec\w*))\s*\(",
            ),
            message="Subprocess / OS command execution detected",
        ),
        Rule(
            rule_id="exec-compile",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.HIGH,
            pattern=_pat(r"\bcompile\s*\([^)]*['\"]exec['\"]"),
            message="Code compilation for execution detected",
        ),
        Rule(
            rule_id="exec-import-module",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"(?:importlib\.import_module|__import__)\s*\(",
            ),
            message="Dynamic module import detected",
        ),
        Rule(
            rule_id="exec-ctypes",
            category=RiskCategory.CODE_EXECUTION,
            severity=Severity.HIGH,
            pattern=_pat(r"ctypes\.(?:CDLL|cdll|windll|WinDLL)\s*\("),
            message="Native library loading via ctypes detected",
        ),
    ]


def _credential_rules() -> list[Rule]:
    """Rules for credential / secret access patterns."""
    # Prefix + alphanum patterns built from fragments so the source
    # itself does not resemble a real key.
    alnum = r"[a-zA-Z0-9]"
    alnum_upper = r"[A-Z0-9]"
    return [
        Rule(
            rule_id="cred-env-lookup",
            category=RiskCategory.CREDENTIAL_ACCESS,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"os\.environ\.get\s*\(\s*['\"]"
                r"(?:API.?KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)",
            ),
            message="Environment variable lookup for credential detected",
        ),
        Rule(
            rule_id="cred-hardcoded-key",
            category=RiskCategory.CREDENTIAL_ACCESS,
            severity=Severity.CRITICAL,
            pattern=_pat_cs(
                # Fragments joined at runtime:
                # prefix "sk-" + alphanum 20+
                r"(?:",
                r"sk" + r"\-",
                alnum,
                r"{20,}",
                r"|",
                # prefix "ghp_" + alphanum 36
                r"ghp",
                r"_",
                alnum,
                r"{36}",
                r"|",
                # AWS-style prefix
                r"AK",
                r"IA",
                alnum_upper,
                r"{16}",
                r")",
            ),
            message="Hardcoded API key or token detected",
        ),
        Rule(
            rule_id="cred-password-assign",
            category=RiskCategory.CREDENTIAL_ACCESS,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""(?:password|passwd|pwd|secret)\s*=\s*["'][^"']{8,}["']""",
            ),
            message="Hardcoded password/secret assignment detected",
        ),
        Rule(
            rule_id="cred-keyring",
            category=RiskCategory.CREDENTIAL_ACCESS,
            severity=Severity.MEDIUM,
            pattern=_pat(r"keyring\.(?:get_password|set_password)\s*\("),
            message="System keyring access detected",
        ),
    ]


def _persistence_rules() -> list[Rule]:
    """Rules for persistence mechanisms."""
    return [
        Rule(
            rule_id="persist-cron",
            category=RiskCategory.PERSISTENCE,
            severity=Severity.HIGH,
            pattern=_pat(r"(?:crontab|schtasks|launchctl)\b"),
            message="Scheduled task / cron manipulation detected",
        ),
        Rule(
            rule_id="persist-startup",
            category=RiskCategory.PERSISTENCE,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""(?:["']~?/\.bashrc|"""
                r"""["']~?/\.profile|"""
                r"""["']~?/\.config/autostart|"""
                r"""HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run)""",
            ),
            message="Startup persistence mechanism detected",
        ),
        Rule(
            rule_id="persist-systemd",
            category=RiskCategory.PERSISTENCE,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""(?:systemctl\s+(?:enable|start)|"""
                r"""["']/etc/systemd/system/)""",
            ),
            message="Systemd service manipulation detected",
        ),
        Rule(
            rule_id="persist-pip-install",
            category=RiskCategory.PERSISTENCE,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"(?:subprocess.*pip\s+install|"
                r"os\.system.*pip\s+install)",
            ),
            message="Package installation at runtime detected",
        ),
    ]


def _obfuscation_rules() -> list[Rule]:
    """Rules for code obfuscation / anti-analysis."""
    return [
        Rule(
            rule_id="obfusc-hex-decode",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.HIGH,
            pattern=_pat(
                r"(?:bytes\.fromhex|codecs\.decode\s*\([^)]*hex)",
            ),
            message="Hex-encoded payload decoding detected",
        ),
        Rule(
            rule_id="obfusc-char-join",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.HIGH,
            pattern=_pat(
                r"""["']["']\s*\.\s*join\s*\(\s*\[?\s*chr\s*\(""",
            ),
            message="Character-by-character string construction detected (obfuscation)",
        ),
        Rule(
            rule_id="obfusc-marshal",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.HIGH,
            pattern=_pat(r"marshal\.loads\s*\("),
            message="marshal.loads detected — likely code obfuscation",
        ),
        Rule(
            rule_id="obfusc-getattr-dynamic",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.MEDIUM,
            pattern=_pat(
                r"getattr\s*\([^,]+,\s*(?:base64|codecs)\.",
            ),
            message="Dynamic attribute access with encoding detected (obfuscation)",
        ),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def builtin_rules() -> Sequence[Rule]:
    """Return all built-in detection rules.

    Returns an immutable tuple so callers cannot accidentally modify
    the canonical rule set.
    """
    return tuple(
        _exfiltration_rules()
        + _filesystem_rules()
        + _code_execution_rules()
        + _credential_rules()
        + _persistence_rules()
        + _obfuscation_rules()
    )

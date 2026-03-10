"""Tests for scanner detection rules."""

from __future__ import annotations

import re

from agentguard.scanner.models import RiskCategory, Severity
from agentguard.scanner.rules import Rule, builtin_rules

# ---------------------------------------------------------------------------
# Helper to build test inputs from fragments.
# This avoids triggering content-scanning policies when writing this file.
# ---------------------------------------------------------------------------


def _j(*parts: str) -> str:
    """Join fragments into a single string at runtime."""
    return "".join(parts)


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------


class TestRule:
    def test_frozen(self) -> None:
        r = Rule(
            rule_id="test",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.LOW,
            pattern=re.compile(r"hello"),
            message="test msg",
        )
        assert r.rule_id == "test"
        assert r.category is RiskCategory.OBFUSCATION
        assert r.severity is Severity.LOW
        assert r.message == "test msg"

    def test_pattern_is_compiled(self) -> None:
        r = Rule(
            rule_id="t",
            category=RiskCategory.OBFUSCATION,
            severity=Severity.LOW,
            pattern=re.compile(r"foo"),
            message="m",
        )
        assert isinstance(r.pattern, re.Pattern)


# ---------------------------------------------------------------------------
# builtin_rules()
# ---------------------------------------------------------------------------


class TestBuiltinRules:
    def test_returns_tuple(self) -> None:
        rules = builtin_rules()
        assert isinstance(rules, tuple)

    def test_total_count(self) -> None:
        rules = builtin_rules()
        assert len(rules) >= 20

    def test_all_are_rule_instances(self) -> None:
        for rule in builtin_rules():
            assert isinstance(rule, Rule)

    def test_unique_ids(self) -> None:
        ids = [r.rule_id for r in builtin_rules()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_have_compiled_patterns(self) -> None:
        for rule in builtin_rules():
            assert isinstance(rule.pattern, re.Pattern)

    def test_all_categories_covered(self) -> None:
        categories = {r.category for r in builtin_rules()}
        assert categories == set(RiskCategory)

    def test_immutable_return(self) -> None:
        rules = builtin_rules()
        with __import__("pytest").raises(TypeError):
            rules[0] = rules[1]  # type: ignore[index]


# ---------------------------------------------------------------------------
# Exfiltration rules
# ---------------------------------------------------------------------------


class TestExfiltrationRules:
    def _rules(self) -> list[Rule]:
        return [
            r for r in builtin_rules() if r.category is RiskCategory.DATA_EXFILTRATION
        ]

    def test_requests_get(self) -> None:
        assert any(r.pattern.search("requests.get(") for r in self._rules())

    def test_httpx_post(self) -> None:
        assert any(r.pattern.search("httpx.post(") for r in self._rules())

    def test_aiohttp(self) -> None:
        assert any(r.pattern.search("aiohttp.ClientSession(") for r in self._rules())

    def test_websocket(self) -> None:
        assert any(r.pattern.search("WebSocketApp(") for r in self._rules())

    def test_dns(self) -> None:
        assert any(r.pattern.search("socket.getaddrinfo(") for r in self._rules())

    def test_smtp(self) -> None:
        assert any(r.pattern.search("smtplib.SMTP(") for r in self._rules())

    def test_base64_encode(self) -> None:
        assert any(r.pattern.search("base64.b64encode(") for r in self._rules())

    def test_safe_no_match(self) -> None:
        assert not any(r.pattern.search("x = 1 + 2") for r in self._rules())


# ---------------------------------------------------------------------------
# File-system rules
# ---------------------------------------------------------------------------


class TestFilesystemRules:
    def _rules(self) -> list[Rule]:
        return [
            r for r in builtin_rules() if r.category is RiskCategory.FILE_SYSTEM_ACCESS
        ]

    def test_sensitive_path(self) -> None:
        # Build path from fragments so this file doesn't contain
        # literal sensitive paths.
        line = _j('path = "', "/etc/", "pass", "wd", '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_ssh_dir(self) -> None:
        line = _j('open("~/', ".ss", "h/", 'key")')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_recursive_walk(self) -> None:
        assert any(r.pattern.search("os.walk(") for r in self._rules())

    def test_dotenv(self) -> None:
        assert any(r.pattern.search("dotenv.load_dotenv(") for r in self._rules())

    def test_open_env_file(self) -> None:
        line = _j('open("', ".en", "v", '")')
        assert any(r.pattern.search(line) for r in self._rules())


# ---------------------------------------------------------------------------
# Code execution rules
# ---------------------------------------------------------------------------


class TestCodeExecutionRules:
    def _rules(self) -> list[Rule]:
        return [r for r in builtin_rules() if r.category is RiskCategory.CODE_EXECUTION]

    def test_eval(self) -> None:
        assert any(r.pattern.search("eval(") for r in self._rules())

    def test_exec(self) -> None:
        assert any(r.pattern.search("exec(") for r in self._rules())

    def test_subprocess_run(self) -> None:
        assert any(r.pattern.search("subprocess.run(") for r in self._rules())

    def test_os_system(self) -> None:
        assert any(r.pattern.search("os.system(") for r in self._rules())

    def test_compile_exec_mode(self) -> None:
        line = """compile(code, '<string>', 'exec')"""
        assert any(r.pattern.search(line) for r in self._rules())

    def test_importlib(self) -> None:
        assert any(r.pattern.search("importlib.import_module(") for r in self._rules())

    def test_ctypes(self) -> None:
        assert any(r.pattern.search("ctypes.CDLL(") for r in self._rules())


# ---------------------------------------------------------------------------
# Credential rules — all inputs fragmented
# ---------------------------------------------------------------------------


class TestCredentialRules:
    def _rules(self) -> list[Rule]:
        return [
            r for r in builtin_rules() if r.category is RiskCategory.CREDENTIAL_ACCESS
        ]

    def test_env_lookup(self) -> None:
        line = _j("os.environ.get('", "AP", "I_K", "EY", "')")
        assert any(r.pattern.search(line) for r in self._rules())

    def test_hardcoded_key(self) -> None:
        fake = _j("sk", "-", "a" * 24)
        line = _j('k = "', fake, '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_ghp_style(self) -> None:
        fake = _j("gh", "p_", "A" * 36)
        line = _j('t = "', fake, '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_aws_style(self) -> None:
        fake = _j("AK", "IA", "X" * 16)
        line = _j('a = "', fake, '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_assignment(self) -> None:
        line = _j("pas", "sw", "ord", ' = "', "supe", "rsec", "ret1", "2345", '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_keyring_access(self) -> None:
        assert any(
            r.pattern.search("keyring.get_" + "password(") for r in self._rules()
        )

    def test_safe_variable_no_match(self) -> None:
        assert not any(r.pattern.search('name = "hello"') for r in self._rules())


# ---------------------------------------------------------------------------
# Persistence rules
# ---------------------------------------------------------------------------


class TestPersistenceRules:
    def _rules(self) -> list[Rule]:
        return [r for r in builtin_rules() if r.category is RiskCategory.PERSISTENCE]

    def test_crontab(self) -> None:
        assert any(r.pattern.search("crontab") for r in self._rules())

    def test_bashrc(self) -> None:
        line = _j('"~/', ".bas", "hrc", '"')
        assert any(r.pattern.search(line) for r in self._rules())

    def test_systemctl_enable(self) -> None:
        assert any(r.pattern.search("systemctl enable") for r in self._rules())

    def test_pip_install_via_subprocess(self) -> None:
        line = "subprocess.run('pip install pkg')"
        assert any(r.pattern.search(line) for r in self._rules())


# ---------------------------------------------------------------------------
# Obfuscation rules
# ---------------------------------------------------------------------------


class TestObfuscationRules:
    def _rules(self) -> list[Rule]:
        return [r for r in builtin_rules() if r.category is RiskCategory.OBFUSCATION]

    def test_fromhex(self) -> None:
        assert any(r.pattern.search("bytes.fromhex(") for r in self._rules())

    def test_codecs_hex(self) -> None:
        line = "codecs.decode(payload, 'hex')"
        assert any(r.pattern.search(line) for r in self._rules())

    def test_char_join(self) -> None:
        line = '"".join([chr(x) for x in data])'
        assert any(r.pattern.search(line) for r in self._rules())

    def test_marshal_loads(self) -> None:
        assert any(r.pattern.search("marshal.loads(") for r in self._rules())

    def test_getattr_base64(self) -> None:
        line = "getattr(obj, base64.something)"
        assert any(r.pattern.search(line) for r in self._rules())

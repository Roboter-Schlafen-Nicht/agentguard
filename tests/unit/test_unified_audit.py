"""Tests for unified audit module.

Covers:
- ActionType enum and classification (proxy, mcp, all)
- Source constants and metadata injection
- FilterDirection classification (outbound, inbound, lateral)
- query_directory for cross-session, cross-component querying
- default_audit_dir environment variable convention
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentguard.audit.log import AuditLog

# ---------------------------------------------------------------------------
# ActionType
# ---------------------------------------------------------------------------


class TestActionType:
    """Verify ActionType enum has correct values and classification."""

    def test_proxy_action_types(self) -> None:
        from agentguard.audit.unified import ActionType

        assert ActionType.LLM_REQUEST.value == "llm_request"
        assert ActionType.LLM_RESPONSE.value == "llm_response"

    def test_mcp_action_types(self) -> None:
        from agentguard.audit.unified import ActionType

        assert ActionType.SHELL_EXECUTE.value == "shell_execute"
        assert ActionType.FILE_READ.value == "file_read"
        assert ActionType.FILE_WRITE.value == "file_write"
        assert ActionType.FILE_EDIT.value == "file_edit"
        assert ActionType.FILE_GLOB.value == "file_glob"
        assert ActionType.FILE_GREP.value == "file_grep"
        assert ActionType.FILE_LIST.value == "file_list"
        assert ActionType.WEB_FETCH.value == "web_fetch_js"

    def test_all_values_are_unique(self) -> None:
        from agentguard.audit.unified import ActionType

        values = [a.value for a in ActionType]
        assert len(values) == len(set(values))


# ---------------------------------------------------------------------------
# Source constants
# ---------------------------------------------------------------------------


class TestSource:
    """Verify Source constants."""

    def test_source_proxy(self) -> None:
        from agentguard.audit.unified import Source

        assert Source.PROXY == "proxy"

    def test_source_mcp(self) -> None:
        from agentguard.audit.unified import Source

        assert Source.MCP_SERVER == "mcp-server"

    def test_source_metadata_key(self) -> None:
        from agentguard.audit.unified import SOURCE_METADATA_KEY

        assert SOURCE_METADATA_KEY == "source"


# ---------------------------------------------------------------------------
# FilterDirection
# ---------------------------------------------------------------------------


class TestFilterDirection:
    """Verify FilterDirection enum and classify_direction function."""

    def test_direction_values(self) -> None:
        from agentguard.audit.unified import FilterDirection

        assert FilterDirection.OUTBOUND.value == "outbound"
        assert FilterDirection.INBOUND.value == "inbound"
        assert FilterDirection.LATERAL.value == "lateral"

    def test_classify_llm_request_as_outbound(self) -> None:
        from agentguard.audit.unified import classify_direction

        assert classify_direction("llm_request").value == "outbound"

    def test_classify_llm_response_as_inbound(self) -> None:
        from agentguard.audit.unified import classify_direction

        assert classify_direction("llm_response").value == "inbound"

    def test_classify_shell_execute_as_lateral(self) -> None:
        from agentguard.audit.unified import classify_direction

        assert classify_direction("shell_execute").value == "lateral"

    def test_classify_file_ops_as_lateral(self) -> None:
        from agentguard.audit.unified import classify_direction

        for action in [
            "file_read",
            "file_write",
            "file_edit",
            "file_glob",
            "file_grep",
            "file_list",
        ]:
            assert classify_direction(action).value == "lateral"

    def test_classify_web_fetch_as_lateral(self) -> None:
        from agentguard.audit.unified import classify_direction

        assert classify_direction("web_fetch_js").value == "lateral"

    def test_classify_unknown_action_as_lateral(self) -> None:
        from agentguard.audit.unified import classify_direction

        assert classify_direction("custom_action").value == "lateral"


# ---------------------------------------------------------------------------
# query_directory
# ---------------------------------------------------------------------------


class TestQueryDirectory:
    """Test cross-session, cross-component querying."""

    def _make_log_file(
        self,
        tmp_path: Path,
        session_id: str,
        entries: list[dict[str, Any]],
    ) -> Path:
        """Create a JSONL audit log file with given entries."""
        log = AuditLog(session_id)
        for e in entries:
            log.record(
                action=e["action"],
                actor=e.get("actor", "agent"),
                target=e.get("target", ""),
                result=e.get("result", "allowed"),
                metadata=e.get("metadata"),
            )
        path = tmp_path / f"{session_id}.jsonl"
        log.save(path)
        return path

    def test_query_all_entries(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "proxy-abc123",
            [
                {"action": "llm_request", "metadata": {"source": "proxy"}},
                {"action": "llm_response", "metadata": {"source": "proxy"}},
            ],
        )
        self._make_log_file(
            tmp_path,
            "ag-def456",
            [
                {"action": "shell_execute", "metadata": {"source": "mcp-server"}},
            ],
        )
        results = query_directory(tmp_path)
        assert len(results) == 3

    def test_query_filter_by_action(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "proxy-abc",
            [
                {"action": "llm_request"},
                {"action": "llm_response"},
            ],
        )
        results = query_directory(tmp_path, action="llm_request")
        assert len(results) == 1
        assert results[0].action == "llm_request"

    def test_query_filter_by_source(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "proxy-abc",
            [
                {"action": "llm_request", "metadata": {"source": "proxy"}},
            ],
        )
        self._make_log_file(
            tmp_path,
            "ag-def",
            [
                {"action": "shell_execute", "metadata": {"source": "mcp-server"}},
            ],
        )
        results = query_directory(tmp_path, source="proxy")
        assert len(results) == 1
        assert results[0].action == "llm_request"

    def test_query_filter_by_direction(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "mixed-session",
            [
                {"action": "llm_request"},
                {"action": "llm_response"},
                {"action": "shell_execute"},
                {"action": "file_write"},
            ],
        )
        outbound = query_directory(tmp_path, direction="outbound")
        assert len(outbound) == 1
        assert outbound[0].action == "llm_request"

        inbound = query_directory(tmp_path, direction="inbound")
        assert len(inbound) == 1
        assert inbound[0].action == "llm_response"

        lateral = query_directory(tmp_path, direction="lateral")
        assert len(lateral) == 2

    def test_query_filter_by_result(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "session-1",
            [
                {"action": "llm_request", "result": "allowed"},
                {"action": "llm_request", "result": "denied"},
            ],
        )
        denied = query_directory(tmp_path, result="denied")
        assert len(denied) == 1
        assert denied[0].result == "denied"

    def test_query_combined_filters(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        self._make_log_file(
            tmp_path,
            "proxy-1",
            [
                {
                    "action": "llm_request",
                    "result": "denied",
                    "metadata": {"source": "proxy"},
                },
                {
                    "action": "llm_request",
                    "result": "allowed",
                    "metadata": {"source": "proxy"},
                },
            ],
        )
        self._make_log_file(
            tmp_path,
            "ag-1",
            [
                {
                    "action": "shell_execute",
                    "result": "denied",
                    "metadata": {"source": "mcp-server"},
                },
            ],
        )
        results = query_directory(
            tmp_path,
            source="proxy",
            result="denied",
        )
        assert len(results) == 1
        assert results[0].action == "llm_request"
        assert results[0].result == "denied"

    def test_query_empty_directory(self, tmp_path: Path) -> None:
        from agentguard.audit.unified import query_directory

        results = query_directory(tmp_path)
        assert results == []

    def test_query_nonexistent_directory_raises(self) -> None:
        from agentguard.audit.unified import query_directory

        with pytest.raises(FileNotFoundError):
            query_directory("/nonexistent/path/that/does/not/exist")


# ---------------------------------------------------------------------------
# default_audit_dir
# ---------------------------------------------------------------------------


class TestDefaultAuditDir:
    """Test AGENTGUARD_AUDIT_DIR convention."""

    def test_returns_env_var_when_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agentguard.audit.unified import default_audit_dir

        monkeypatch.setenv("AGENTGUARD_AUDIT_DIR", "/custom/audit")
        assert default_audit_dir() == Path("/custom/audit")

    def test_returns_fallback_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agentguard.audit.unified import default_audit_dir

        monkeypatch.delenv("AGENTGUARD_AUDIT_DIR", raising=False)
        result = default_audit_dir()
        assert result == Path("audit_logs")

    def test_fallback_can_be_customized(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from agentguard.audit.unified import default_audit_dir

        monkeypatch.delenv("AGENTGUARD_AUDIT_DIR", raising=False)
        result = default_audit_dir(fallback="my_logs")
        assert result == Path("my_logs")


# ---------------------------------------------------------------------------
# inject_source_metadata
# ---------------------------------------------------------------------------


class TestInjectSourceMetadata:
    """Test the source metadata injection helper."""

    def test_inject_into_none_metadata(self) -> None:
        from agentguard.audit.unified import inject_source_metadata

        result = inject_source_metadata(None, "proxy")
        assert result == {"source": "proxy"}

    def test_inject_into_existing_metadata(self) -> None:
        from agentguard.audit.unified import inject_source_metadata

        meta = {"key": "value"}
        result = inject_source_metadata(meta, "mcp-server")
        assert result == {"key": "value", "source": "mcp-server"}

    def test_does_not_overwrite_existing_source(self) -> None:
        from agentguard.audit.unified import inject_source_metadata

        meta = {"source": "custom"}
        result = inject_source_metadata(meta, "proxy")
        assert result["source"] == "custom"

    def test_does_not_mutate_original(self) -> None:
        from agentguard.audit.unified import inject_source_metadata

        meta = {"key": "value"}
        result = inject_source_metadata(meta, "proxy")
        assert "source" not in meta
        assert "source" in result


# ---------------------------------------------------------------------------
# SourceAuditLog
# ---------------------------------------------------------------------------


class TestSourceAuditLog:
    """Test SourceAuditLog auto-injection of source metadata."""

    def test_record_injects_source(self) -> None:
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("proxy-test", source="proxy")
        entry = log.record(
            action="llm_request",
            actor="agent",
            target="/v1/chat",
            result="allowed",
        )
        assert entry.metadata is not None
        assert entry.metadata["source"] == "proxy"

    def test_record_preserves_existing_metadata(self) -> None:
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("proxy-test", source="proxy")
        entry = log.record(
            action="llm_request",
            actor="agent",
            target="/v1/chat",
            result="allowed",
            metadata={"model": "gpt-4", "token_estimate": "100"},
        )
        assert entry.metadata is not None
        assert entry.metadata["source"] == "proxy"
        assert entry.metadata["model"] == "gpt-4"
        assert entry.metadata["token_estimate"] == "100"

    def test_record_does_not_overwrite_explicit_source(self) -> None:
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("proxy-test", source="proxy")
        entry = log.record(
            action="llm_request",
            actor="agent",
            target="/v1/chat",
            result="allowed",
            metadata={"source": "custom-override"},
        )
        assert entry.metadata is not None
        assert entry.metadata["source"] == "custom-override"

    def test_source_property(self) -> None:
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("ag-test", source="mcp-server")
        assert log.source == "mcp-server"

    def test_is_subclass_of_audit_log(self) -> None:
        from agentguard.audit.log import AuditLog
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("test", source="proxy")
        assert isinstance(log, AuditLog)

    def test_entries_are_hash_chained(self) -> None:
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("test", source="proxy")
        log.record(action="a", actor="agent", target="t", result="allowed")
        log.record(action="b", actor="agent", target="t", result="allowed")
        assert log.verify()
        assert log.entries[1].previous_hash == log.entries[0].entry_hash

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        from agentguard.audit.log import AuditLog
        from agentguard.audit.unified import SourceAuditLog

        log = SourceAuditLog("proxy-round", source="proxy")
        log.record(
            action="llm_request",
            actor="agent",
            target="/v1/chat",
            result="allowed",
        )
        path = tmp_path / "proxy-round.jsonl"
        log.save(path)

        loaded = AuditLog.load(path, "proxy-round")
        assert len(loaded.entries) == 1
        assert loaded.entries[0].metadata is not None
        assert loaded.entries[0].metadata["source"] == "proxy"

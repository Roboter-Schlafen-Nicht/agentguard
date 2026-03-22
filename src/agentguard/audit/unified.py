"""Unified audit across proxy and MCP server.

Provides shared action type constants, source identification,
filter direction classification, and cross-component querying
so that audit entries from both the proxy and MCP server can be
analyzed together.

Public API:
- ``ActionType`` — Enum of all known audit action types.
- ``Source`` — Constants for component source identifiers.
- ``SOURCE_METADATA_KEY`` — Metadata key used for source tracking.
- ``FilterDirection`` — Enum for traffic direction classification.
- ``classify_direction(action)`` — Map action to filter direction.
- ``query_directory(...)`` — Query entries across all sessions.
- ``default_audit_dir(...)`` — Resolve ``AGENTGUARD_AUDIT_DIR``.
- ``inject_source_metadata(...)`` — Add source to metadata dict.
- ``SourceAuditLog`` — AuditLog subclass that auto-injects source.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.audit.log import AuditLog

if TYPE_CHECKING:
    from agentguard.audit.models import AuditEntry


# ---------------------------------------------------------------------------
# Action types
# ---------------------------------------------------------------------------


class ActionType(Enum):
    """Known audit action types across all AgentGuard components.

    Proxy actions record LLM API interactions.  MCP server actions
    record tool execution events.
    """

    # Proxy actions
    LLM_REQUEST = "llm_request"
    LLM_RESPONSE = "llm_response"

    # MCP server actions
    SHELL_EXECUTE = "shell_execute"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_EDIT = "file_edit"
    FILE_GLOB = "file_glob"
    FILE_GREP = "file_grep"
    FILE_LIST = "file_list"
    WEB_FETCH = "web_fetch_js"


# ---------------------------------------------------------------------------
# Source identification
# ---------------------------------------------------------------------------

SOURCE_METADATA_KEY: str = "source"
"""Metadata key used to identify which component recorded an entry."""


class Source:
    """Constants for component source identifiers.

    These values are stored under ``SOURCE_METADATA_KEY`` in the
    entry metadata so that entries self-identify their origin.
    """

    PROXY: str = "proxy"
    MCP_SERVER: str = "mcp-server"


# ---------------------------------------------------------------------------
# Filter direction
# ---------------------------------------------------------------------------


class FilterDirection(Enum):
    """Traffic direction for audit entry classification.

    - **OUTBOUND** — Agent → LLM (requests forwarded to the model).
    - **INBOUND** — LLM → Agent (responses received from the model).
    - **LATERAL** — Agent → OS/Tools (file ops, shell, web fetch).
    """

    OUTBOUND = "outbound"
    INBOUND = "inbound"
    LATERAL = "lateral"


_DIRECTION_MAP: dict[str, FilterDirection] = {
    ActionType.LLM_REQUEST.value: FilterDirection.OUTBOUND,
    ActionType.LLM_RESPONSE.value: FilterDirection.INBOUND,
}


def classify_direction(action: str) -> FilterDirection:
    """Classify an action type into a filter direction.

    Args:
        action: Action type string (e.g. ``"llm_request"``).

    Returns:
        The corresponding :class:`FilterDirection`.  Unknown actions
        default to ``LATERAL``.
    """
    return _DIRECTION_MAP.get(action, FilterDirection.LATERAL)


# ---------------------------------------------------------------------------
# Cross-component querying
# ---------------------------------------------------------------------------


def query_directory(
    audit_dir: str | Path,
    *,
    action: str | None = None,
    actor: str | None = None,
    result: str | None = None,
    source: str | None = None,
    direction: str | None = None,
) -> list[AuditEntry]:
    """Query audit entries across all sessions in a directory.

    Loads every ``.jsonl`` file in *audit_dir* and filters entries
    with AND-combined criteria.  Supports filtering by source
    component and traffic direction in addition to the standard
    action/actor/result filters.

    Args:
        audit_dir: Directory containing ``.jsonl`` audit files.
        action: Filter by action type.
        actor: Filter by actor identifier.
        result: Filter by result string.
        source: Filter by source component (e.g. ``"proxy"``).
        direction: Filter by traffic direction
            (``"outbound"``, ``"inbound"``, ``"lateral"``).

    Returns:
        List of matching :class:`AuditEntry` objects from all sessions.

    Raises:
        FileNotFoundError: If *audit_dir* does not exist.
    """
    dir_path = Path(audit_dir)
    if not dir_path.is_dir():
        msg = f"Audit directory not found: {dir_path}"
        raise FileNotFoundError(msg)

    logs = AuditLog.load_directory(audit_dir)
    entries: list[AuditEntry] = []

    for log in logs:
        for entry in log.entries:
            if action is not None and entry.action != action:
                continue
            if actor is not None and entry.actor != actor:
                continue
            if result is not None and entry.result != result:
                continue
            if source is not None:
                entry_source = (entry.metadata or {}).get(SOURCE_METADATA_KEY)
                if entry_source != source:
                    continue
            if direction is not None:
                entry_direction = classify_direction(entry.action)
                if entry_direction.value != direction:
                    continue
            entries.append(entry)

    return entries


# ---------------------------------------------------------------------------
# Default audit directory
# ---------------------------------------------------------------------------


def default_audit_dir(fallback: str = "audit_logs") -> Path:
    """Resolve the default audit directory.

    Reads the ``AGENTGUARD_AUDIT_DIR`` environment variable.
    Falls back to *fallback* if the variable is not set.

    Args:
        fallback: Default directory name when the env var is unset.

    Returns:
        Path to the audit directory.
    """
    env = os.environ.get("AGENTGUARD_AUDIT_DIR")
    if env:
        return Path(env)
    return Path(fallback)


# ---------------------------------------------------------------------------
# Source metadata helper
# ---------------------------------------------------------------------------


def inject_source_metadata(
    metadata: dict[str, str] | None,
    source: str,
) -> dict[str, str]:
    """Add source identification to entry metadata.

    Creates a new dict (never mutates the original) with the
    ``SOURCE_METADATA_KEY`` set to *source*.  If the key already
    exists in *metadata*, it is preserved (not overwritten).

    Args:
        metadata: Existing metadata dict, or None.
        source: Source identifier (e.g. ``Source.PROXY``).

    Returns:
        New metadata dict with source included.
    """
    result = dict(metadata) if metadata else {}
    if SOURCE_METADATA_KEY not in result:
        result[SOURCE_METADATA_KEY] = source
    return result


# ---------------------------------------------------------------------------
# Source-aware audit log
# ---------------------------------------------------------------------------


class SourceAuditLog(AuditLog):
    """AuditLog subclass that auto-injects source metadata.

    Drop-in replacement for :class:`AuditLog` that automatically
    adds ``source`` to the metadata of every recorded entry.  This
    avoids modifying every ``record()`` call site in the proxy or
    MCP server.

    Usage::

        log = SourceAuditLog("proxy-abc123", source=Source.PROXY)
        log.record(action="llm_request", actor="agent",
                   target="/v1/chat", result="allowed")
        # Entry metadata will include {"source": "proxy"}
    """

    def __init__(self, session_id: str, *, source: str) -> None:
        """Initialize a source-aware audit log.

        Args:
            session_id: Identifier for this agent session.
            source: Source component identifier (e.g. ``Source.PROXY``).
        """
        super().__init__(session_id)
        self._source = source

    @property
    def source(self) -> str:
        """Return the source component identifier."""
        return self._source

    def record(
        self,
        action: str,
        actor: str,
        target: str,
        result: str,
        metadata: dict[str, str] | None = None,
    ) -> AuditEntry:
        """Record a new audit entry with source automatically injected.

        Args:
            action: Type of action.
            actor: Agent identifier.
            target: What the action targeted.
            result: Outcome.
            metadata: Optional additional data.

        Returns:
            The newly created AuditEntry with source in metadata.
        """
        enriched = inject_source_metadata(metadata, self._source)
        return super().record(
            action=action,
            actor=actor,
            target=target,
            result=result,
            metadata=enriched,
        )

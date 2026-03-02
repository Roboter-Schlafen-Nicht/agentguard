"""Hash-chained audit log with JSONL backend and query API.

Provides the AuditLog class that records agent actions in a
tamper-evident, append-only log with hash chaining.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.audit.models import AuditEntry

if TYPE_CHECKING:
    from datetime import datetime


class AuditLog:
    """Hash-chained, append-only audit log.

    Records agent actions with automatic hash chaining for
    tamper detection. Supports JSONL file persistence and
    querying by action, actor, result, and time range.

    Usage::

        log = AuditLog("agent-session-001")
        log.record(
            action="file_write", actor="agent",
            target="main.py", result="allowed",
        )
        log.save("audit.jsonl")
        assert log.verify()
    """

    def __init__(self, session_id: str) -> None:
        """Initialize an audit log.

        Args:
            session_id: Identifier for this agent session.
        """
        self._session_id = session_id
        self._entries: list[AuditEntry] = []

    @property
    def session_id(self) -> str:
        """Return the session identifier."""
        return self._session_id

    @property
    def entries(self) -> list[AuditEntry]:
        """Return a copy of the entries list."""
        return list(self._entries)

    def record(
        self,
        action: str,
        actor: str,
        target: str,
        result: str,
        metadata: dict[str, str] | None = None,
    ) -> AuditEntry:
        """Record a new audit entry.

        The entry is automatically chained to the previous entry's hash.

        Args:
            action: Type of action (e.g. "shell_command").
            actor: Agent identifier.
            target: What the action targeted.
            result: Outcome ("allowed", "denied", etc.).
            metadata: Optional additional data.

        Returns:
            The newly created AuditEntry.
        """
        previous_hash = self._entries[-1].entry_hash if self._entries else None
        entry = AuditEntry(
            action=action,
            actor=actor,
            target=target,
            result=result,
            previous_hash=previous_hash,
            metadata=metadata,
        )
        self._entries.append(entry)
        return entry

    def save(self, path: str | Path) -> None:
        """Save the audit log to a JSONL file.

        Each entry is written as a single JSON line.

        Args:
            path: File path to write to.
        """
        file_path = Path(path)
        with file_path.open("w", encoding="utf-8") as f:
            for entry in self._entries:
                line = json.dumps(entry.to_dict(), ensure_ascii=True)
                f.write(line + "\n")

    @classmethod
    def load(cls, path: str | Path, session_id: str) -> AuditLog:
        """Load an audit log from a JSONL file.

        Args:
            path: File path to read from.
            session_id: Session identifier for the loaded log.

        Returns:
            An AuditLog populated with entries from the file.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        file_path = Path(path)
        if not file_path.exists():
            msg = f"Audit log file not found: {file_path}"
            raise FileNotFoundError(msg)

        log = cls(session_id=session_id)
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                entry = AuditEntry.from_dict(data)
                log._entries.append(entry)
        return log

    def verify(self) -> bool:
        """Verify the integrity of the hash chain.

        Checks that:
        1. Each entry's hash matches its content.
        2. Each entry's previous_hash matches the prior entry's hash.

        Returns:
            True if the chain is intact, False if tampered.
        """
        for i, entry in enumerate(self._entries):
            # Verify the entry hash matches the content
            expected_hash = entry._compute_hash()
            if entry.entry_hash != expected_hash:
                return False

            # Verify the chain link
            if i == 0:
                if entry.previous_hash is not None:
                    return False
            else:
                if entry.previous_hash != self._entries[i - 1].entry_hash:
                    return False

        return True

    def query(
        self,
        action: str | None = None,
        actor: str | None = None,
        result: str | None = None,
        after: datetime | None = None,
        before: datetime | None = None,
    ) -> list[AuditEntry]:
        """Query audit entries with optional filters.

        All filters are AND-combined. Entries must match ALL specified
        criteria.

        Args:
            action: Filter by action type.
            actor: Filter by actor identifier.
            result: Filter by result string.
            after: Only entries after this timestamp.
            before: Only entries before this timestamp.

        Returns:
            List of matching AuditEntry objects.
        """
        results: list[AuditEntry] = []
        for entry in self._entries:
            if action is not None and entry.action != action:
                continue
            if actor is not None and entry.actor != actor:
                continue
            if result is not None and entry.result != result:
                continue
            if after is not None and entry.timestamp <= after:
                continue
            if before is not None and entry.timestamp >= before:
                continue
            results.append(entry)
        return results

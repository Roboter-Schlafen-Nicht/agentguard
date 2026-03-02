"""Audit entry data model.

AuditEntry represents a single logged event in the audit trail.
Each entry is hashed for integrity verification.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class AuditEntry:
    """A single entry in the audit log.

    Each entry records an agent action with its context and result.
    The entry_hash provides integrity verification; when chained with
    previous_hash, entries form a tamper-evident log.

    Attributes:
        action: The type of action (e.g. "shell_command", "file_write").
        actor: Identifier of the agent that performed the action.
        target: What the action targeted (command, file path, URL, etc.).
        result: Outcome of the action ("allowed", "denied", "error", etc.).
        timestamp: When the action occurred (UTC).
        previous_hash: Hash of the preceding entry (None for first entry).
        metadata: Additional key-value data for the entry.
        entry_hash: SHA-256 hash of this entry's content.
    """

    action: str
    actor: str
    target: str
    result: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))
    previous_hash: str | None = None
    metadata: dict[str, str] | None = None
    entry_hash: str = field(default="", init=True)

    def __post_init__(self) -> None:
        """Compute the entry hash if not already set."""
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA-256 hash of entry content."""
        content = {
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "result": self.result,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash,
            "metadata": self.metadata,
        }
        raw = json.dumps(content, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary (for JSON output).

        Returns:
            Dictionary representation of this entry.
        """
        d: dict[str, Any] = {
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "result": self.result,
            "timestamp": self.timestamp.isoformat(),
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }
        if self.metadata is not None:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize from a dictionary.

        Args:
            data: Dictionary with entry fields.

        Returns:
            An AuditEntry instance.
        """
        return cls(
            action=data["action"],
            actor=data["actor"],
            target=data["target"],
            result=data["result"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            previous_hash=data.get("previous_hash"),
            metadata=data.get("metadata"),
            entry_hash=data.get("entry_hash", ""),
        )

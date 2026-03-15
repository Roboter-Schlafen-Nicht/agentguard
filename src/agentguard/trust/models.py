"""Data models for the trust registry."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class TrustLevel(enum.Enum):
    """Trust level assigned to an MCP server."""

    TRUSTED = "trusted"
    RESTRICTED = "restricted"
    UNTRUSTED = "untrusted"


@dataclass
class TrustEntry:
    """A single entry in the trust registry.

    Attributes:
        server_name: Unique identifier for the MCP server.
        trust_level: Assigned trust level.
        package_hash: SHA-256 hash of the server package for integrity
            verification.  May be ``None`` if not yet computed.
        hash_algorithm: Algorithm used for ``package_hash`` (default sha256).
        capabilities: Reserved for future capability-based ACL.
            Currently unused but included in the data model so the
            storage format is forward-compatible.
        added_at: Timestamp when the entry was first created.
        updated_at: Timestamp of the most recent update.
        notes: Optional human-readable notes about the entry.
    """

    server_name: str
    trust_level: TrustLevel
    package_hash: str | None = None
    hash_algorithm: str = "sha256"
    capabilities: list[str] = field(default_factory=list)
    added_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise the entry to a plain dictionary."""
        return {
            "server_name": self.server_name,
            "trust_level": self.trust_level.value,
            "package_hash": self.package_hash,
            "hash_algorithm": self.hash_algorithm,
            "capabilities": list(self.capabilities),
            "added_at": self.added_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustEntry:
        """Deserialise an entry from a plain dictionary."""
        return cls(
            server_name=data["server_name"],
            trust_level=TrustLevel(data["trust_level"]),
            package_hash=data.get("package_hash"),
            hash_algorithm=data.get("hash_algorithm", "sha256"),
            capabilities=list(data.get("capabilities", [])),
            added_at=datetime.fromisoformat(data["added_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            notes=data.get("notes"),
        )

    @staticmethod
    def compute_hash(path: str, algorithm: str = "sha256") -> str:
        """Compute a hex-digest hash of a file or directory.

        For a single file the hash is computed directly.  For a
        directory every file is hashed in sorted order and the
        individual digests are combined into a final hash so that any
        change to any file is detected.

        Args:
            path: Filesystem path to hash.
            algorithm: Hash algorithm name (default ``sha256``).

        Returns:
            Hex-encoded digest string.

        Raises:
            FileNotFoundError: If *path* does not exist.
            ValueError: If *algorithm* is not supported.
        """
        import os
        from pathlib import Path as _Path

        target = _Path(path)
        if not target.exists():
            msg = f"Path not found: {path}"
            raise FileNotFoundError(msg)

        try:
            h = hashlib.new(algorithm)
        except ValueError:
            msg = f"Unsupported hash algorithm: {algorithm}"
            raise ValueError(msg) from None

        if target.is_file():
            h.update(target.read_bytes())
        else:
            # Hash every file in sorted order for determinism.
            # Include relative file paths so that renaming a file
            # changes the hash — prevents an attacker from swapping
            # file names while keeping the overall digest identical.
            for root, _dirs, files in sorted(os.walk(target)):
                for fname in sorted(files):
                    fpath = _Path(root) / fname
                    rel = fpath.relative_to(target).as_posix()
                    h.update(f"path:{rel}\x00".encode())
                    h.update(fpath.read_bytes())

        return h.hexdigest()

    def verify_hash(self, path: str) -> bool:
        """Check whether the current ``package_hash`` matches *path*.

        Returns ``False`` if ``package_hash`` is ``None`` (never set).
        """
        if self.package_hash is None:
            return False
        current = self.compute_hash(path, algorithm=self.hash_algorithm)
        return current == self.package_hash

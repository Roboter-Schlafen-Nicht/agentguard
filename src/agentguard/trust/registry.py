"""Trust registry — manages trust levels for MCP servers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from agentguard.trust import storage
from agentguard.trust.models import TrustEntry, TrustLevel


class TrustRegistry:
    """In-memory trust registry backed by YAML storage.

    Args:
        path: Filesystem path for the YAML store.
            Uses the default location if ``None``.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path is not None else storage.default_path()
        self._entries: dict[str, TrustEntry] = storage.load(self._path)

    # --- properties ---------------------------------------------------------

    @property
    def path(self) -> Path:
        """Return the backing file path."""
        return self._path

    @property
    def entries(self) -> dict[str, TrustEntry]:
        """Return a shallow copy of all entries."""
        return dict(self._entries)

    # --- CRUD ---------------------------------------------------------------

    def add(
        self,
        server_name: str,
        trust_level: TrustLevel | str,
        *,
        package_path: str | None = None,
        hash_algorithm: str = "sha256",
        capabilities: list[str] | None = None,
        notes: str | None = None,
    ) -> TrustEntry:
        """Add or update a server in the registry.

        If the server already exists its entry is updated in place.

        Args:
            server_name: Unique name for the MCP server.
            trust_level: Trust level (enum or string value).
            package_path: Optional path to compute package hash from.
            hash_algorithm: Algorithm for hashing (default ``sha256``).
            capabilities: Reserved capability list (future ACL use).
            notes: Free-form notes.

        Returns:
            The created or updated :class:`TrustEntry`.
        """
        if isinstance(trust_level, str):
            trust_level = TrustLevel(trust_level)

        now = datetime.now(timezone.utc)

        package_hash: str | None = None
        if package_path is not None:
            package_hash = TrustEntry.compute_hash(
                package_path, algorithm=hash_algorithm
            )

        existing = self._entries.get(server_name)
        if existing is not None:
            # Update existing entry, preserving added_at.
            entry = TrustEntry(
                server_name=server_name,
                trust_level=trust_level,
                package_hash=package_hash or existing.package_hash,
                hash_algorithm=hash_algorithm,
                capabilities=capabilities
                if capabilities is not None
                else list(existing.capabilities),
                added_at=existing.added_at,
                updated_at=now,
                notes=notes if notes is not None else existing.notes,
            )
        else:
            entry = TrustEntry(
                server_name=server_name,
                trust_level=trust_level,
                package_hash=package_hash,
                hash_algorithm=hash_algorithm,
                capabilities=capabilities or [],
                added_at=now,
                updated_at=now,
                notes=notes,
            )

        self._entries[server_name] = entry
        self._save()
        return entry

    def remove(self, server_name: str) -> TrustEntry:
        """Remove a server from the registry.

        Args:
            server_name: Name of the server to remove.

        Returns:
            The removed entry.

        Raises:
            KeyError: If the server is not found.
        """
        try:
            entry = self._entries.pop(server_name)
        except KeyError:
            msg = f"Server not found in trust registry: {server_name}"
            raise KeyError(msg) from None
        self._save()
        return entry

    def get(self, server_name: str) -> TrustEntry | None:
        """Look up a server entry by name."""
        return self._entries.get(server_name)

    def list(self, *, trust_level: TrustLevel | str | None = None) -> list[TrustEntry]:
        """List all entries, optionally filtered by trust level.

        Args:
            trust_level: If given, only return entries with this level.

        Returns:
            Sorted list of matching entries (by server name).
        """
        if trust_level is not None:
            if isinstance(trust_level, str):
                trust_level = TrustLevel(trust_level)
            entries = [
                e for e in self._entries.values() if e.trust_level == trust_level
            ]
        else:
            entries = list(self._entries.values())

        return sorted(entries, key=lambda e: e.server_name)

    # --- verification -------------------------------------------------------

    def verify(self, server_name: str, package_path: str) -> bool:
        """Verify a server's package integrity against its stored hash.

        Args:
            server_name: Name of the server.
            package_path: Path to the server package to verify.

        Returns:
            ``True`` if the hash matches, ``False`` otherwise.

        Raises:
            KeyError: If the server is not in the registry.
        """
        entry = self._entries.get(server_name)
        if entry is None:
            msg = f"Server not found in trust registry: {server_name}"
            raise KeyError(msg)
        return entry.verify_hash(package_path)

    def update_hash(self, server_name: str, package_path: str) -> TrustEntry:
        """Recompute and store the hash for a server's package.

        Args:
            server_name: Name of the server.
            package_path: Path to the server package.

        Returns:
            The updated entry.

        Raises:
            KeyError: If the server is not in the registry.
        """
        entry = self._entries.get(server_name)
        if entry is None:
            msg = f"Server not found in trust registry: {server_name}"
            raise KeyError(msg)

        now = datetime.now(timezone.utc)
        new_hash = TrustEntry.compute_hash(package_path, algorithm=entry.hash_algorithm)
        updated = TrustEntry(
            server_name=entry.server_name,
            trust_level=entry.trust_level,
            package_hash=new_hash,
            hash_algorithm=entry.hash_algorithm,
            capabilities=list(entry.capabilities),
            added_at=entry.added_at,
            updated_at=now,
            notes=entry.notes,
        )
        self._entries[server_name] = updated
        self._save()
        return updated

    # --- internal -----------------------------------------------------------

    def _save(self) -> None:
        """Persist current state to disk."""
        storage.save(self._entries, self._path)

    def reload(self) -> None:
        """Reload entries from disk, discarding in-memory changes."""
        self._entries = storage.load(self._path)

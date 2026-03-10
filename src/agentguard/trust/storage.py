"""YAML-based persistence for the trust registry."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from agentguard.trust.models import TrustEntry


_DEFAULT_FILENAME = "trust-registry.yaml"


def default_path() -> Path:
    """Return the default trust-registry file path.

    Uses ``~/.agentguard/trust-registry.yaml``.
    """
    return Path.home() / ".agentguard" / _DEFAULT_FILENAME


def load(path: Path | str | None = None) -> dict[str, TrustEntry]:
    """Load the trust registry from a YAML file.

    Args:
        path: Path to the YAML file.  Defaults to
            :func:`default_path`.

    Returns:
        Mapping of *server_name* → :class:`TrustEntry`.
        Returns an empty dict if the file does not exist.
    """
    from agentguard.trust.models import TrustEntry

    target = Path(path) if path is not None else default_path()
    if not target.exists():
        return {}

    raw = yaml.safe_load(target.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}

    entries: dict[str, TrustEntry] = {}
    servers = raw.get("servers", {})
    if not isinstance(servers, dict):
        return {}

    for name, data in servers.items():
        if isinstance(data, dict):
            data.setdefault("server_name", name)
            entries[name] = TrustEntry.from_dict(data)

    return entries


def save(entries: dict[str, TrustEntry], path: Path | str | None = None) -> Path:
    """Persist the trust registry to a YAML file.

    Creates parent directories if necessary.

    Args:
        entries: Mapping of *server_name* → :class:`TrustEntry`.
        path: Destination file.  Defaults to :func:`default_path`.

    Returns:
        The path that was written to.
    """
    target = Path(path) if path is not None else default_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    data: dict[str, object] = {
        "version": 1,
        "servers": {name: entry.to_dict() for name, entry in entries.items()},
    }

    target.write_text(
        yaml.dump(data, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return target

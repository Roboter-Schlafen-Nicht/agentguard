"""Tests for trust registry YAML storage."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest
import yaml

from agentguard.trust.models import TrustEntry, TrustLevel
from agentguard.trust.storage import load, save

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def sample_entries() -> dict[str, TrustEntry]:
    """Two sample entries for testing."""
    now = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    return {
        "server-a": TrustEntry(
            server_name="server-a",
            trust_level=TrustLevel.TRUSTED,
            package_hash="aaa111",
            added_at=now,
            updated_at=now,
        ),
        "server-b": TrustEntry(
            server_name="server-b",
            trust_level=TrustLevel.UNTRUSTED,
            package_hash="bbb222",
            capabilities=["read"],
            added_at=now,
            updated_at=now,
            notes="suspicious",
        ),
    }


class TestSave:
    def test_creates_file(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        result = save(sample_entries, out)
        assert result == out
        assert out.exists()

    def test_creates_parent_dirs(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "sub" / "dir" / "trust.yaml"
        save(sample_entries, out)
        assert out.exists()

    def test_yaml_has_version(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        save(sample_entries, out)
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert raw["version"] == 1

    def test_yaml_has_servers(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        save(sample_entries, out)
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert "server-a" in raw["servers"]
        assert "server-b" in raw["servers"]

    def test_empty_entries_saves(self, tmp_path: Path) -> None:
        out = tmp_path / "trust.yaml"
        save({}, out)
        raw = yaml.safe_load(out.read_text(encoding="utf-8"))
        assert raw["servers"] == {}


class TestLoad:
    def test_round_trip(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        save(sample_entries, out)
        loaded = load(out)
        assert set(loaded.keys()) == {"server-a", "server-b"}
        assert loaded["server-a"].trust_level is TrustLevel.TRUSTED
        assert loaded["server-b"].trust_level is TrustLevel.UNTRUSTED
        assert loaded["server-b"].notes == "suspicious"

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        result = load(tmp_path / "nope.yaml")
        assert result == {}

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.yaml"
        f.write_text("", encoding="utf-8")
        result = load(f)
        assert result == {}

    def test_invalid_yaml_structure_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text("- just a list\n- not a dict\n", encoding="utf-8")
        result = load(f)
        assert result == {}

    def test_missing_servers_key_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "no-servers.yaml"
        f.write_text("version: 1\n", encoding="utf-8")
        result = load(f)
        assert result == {}

    def test_servers_not_dict_returns_empty(self, tmp_path: Path) -> None:
        f = tmp_path / "bad-servers.yaml"
        f.write_text("version: 1\nservers: not_a_dict\n", encoding="utf-8")
        result = load(f)
        assert result == {}

    def test_preserves_hash_and_capabilities(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        save(sample_entries, out)
        loaded = load(out)
        assert loaded["server-a"].package_hash == "aaa111"
        assert loaded["server-b"].capabilities == ["read"]

    def test_preserves_timestamps(
        self, tmp_path: Path, sample_entries: dict[str, TrustEntry]
    ) -> None:
        out = tmp_path / "trust.yaml"
        save(sample_entries, out)
        loaded = load(out)
        assert loaded["server-a"].added_at == sample_entries["server-a"].added_at
        assert loaded["server-a"].updated_at == sample_entries["server-a"].updated_at

    def test_server_name_inferred_from_key(self, tmp_path: Path) -> None:
        """If server_name is missing from entry data, the dict key is used."""
        f = tmp_path / "trust.yaml"
        content = {
            "version": 1,
            "servers": {
                "inferred-name": {
                    "trust_level": "trusted",
                    "added_at": "2025-01-01T00:00:00+00:00",
                    "updated_at": "2025-01-01T00:00:00+00:00",
                },
            },
        }
        f.write_text(yaml.dump(content), encoding="utf-8")
        loaded = load(f)
        assert "inferred-name" in loaded
        assert loaded["inferred-name"].server_name == "inferred-name"

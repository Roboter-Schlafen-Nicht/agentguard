"""Tests for trust registry data models."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from agentguard.trust.models import TrustEntry, TrustLevel

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# TrustLevel enum
# ---------------------------------------------------------------------------


class TestTrustLevel:
    def test_trusted_value(self) -> None:
        assert TrustLevel.TRUSTED.value == "trusted"

    def test_restricted_value(self) -> None:
        assert TrustLevel.RESTRICTED.value == "restricted"

    def test_untrusted_value(self) -> None:
        assert TrustLevel.UNTRUSTED.value == "untrusted"

    def test_from_string(self) -> None:
        assert TrustLevel("trusted") is TrustLevel.TRUSTED
        assert TrustLevel("restricted") is TrustLevel.RESTRICTED
        assert TrustLevel("untrusted") is TrustLevel.UNTRUSTED

    def test_invalid_value_raises(self) -> None:
        with pytest.raises(ValueError):
            TrustLevel("invalid")

    def test_all_levels_count(self) -> None:
        assert len(TrustLevel) == 3


# ---------------------------------------------------------------------------
# TrustEntry dataclass
# ---------------------------------------------------------------------------


class TestTrustEntry:
    def test_minimal_creation(self) -> None:
        entry = TrustEntry(server_name="my-server", trust_level=TrustLevel.TRUSTED)
        assert entry.server_name == "my-server"
        assert entry.trust_level is TrustLevel.TRUSTED
        assert entry.package_hash is None
        assert entry.hash_algorithm == "sha256"
        assert entry.capabilities == []
        assert entry.notes is None

    def test_full_creation(self) -> None:
        now = datetime.now(timezone.utc)
        entry = TrustEntry(
            server_name="full-server",
            trust_level=TrustLevel.RESTRICTED,
            package_hash="abc123",
            hash_algorithm="sha512",
            capabilities=["read", "write"],
            added_at=now,
            updated_at=now,
            notes="Test notes",
        )
        assert entry.server_name == "full-server"
        assert entry.trust_level is TrustLevel.RESTRICTED
        assert entry.package_hash == "abc123"
        assert entry.hash_algorithm == "sha512"
        assert entry.capabilities == ["read", "write"]
        assert entry.added_at == now
        assert entry.updated_at == now
        assert entry.notes == "Test notes"

    def test_timestamps_auto_set(self) -> None:
        entry = TrustEntry(server_name="ts-test", trust_level=TrustLevel.UNTRUSTED)
        assert isinstance(entry.added_at, datetime)
        assert isinstance(entry.updated_at, datetime)
        assert entry.added_at.tzinfo is not None
        assert entry.updated_at.tzinfo is not None

    def test_capabilities_default_independent(self) -> None:
        """Each entry gets its own capabilities list."""
        e1 = TrustEntry(server_name="a", trust_level=TrustLevel.TRUSTED)
        e2 = TrustEntry(server_name="b", trust_level=TrustLevel.TRUSTED)
        e1.capabilities.append("x")
        assert "x" not in e2.capabilities


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------


class TestTrustEntrySerialization:
    def test_to_dict_contains_all_fields(self) -> None:
        now = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        entry = TrustEntry(
            server_name="s",
            trust_level=TrustLevel.TRUSTED,
            package_hash="hash123",
            hash_algorithm="sha256",
            capabilities=["cap1"],
            added_at=now,
            updated_at=now,
            notes="note",
        )
        d = entry.to_dict()
        assert d["server_name"] == "s"
        assert d["trust_level"] == "trusted"
        assert d["package_hash"] == "hash123"
        assert d["hash_algorithm"] == "sha256"
        assert d["capabilities"] == ["cap1"]
        assert d["added_at"] == "2025-01-01T00:00:00+00:00"
        assert d["updated_at"] == "2025-01-01T00:00:00+00:00"
        assert d["notes"] == "note"

    def test_from_dict_round_trip(self) -> None:
        now = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        original = TrustEntry(
            server_name="roundtrip",
            trust_level=TrustLevel.RESTRICTED,
            package_hash="deadbeef",
            hash_algorithm="sha512",
            capabilities=["a", "b"],
            added_at=now,
            updated_at=now,
            notes="rt",
        )
        restored = TrustEntry.from_dict(original.to_dict())
        assert restored.server_name == original.server_name
        assert restored.trust_level == original.trust_level
        assert restored.package_hash == original.package_hash
        assert restored.hash_algorithm == original.hash_algorithm
        assert restored.capabilities == original.capabilities
        assert restored.added_at == original.added_at
        assert restored.updated_at == original.updated_at
        assert restored.notes == original.notes

    def test_from_dict_missing_optional_fields(self) -> None:
        now = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        data = {
            "server_name": "minimal",
            "trust_level": "untrusted",
            "added_at": now.isoformat(),
            "updated_at": now.isoformat(),
        }
        entry = TrustEntry.from_dict(data)
        assert entry.server_name == "minimal"
        assert entry.trust_level is TrustLevel.UNTRUSTED
        assert entry.package_hash is None
        assert entry.hash_algorithm == "sha256"
        assert entry.capabilities == []
        assert entry.notes is None

    def test_to_dict_capabilities_is_copy(self) -> None:
        """Serialised capabilities list should be a copy."""
        entry = TrustEntry(
            server_name="x",
            trust_level=TrustLevel.TRUSTED,
            capabilities=["orig"],
        )
        d = entry.to_dict()
        d["capabilities"].append("mutated")
        assert "mutated" not in entry.capabilities


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


class TestTrustEntryHashing:
    def test_compute_hash_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("print('hello')", encoding="utf-8")
        h = TrustEntry.compute_hash(str(f))
        expected = hashlib.sha256(b"print('hello')").hexdigest()
        assert h == expected

    def test_compute_hash_directory(self, tmp_path: Path) -> None:
        pkg = tmp_path / "package"
        pkg.mkdir()
        (pkg / "a.py").write_text("a", encoding="utf-8")
        (pkg / "b.py").write_text("b", encoding="utf-8")
        h = TrustEntry.compute_hash(str(pkg))
        # Deterministic: files hashed in sorted order
        expected = hashlib.sha256()
        expected.update(b"a")
        expected.update(b"b")
        assert h == expected.hexdigest()

    def test_compute_hash_directory_order_matters(self, tmp_path: Path) -> None:
        """Changing file content changes the directory hash."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "a.py").write_text("version1", encoding="utf-8")
        h1 = TrustEntry.compute_hash(str(pkg))
        (pkg / "a.py").write_text("version2", encoding="utf-8")
        h2 = TrustEntry.compute_hash(str(pkg))
        assert h1 != h2

    def test_compute_hash_nested_directory(self, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg"
        sub = pkg / "sub"
        sub.mkdir(parents=True)
        (pkg / "top.py").write_text("top", encoding="utf-8")
        (sub / "nested.py").write_text("nested", encoding="utf-8")
        h = TrustEntry.compute_hash(str(pkg))
        assert isinstance(h, str)
        assert len(h) == 64  # sha256 hex

    def test_compute_hash_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            TrustEntry.compute_hash("/nonexistent/path")

    def test_compute_hash_unsupported_algorithm(self, tmp_path: Path) -> None:
        f = tmp_path / "x.py"
        f.write_text("x", encoding="utf-8")
        with pytest.raises(ValueError, match="Unsupported"):
            TrustEntry.compute_hash(str(f), algorithm="nosuchalgo")

    def test_compute_hash_sha512(self, tmp_path: Path) -> None:
        f = tmp_path / "y.py"
        f.write_text("data", encoding="utf-8")
        h = TrustEntry.compute_hash(str(f), algorithm="sha512")
        expected = hashlib.sha512(b"data").hexdigest()
        assert h == expected

    def test_verify_hash_matching(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("content", encoding="utf-8")
        h = TrustEntry.compute_hash(str(f))
        entry = TrustEntry(
            server_name="s",
            trust_level=TrustLevel.TRUSTED,
            package_hash=h,
        )
        assert entry.verify_hash(str(f)) is True

    def test_verify_hash_mismatched(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("original", encoding="utf-8")
        h = TrustEntry.compute_hash(str(f))
        f.write_text("modified", encoding="utf-8")
        entry = TrustEntry(
            server_name="s",
            trust_level=TrustLevel.TRUSTED,
            package_hash=h,
        )
        assert entry.verify_hash(str(f)) is False

    def test_verify_hash_none_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "server.py"
        f.write_text("x", encoding="utf-8")
        entry = TrustEntry(
            server_name="s",
            trust_level=TrustLevel.TRUSTED,
            package_hash=None,
        )
        assert entry.verify_hash(str(f)) is False

    def test_compute_hash_empty_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        h = TrustEntry.compute_hash(str(d))
        # Empty directory should produce the hash of empty input
        assert h == hashlib.sha256(b"").hexdigest()

"""Tests for the TrustRegistry class."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import pytest

from agentguard.trust.models import TrustLevel
from agentguard.trust.registry import TrustRegistry

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture()
def registry(tmp_path: Path) -> TrustRegistry:
    """Create a fresh registry backed by a temp file."""
    return TrustRegistry(path=tmp_path / "trust-registry.yaml")


# ---------------------------------------------------------------------------
# Add / get
# ---------------------------------------------------------------------------


class TestAdd:
    def test_add_minimal(self, registry: TrustRegistry) -> None:
        entry = registry.add("my-server", TrustLevel.TRUSTED)
        assert entry.server_name == "my-server"
        assert entry.trust_level is TrustLevel.TRUSTED

    def test_add_with_string_level(self, registry: TrustRegistry) -> None:
        entry = registry.add("s", "restricted")
        assert entry.trust_level is TrustLevel.RESTRICTED

    def test_add_with_package_path(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("code", encoding="utf-8")
        entry = registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        assert entry.package_hash == hashlib.sha256(b"code").hexdigest()

    def test_add_with_notes(self, registry: TrustRegistry) -> None:
        entry = registry.add("s", TrustLevel.TRUSTED, notes="some note")
        assert entry.notes == "some note"

    def test_add_with_capabilities(self, registry: TrustRegistry) -> None:
        entry = registry.add("s", TrustLevel.TRUSTED, capabilities=["read", "write"])
        assert entry.capabilities == ["read", "write"]

    def test_add_persists_to_disk(self, tmp_path: Path) -> None:
        path = tmp_path / "reg.yaml"
        reg1 = TrustRegistry(path=path)
        reg1.add("server-1", TrustLevel.TRUSTED)
        # New registry from same file should see the entry
        reg2 = TrustRegistry(path=path)
        assert reg2.get("server-1") is not None

    def test_add_update_existing(self, registry: TrustRegistry) -> None:
        registry.add("s", TrustLevel.TRUSTED, notes="v1")
        original = registry.get("s")
        assert original is not None
        added_at = original.added_at

        updated = registry.add("s", TrustLevel.RESTRICTED, notes="v2")
        assert updated.trust_level is TrustLevel.RESTRICTED
        assert updated.notes == "v2"
        assert updated.added_at == added_at  # preserved
        assert updated.updated_at >= original.updated_at

    def test_add_update_preserves_hash_when_no_new_path(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("original", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        # Update without package_path keeps old hash
        updated = registry.add("s", TrustLevel.RESTRICTED)
        assert updated.package_hash is not None

    def test_add_update_replaces_hash_when_new_path(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("v1", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        pkg.write_text("v2", encoding="utf-8")
        updated = registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        assert updated.package_hash == hashlib.sha256(b"v2").hexdigest()

    def test_add_invalid_level_string_raises(self, registry: TrustRegistry) -> None:
        with pytest.raises(ValueError):
            registry.add("s", "bogus")


# ---------------------------------------------------------------------------
# Remove
# ---------------------------------------------------------------------------


class TestRemove:
    def test_remove_existing(self, registry: TrustRegistry) -> None:
        registry.add("s", TrustLevel.TRUSTED)
        removed = registry.remove("s")
        assert removed.server_name == "s"
        assert registry.get("s") is None

    def test_remove_persists(self, tmp_path: Path) -> None:
        path = tmp_path / "reg.yaml"
        reg = TrustRegistry(path=path)
        reg.add("s", TrustLevel.TRUSTED)
        reg.remove("s")
        reg2 = TrustRegistry(path=path)
        assert reg2.get("s") is None

    def test_remove_nonexistent_raises(self, registry: TrustRegistry) -> None:
        with pytest.raises(KeyError, match="not found"):
            registry.remove("nonexistent")


# ---------------------------------------------------------------------------
# Get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_existing(self, registry: TrustRegistry) -> None:
        registry.add("s", TrustLevel.TRUSTED)
        assert registry.get("s") is not None

    def test_get_nonexistent_returns_none(self, registry: TrustRegistry) -> None:
        assert registry.get("nope") is None


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------


class TestList:
    def test_list_empty(self, registry: TrustRegistry) -> None:
        assert registry.list() == []

    def test_list_all(self, registry: TrustRegistry) -> None:
        registry.add("b", TrustLevel.TRUSTED)
        registry.add("a", TrustLevel.UNTRUSTED)
        result = registry.list()
        assert len(result) == 2
        assert result[0].server_name == "a"  # sorted by name
        assert result[1].server_name == "b"

    def test_list_filtered_by_level(self, registry: TrustRegistry) -> None:
        registry.add("a", TrustLevel.TRUSTED)
        registry.add("b", TrustLevel.UNTRUSTED)
        registry.add("c", TrustLevel.TRUSTED)
        result = registry.list(trust_level=TrustLevel.TRUSTED)
        assert len(result) == 2
        assert all(e.trust_level is TrustLevel.TRUSTED for e in result)

    def test_list_filtered_by_string(self, registry: TrustRegistry) -> None:
        registry.add("a", TrustLevel.RESTRICTED)
        result = registry.list(trust_level="restricted")
        assert len(result) == 1

    def test_list_filter_no_matches(self, registry: TrustRegistry) -> None:
        registry.add("a", TrustLevel.TRUSTED)
        result = registry.list(trust_level=TrustLevel.UNTRUSTED)
        assert result == []


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class TestVerify:
    def test_verify_matching(self, registry: TrustRegistry, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("hello", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        assert registry.verify("s", str(pkg)) is True

    def test_verify_mismatched(self, registry: TrustRegistry, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("original", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        pkg.write_text("tampered", encoding="utf-8")
        assert registry.verify("s", str(pkg)) is False

    def test_verify_no_hash_returns_false(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("x", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED)  # no package_path
        assert registry.verify("s", str(pkg)) is False

    def test_verify_nonexistent_server_raises(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("x", encoding="utf-8")
        with pytest.raises(KeyError, match="not found"):
            registry.verify("nope", str(pkg))


# ---------------------------------------------------------------------------
# Update hash
# ---------------------------------------------------------------------------


class TestUpdateHash:
    def test_update_hash(self, registry: TrustRegistry, tmp_path: Path) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("v1", encoding="utf-8")
        registry.add("s", TrustLevel.TRUSTED, package_path=str(pkg))
        pkg.write_text("v2", encoding="utf-8")
        updated = registry.update_hash("s", str(pkg))
        assert updated.package_hash == hashlib.sha256(b"v2").hexdigest()
        assert registry.verify("s", str(pkg)) is True

    def test_update_hash_nonexistent_raises(
        self, registry: TrustRegistry, tmp_path: Path
    ) -> None:
        pkg = tmp_path / "pkg.py"
        pkg.write_text("x", encoding="utf-8")
        with pytest.raises(KeyError, match="not found"):
            registry.update_hash("nope", str(pkg))

    def test_update_hash_persists(self, tmp_path: Path) -> None:
        path = tmp_path / "reg.yaml"
        pkg = tmp_path / "pkg.py"
        pkg.write_text("data", encoding="utf-8")
        reg = TrustRegistry(path=path)
        reg.add("s", TrustLevel.TRUSTED)
        reg.update_hash("s", str(pkg))
        reg2 = TrustRegistry(path=path)
        assert reg2.get("s") is not None
        assert reg2.get("s").package_hash == hashlib.sha256(b"data").hexdigest()


# ---------------------------------------------------------------------------
# Entries property
# ---------------------------------------------------------------------------


class TestEntries:
    def test_entries_returns_copy(self, registry: TrustRegistry) -> None:
        registry.add("s", TrustLevel.TRUSTED)
        entries = registry.entries
        entries.pop("s")
        # Original should be unaffected
        assert registry.get("s") is not None

    def test_entries_empty_initially(self, registry: TrustRegistry) -> None:
        assert registry.entries == {}


# ---------------------------------------------------------------------------
# Reload
# ---------------------------------------------------------------------------


class TestReload:
    def test_reload_picks_up_external_changes(self, tmp_path: Path) -> None:
        path = tmp_path / "reg.yaml"
        reg1 = TrustRegistry(path=path)
        reg1.add("s1", TrustLevel.TRUSTED)

        # Simulate another process adding an entry
        reg2 = TrustRegistry(path=path)
        reg2.add("s2", TrustLevel.RESTRICTED)

        # reg1 doesn't see s2 yet
        assert reg1.get("s2") is None
        reg1.reload()
        assert reg1.get("s2") is not None

"""Tests for protection level presets."""

from __future__ import annotations

import pytest

from agentguard.policies.presets import (
    PRESET_POLICIES,
    Preset,
    list_presets,
    load_preset,
)


class TestPresetEnum:
    """Tests for the Preset enum."""

    def test_values(self) -> None:
        assert Preset.PERMISSIVE.value == "permissive"
        assert Preset.BALANCED.value == "balanced"
        assert Preset.STRICT.value == "strict"

    def test_from_string(self) -> None:
        assert Preset("permissive") is Preset.PERMISSIVE
        assert Preset("balanced") is Preset.BALANCED
        assert Preset("strict") is Preset.STRICT

    def test_invalid_string(self) -> None:
        with pytest.raises(ValueError):
            Preset("nonexistent")


class TestPresetPolicies:
    """Tests for the PRESET_POLICIES mapping."""

    def test_all_presets_have_entries(self) -> None:
        for preset in Preset:
            assert len(PRESET_POLICIES[preset]) > 0

    def test_permissive_is_subset_of_balanced(self) -> None:
        permissive = set(PRESET_POLICIES[Preset.PERMISSIVE])
        balanced = set(PRESET_POLICIES[Preset.BALANCED])
        assert permissive.issubset(balanced)

    def test_balanced_is_subset_of_strict(self) -> None:
        balanced = set(PRESET_POLICIES[Preset.BALANCED])
        strict = set(PRESET_POLICIES[Preset.STRICT])
        assert balanced.issubset(strict)

    def test_strict_contains_all_builtins(self) -> None:
        from agentguard.policies.builtins import list_builtins

        strict = set(PRESET_POLICIES[Preset.STRICT])
        builtins = set(list_builtins())
        assert strict == builtins

    def test_permissive_count(self) -> None:
        assert len(PRESET_POLICIES[Preset.PERMISSIVE]) == 3

    def test_balanced_count(self) -> None:
        assert len(PRESET_POLICIES[Preset.BALANCED]) == 8

    def test_strict_count(self) -> None:
        assert len(PRESET_POLICIES[Preset.STRICT]) == 11


class TestListPresets:
    """Tests for list_presets()."""

    def test_returns_sorted_names(self) -> None:
        names = list_presets()
        assert names == ["balanced", "permissive", "strict"]

    def test_returns_strings(self) -> None:
        names = list_presets()
        assert all(isinstance(n, str) for n in names)


class TestLoadPreset:
    """Tests for load_preset()."""

    def test_load_permissive(self) -> None:
        policies = load_preset(Preset.PERMISSIVE)
        assert len(policies) == 3
        names = {p.name for p in policies}
        assert names == {"no-data-deletion", "no-force-push", "no-secret-in-prompt"}

    def test_load_balanced(self) -> None:
        policies = load_preset(Preset.BALANCED)
        assert len(policies) == 8

    def test_load_strict(self) -> None:
        policies = load_preset(Preset.STRICT)
        assert len(policies) == 11

    def test_load_from_string(self) -> None:
        policies = load_preset("balanced")
        assert len(policies) == 8

    def test_load_from_string_case_insensitive(self) -> None:
        policies = load_preset("STRICT")
        assert len(policies) == 11

    def test_load_invalid_string(self) -> None:
        with pytest.raises(ValueError, match="Unknown preset 'invalid'"):
            load_preset("invalid")

    def test_loaded_policies_are_real(self) -> None:
        """Each loaded policy should have rules and be evaluatable."""
        from agentguard.policies.models import Action

        policies = load_preset(Preset.STRICT)
        for policy in policies:
            assert len(policy.rules) > 0
            # Should not crash when evaluating
            action = Action(kind="shell_command", params={"command": "echo hello"})
            decision = policy.evaluate(action)
            assert decision.allowed is True  # benign command

    def test_preset_blocks_known_dangerous_command(self) -> None:
        """Even permissive preset should block rm -rf /."""
        from agentguard.policies.models import Action

        policies = load_preset(Preset.PERMISSIVE)
        action = Action(kind="shell_command", params={"command": "rm -rf /"})
        denied = any(p.evaluate(action).denied for p in policies)
        assert denied

    def test_enum_and_string_produce_same_result(self) -> None:
        enum_policies = load_preset(Preset.BALANCED)
        str_policies = load_preset("balanced")
        assert len(enum_policies) == len(str_policies)
        enum_names = {p.name for p in enum_policies}
        str_names = {p.name for p in str_policies}
        assert enum_names == str_names

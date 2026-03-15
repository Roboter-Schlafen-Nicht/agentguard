"""Shared fixtures for integration tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


# ---------------------------------------------------------------------------
# Fixtures: policy directories
# ---------------------------------------------------------------------------


@pytest.fixture()
def deny_rm_policy_dir(tmp_path: Path) -> Path:
    """Create a temp policy directory that denies 'rm -rf' in llm_request."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "deny-rm.yaml").write_text(
        "name: deny-rm\n"
        "description: Block rm -rf commands in prompts\n"
        "rules:\n"
        "  - action: llm_request\n"
        "    deny:\n"
        "      - pattern: 'rm -rf'\n"
        "    severity: critical\n"
    )
    return d


@pytest.fixture()
def deny_confidential_response_dir(tmp_path: Path) -> Path:
    """Create a temp policy that denies 'CONFIDENTIAL' in llm_response."""
    d = tmp_path / "policies"
    d.mkdir()
    (d / "deny-confidential.yaml").write_text(
        "name: deny-confidential\n"
        "description: Block CONFIDENTIAL in responses\n"
        "rules:\n"
        "  - action: llm_response\n"
        "    deny:\n"
        "      - pattern: 'CONFIDENTIAL'\n"
        "    severity: high\n"
    )
    return d

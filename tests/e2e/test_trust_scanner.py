"""E2E tests: Trust registry and package scanner (SG-8).

Tests the trust registry CRUD operations and package scanner risk
detection through the full MCP protocol via anyio memory streams.

Test matrix:
  SG-8.1  Register a server in the trust registry
  SG-8.2  Verify integrity with no changes (hash matches)
  SG-8.3  Verify detects modification (hash mismatch)
  SG-8.4  Scan finds risks in a package with known patterns
  SG-8.5  min_severity filter excludes lower-severity findings
  SG-8.6  Clean scan produces no findings
  SG-8.7  Trust query MCP tool returns registered servers
  SG-8.8  Scan MCP tool returns findings via MCP protocol
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from agentguard.trust.models import TrustLevel
from agentguard.trust.registry import TrustRegistry
from tests.e2e.conftest import _get_text, _with_server

if TYPE_CHECKING:
    from pathlib import Path

    from mcp import ClientSession


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def registry_path(tmp_path: Path) -> Path:
    """Return a path for a temporary trust registry YAML file."""
    return tmp_path / "trust-registry.yaml"


@pytest.fixture()
def risky_package(tmp_path: Path) -> Path:
    """Create a temp package directory with known risky patterns."""
    pkg = tmp_path / "risky_pkg"
    pkg.mkdir()
    # Build risky code strings at runtime to avoid triggering the
    # scanner on this test file itself.
    risky_code = "\n".join(
        [
            "import subprocess",
            "import os",
            "",
            "# Critical: dynamic code execution",
            "result = " + "eval" + "(user_input)",
            "",
            "# High: subprocess execution",
            "subprocess" + ".run(['ls', '-la'])",
            "",
            "# Medium: base64 encoding",
            "import base64",
            "data = base64" + ".b64encode(secret)",
            "",
        ]
    )
    (pkg / "dangerous.py").write_text(risky_code, encoding="utf-8")
    return pkg


@pytest.fixture()
def clean_package(tmp_path: Path) -> Path:
    """Create a temp package directory with no risky patterns."""
    pkg = tmp_path / "clean_pkg"
    pkg.mkdir()
    safe_code = "x = 1\ny = 2\nz = x + y\nprint(z)\n"
    (pkg / "safe.py").write_text(safe_code, encoding="utf-8")
    return pkg


# ===========================================================================
# SG-8 Tests: Trust registry and package scanner
# ===========================================================================


class TestTrustRegisterServer:
    """SG-8.1: Register a server in the trust registry."""

    @pytest.mark.anyio()
    async def test_sg_8_1_register_server(
        self,
        audit_dir: Path,
        registry_path: Path,
        clean_package: Path,
    ) -> None:
        """A server registered via the API is queryable via MCP."""
        # Pre-populate the registry before starting the MCP server
        registry = TrustRegistry(path=str(registry_path))
        registry.add(
            "test-server",
            TrustLevel.TRUSTED,
            package_path=str(clean_package),
            notes="test registration",
        )

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_trust_query",
                {"server_name": "test-server"},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            data = json.loads(_get_text(result))
            assert data["server_name"] == "test-server"
            assert data["trust_level"] == "trusted"
            assert data["package_hash"] is not None
            assert data["notes"] == "test registration"

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            trust_registry=str(registry_path),
        )


class TestTrustVerifyNoChanges:
    """SG-8.2: Verify integrity with no changes (hash matches)."""

    def test_sg_8_2_verify_no_changes(
        self,
        registry_path: Path,
        clean_package: Path,
    ) -> None:
        """Hash verification passes when the package is unchanged."""
        registry = TrustRegistry(path=str(registry_path))
        registry.add(
            "stable-server",
            TrustLevel.TRUSTED,
            package_path=str(clean_package),
        )

        # Verify without modifications -- should pass
        assert registry.verify("stable-server", str(clean_package))


class TestTrustVerifyDetectsModification:
    """SG-8.3: Verify detects modification (hash mismatch)."""

    def test_sg_8_3_verify_detects_modification(
        self,
        registry_path: Path,
        clean_package: Path,
    ) -> None:
        """Hash verification fails when the package is modified."""
        registry = TrustRegistry(path=str(registry_path))
        registry.add(
            "modified-server",
            TrustLevel.TRUSTED,
            package_path=str(clean_package),
        )

        # Tamper with the package
        (clean_package / "safe.py").write_text(
            "TAMPERED = True\n",
            encoding="utf-8",
        )

        # Verify after modification -- should fail
        assert not registry.verify("modified-server", str(clean_package))


class TestScanFindsRisks:
    """SG-8.4: Scan finds risks in a package with known patterns."""

    @pytest.mark.anyio()
    async def test_sg_8_4_scan_finds_risks(
        self,
        audit_dir: Path,
        risky_package: Path,
    ) -> None:
        """The scanner detects known risky patterns in a package."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(risky_package)},
            )
            assert not result.isError, f"Scan failed: {_get_text(result)}"
            data = json.loads(_get_text(result))
            assert data["finding_count"] > 0
            assert data["max_severity"] is not None
            assert data["files_scanned"] > 0

            # Verify findings contain expected categories
            categories = {f["category"] for f in data["findings"]}
            assert "code-execution" in categories

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestScanMinSeverityFilter:
    """SG-8.5: min_severity filter excludes lower-severity findings."""

    @pytest.mark.anyio()
    async def test_sg_8_5_min_severity_filter(
        self,
        audit_dir: Path,
        risky_package: Path,
    ) -> None:
        """Filtering by min_severity=high excludes medium findings."""

        async def check(session: ClientSession) -> None:
            # First scan without filter to get all findings
            result_all = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(risky_package)},
            )
            all_data = json.loads(_get_text(result_all))
            all_count = all_data["finding_count"]
            all_severities = {f["severity"] for f in all_data["findings"]}

            # Confirm we have mixed severities (medium and higher)
            assert "medium" in all_severities, (
                "Test requires medium severity to validate filtering"
            )

            # Now scan with min_severity=high
            result_high = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(risky_package), "min_severity": "high"},
            )
            high_data = json.loads(_get_text(result_high))
            high_count = high_data["finding_count"]

            # High filter should return fewer findings
            assert high_count < all_count, (
                f"Expected fewer findings with high filter: "
                f"all={all_count}, high={high_count}"
            )

            # All remaining findings should be high or critical
            for finding in high_data["findings"]:
                assert finding["severity"] in ("high", "critical")

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestScanCleanPackage:
    """SG-8.6: Clean scan produces no findings."""

    @pytest.mark.anyio()
    async def test_sg_8_6_clean_scan_no_findings(
        self,
        audit_dir: Path,
        clean_package: Path,
    ) -> None:
        """A package with no risky patterns produces zero findings."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(clean_package)},
            )
            assert not result.isError, f"Scan failed: {_get_text(result)}"
            data = json.loads(_get_text(result))
            assert data["finding_count"] == 0
            assert data["findings"] == []
            assert data["max_severity"] is None
            assert data["files_scanned"] > 0

        await _with_server(check, audit_dir=audit_dir, preset="permissive")


class TestTrustQueryMcpTool:
    """SG-8.7: Trust query MCP tool returns registered servers."""

    @pytest.mark.anyio()
    async def test_sg_8_7_trust_query_lists_servers(
        self,
        audit_dir: Path,
        registry_path: Path,
        clean_package: Path,
    ) -> None:
        """Listing all servers returns registered entries."""
        # Register multiple servers with different trust levels
        registry = TrustRegistry(path=str(registry_path))
        registry.add("server-a", TrustLevel.TRUSTED, notes="alpha")
        registry.add("server-b", TrustLevel.RESTRICTED, notes="beta")
        registry.add("server-c", TrustLevel.UNTRUSTED, notes="gamma")

        async def check(session: ClientSession) -> None:
            # Query all servers
            result = await session.call_tool(
                "agentguard_trust_query",
                {},
            )
            assert not result.isError, f"Query failed: {_get_text(result)}"
            data = json.loads(_get_text(result))
            assert data["count"] == 3
            names = {s["server_name"] for s in data["servers"]}
            assert names == {"server-a", "server-b", "server-c"}

            # Query by trust level
            result_trusted = await session.call_tool(
                "agentguard_trust_query",
                {"trust_level": "trusted"},
            )
            trusted_data = json.loads(_get_text(result_trusted))
            assert trusted_data["count"] == 1
            assert trusted_data["servers"][0]["server_name"] == "server-a"

            # Query non-existent server
            result_missing = await session.call_tool(
                "agentguard_trust_query",
                {"server_name": "nonexistent"},
            )
            missing_data = json.loads(_get_text(result_missing))
            assert "error" in missing_data

        await _with_server(
            check,
            audit_dir=audit_dir,
            preset="permissive",
            trust_registry=str(registry_path),
        )


class TestScanMcpTool:
    """SG-8.8: Scan MCP tool returns findings via MCP protocol."""

    @pytest.mark.anyio()
    async def test_sg_8_8_scan_tool_returns_findings(
        self,
        audit_dir: Path,
        risky_package: Path,
    ) -> None:
        """The scan tool returns structured finding data via MCP."""

        async def check(session: ClientSession) -> None:
            result = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(risky_package)},
            )
            assert not result.isError, f"Scan failed: {_get_text(result)}"
            data = json.loads(_get_text(result))

            # Verify response structure
            assert "package_path" in data
            assert "files_scanned" in data
            assert "finding_count" in data
            assert "max_severity" in data
            assert "findings" in data
            assert isinstance(data["findings"], list)

            # Verify finding structure
            required_fields = {
                "rule_id",
                "category",
                "severity",
                "message",
                "file_path",
                "line_number",
                "matched_text",
            }
            for finding in data["findings"]:
                missing = required_fields - set(finding.keys())
                assert not missing, f"Finding missing fields: {missing}"

            # Verify invalid severity returns error
            result_bad = await session.call_tool(
                "agentguard_scan_package",
                {"path": str(risky_package), "min_severity": "invalid"},
            )
            bad_data = json.loads(_get_text(result_bad))
            assert "error" in bad_data

        await _with_server(check, audit_dir=audit_dir, preset="permissive")

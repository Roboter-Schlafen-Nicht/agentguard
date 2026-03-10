"""Tests for the 'agentguard trust' CLI subcommand group."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from agentguard.cli import main

if TYPE_CHECKING:
    from pathlib import Path


def _run_cli(*args: str) -> tuple[int, str, str]:
    """Run the CLI and capture output."""
    import io
    import sys

    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        exit_code = main(list(args))
    except SystemExit as e:
        exit_code = e.code if isinstance(e.code, int) else 1
    finally:
        stdout = sys.stdout.getvalue()
        stderr = sys.stderr.getvalue()
        sys.stdout, sys.stderr = old_stdout, old_stderr
    return exit_code, stdout, stderr


class TestTrustHelp:
    def test_trust_in_top_level_help(self) -> None:
        exit_code, stdout, _ = _run_cli("--help")
        assert exit_code == 0
        assert "trust" in stdout

    def test_trust_help_shows_subcommands(self) -> None:
        exit_code, stdout, _ = _run_cli("trust", "--help")
        assert exit_code == 0
        assert "add" in stdout
        assert "remove" in stdout
        assert "list" in stdout
        assert "show" in stdout
        assert "verify" in stdout
        assert "update-hash" in stdout

    def test_trust_no_subcommand_shows_help(self) -> None:
        exit_code, stdout, _ = _run_cli("trust")
        assert exit_code == 1
        assert "add" in stdout or "list" in stdout


class TestTrustAdd:
    def test_add_server(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, stdout, _ = _run_cli(
            "trust", "add", "my-server", "--level", "trusted", "--registry", reg
        )
        assert exit_code == 0
        assert "my-server" in stdout
        assert "Added" in stdout

    def test_add_server_with_hash(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("code", encoding="utf-8")
        exit_code, stdout, _ = _run_cli(
            "trust",
            "add",
            "s",
            "--level",
            "restricted",
            "--package-path",
            str(pkg),
            "--registry",
            reg,
        )
        assert exit_code == 0
        assert "Hash:" in stdout

    def test_add_server_update(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "s", "--level", "trusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli(
            "trust", "add", "s", "--level", "restricted", "--registry", reg
        )
        assert exit_code == 0
        assert "Updated" in stdout

    def test_add_missing_level_fails(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, _stdout, _stderr = _run_cli("trust", "add", "s", "--registry", reg)
        assert exit_code != 0

    def test_add_invalid_level_fails(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, _stdout, _stderr = _run_cli(
            "trust", "add", "s", "--level", "bogus", "--registry", reg
        )
        assert exit_code != 0

    def test_add_nonexistent_package_path_fails(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, _stdout, _stderr = _run_cli(
            "trust",
            "add",
            "s",
            "--level",
            "trusted",
            "--package-path",
            "/nonexistent/pkg",
            "--registry",
            reg,
        )
        assert exit_code == 1


class TestTrustRemove:
    def test_remove_existing(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "s", "--level", "trusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli("trust", "remove", "s", "--registry", reg)
        assert exit_code == 0
        assert "Removed" in stdout

    def test_remove_nonexistent(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, _, stderr = _run_cli("trust", "remove", "nope", "--registry", reg)
        assert exit_code == 1
        assert "not found" in stderr.lower()


class TestTrustList:
    def test_list_empty(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, stdout, _ = _run_cli("trust", "list", "--registry", reg)
        assert exit_code == 0
        assert "No servers" in stdout

    def test_list_with_entries(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "a", "--level", "trusted", "--registry", reg)
        _run_cli("trust", "add", "b", "--level", "untrusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli("trust", "list", "--registry", reg)
        assert exit_code == 0
        assert "a" in stdout
        assert "b" in stdout

    def test_list_filtered_by_level(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "a", "--level", "trusted", "--registry", reg)
        _run_cli("trust", "add", "b", "--level", "untrusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli(
            "trust", "list", "--level", "trusted", "--registry", reg
        )
        assert exit_code == 0
        assert "a" in stdout
        assert "b" not in stdout

    def test_list_json_format(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "s", "--level", "trusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli(
            "trust", "list", "--format", "json", "--registry", reg
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["server_name"] == "s"


class TestTrustShow:
    def test_show_existing(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "my-srv", "--level", "restricted", "--registry", reg)
        exit_code, stdout, _ = _run_cli("trust", "show", "my-srv", "--registry", reg)
        assert exit_code == 0
        assert "my-srv" in stdout
        assert "restricted" in stdout

    def test_show_nonexistent(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        exit_code, _, stderr = _run_cli("trust", "show", "nope", "--registry", reg)
        assert exit_code == 1
        assert "not found" in stderr.lower()

    def test_show_json_format(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        _run_cli("trust", "add", "s", "--level", "trusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli(
            "trust", "show", "s", "--format", "json", "--registry", reg
        )
        assert exit_code == 0
        data = json.loads(stdout)
        assert data["server_name"] == "s"
        assert data["trust_level"] == "trusted"


class TestTrustVerify:
    def test_verify_pass(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("content", encoding="utf-8")
        _run_cli(
            "trust",
            "add",
            "s",
            "--level",
            "trusted",
            "--package-path",
            str(pkg),
            "--registry",
            reg,
        )
        exit_code, stdout, _ = _run_cli(
            "trust", "verify", "s", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code == 0
        assert "PASS" in stdout

    def test_verify_fail_modified(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("original", encoding="utf-8")
        _run_cli(
            "trust",
            "add",
            "s",
            "--level",
            "trusted",
            "--package-path",
            str(pkg),
            "--registry",
            reg,
        )
        pkg.write_text("tampered", encoding="utf-8")
        exit_code, stdout, _ = _run_cli(
            "trust", "verify", "s", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code == 1
        assert "FAIL" in stdout

    def test_verify_no_hash(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("x", encoding="utf-8")
        _run_cli("trust", "add", "s", "--level", "trusted", "--registry", reg)
        exit_code, stdout, _ = _run_cli(
            "trust", "verify", "s", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code == 1
        assert "FAIL" in stdout

    def test_verify_nonexistent_server(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("x", encoding="utf-8")
        exit_code, _, stderr = _run_cli(
            "trust", "verify", "nope", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code == 1
        assert "not found" in stderr.lower()


class TestTrustUpdateHash:
    def test_update_hash(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("v1", encoding="utf-8")
        _run_cli(
            "trust",
            "add",
            "s",
            "--level",
            "trusted",
            "--package-path",
            str(pkg),
            "--registry",
            reg,
        )
        pkg.write_text("v2", encoding="utf-8")
        exit_code, stdout, _ = _run_cli(
            "trust", "update-hash", "s", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code == 0
        assert "Updated hash" in stdout
        # Verify passes after update
        exit_code2, stdout2, _ = _run_cli(
            "trust", "verify", "s", "--package-path", str(pkg), "--registry", reg
        )
        assert exit_code2 == 0
        assert "PASS" in stdout2

    def test_update_hash_nonexistent(self, tmp_path: Path) -> None:
        reg = str(tmp_path / "reg.yaml")
        pkg = tmp_path / "server.py"
        pkg.write_text("x", encoding="utf-8")
        exit_code, _, stderr = _run_cli(
            "trust",
            "update-hash",
            "nope",
            "--package-path",
            str(pkg),
            "--registry",
            reg,
        )
        assert exit_code == 1
        assert "not found" in stderr.lower()

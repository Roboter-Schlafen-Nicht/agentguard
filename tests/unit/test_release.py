"""Tests for release version validation utilities."""

from __future__ import annotations

import pytest

from agentguard.release import (
    parse_version_tag,
    read_init_version,
    read_pyproject_version,
    validate_version_consistency,
)


class TestParseVersionTag:
    """Tests for parse_version_tag."""

    def test_valid_tag_with_v_prefix(self) -> None:
        assert parse_version_tag("v0.1.0") == "0.1.0"

    def test_valid_tag_with_v_prefix_major(self) -> None:
        assert parse_version_tag("v1.0.0") == "1.0.0"

    def test_valid_tag_with_v_prefix_prerelease(self) -> None:
        assert parse_version_tag("v0.2.0rc1") == "0.2.0rc1"

    def test_valid_tag_without_prefix(self) -> None:
        assert parse_version_tag("0.1.0") == "0.1.0"

    def test_invalid_tag_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid version tag"):
            parse_version_tag("release-1.0")

    def test_empty_tag_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid version tag"):
            parse_version_tag("")

    def test_tag_with_only_v_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid version tag"):
            parse_version_tag("v")

    def test_tag_with_dev_suffix(self) -> None:
        assert parse_version_tag("v1.2.3.dev4") == "1.2.3.dev4"

    def test_tag_with_post_suffix(self) -> None:
        assert parse_version_tag("v1.0.0.post1") == "1.0.0.post1"


class TestReadPyprojectVersion:
    """Tests for read_pyproject_version."""

    def test_reads_version_from_pyproject(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\nversion = "1.2.3"\n')
        assert read_pyproject_version(str(pyproject)) == "1.2.3"

    def test_missing_file_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        with pytest.raises(FileNotFoundError):
            read_pyproject_version(str(tmp_path / "nonexistent.toml"))  # type: ignore[operator]

    def test_missing_version_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\n')
        with pytest.raises(ValueError, match=r"version.*not found"):
            read_pyproject_version(str(pyproject))


class TestReadInitVersion:
    """Tests for read_init_version."""

    def test_reads_version_from_init(self, tmp_path: pytest.TempPathFactory) -> None:
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text('__version__ = "2.0.0"\n')
        assert read_init_version(str(init_file)) == "2.0.0"

    def test_reads_single_quoted_version(
        self, tmp_path: pytest.TempPathFactory
    ) -> None:
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text("__version__ = '1.0.0'\n")
        assert read_init_version(str(init_file)) == "1.0.0"

    def test_missing_file_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        with pytest.raises(FileNotFoundError):
            read_init_version(str(tmp_path / "nonexistent.py"))  # type: ignore[operator]

    def test_missing_version_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text("# no version here\n")
        with pytest.raises(ValueError, match=r"__version__.*not found"):
            read_init_version(str(init_file))


class TestValidateVersionConsistency:
    """Tests for validate_version_consistency."""

    def test_all_match_returns_none(self, tmp_path: pytest.TempPathFactory) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\nversion = "0.1.0"\n')
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text('__version__ = "0.1.0"\n')

        errors = validate_version_consistency(
            tag="v0.1.0",
            pyproject_path=str(pyproject),
            init_path=str(init_file),
        )
        assert errors == []

    def test_tag_mismatch_pyproject(self, tmp_path: pytest.TempPathFactory) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\nversion = "0.2.0"\n')
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text('__version__ = "0.1.0"\n')

        errors = validate_version_consistency(
            tag="v0.1.0",
            pyproject_path=str(pyproject),
            init_path=str(init_file),
        )
        assert len(errors) == 1
        assert "pyproject.toml" in errors[0]

    def test_tag_mismatch_init(self, tmp_path: pytest.TempPathFactory) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\nversion = "0.1.0"\n')
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text('__version__ = "0.2.0"\n')

        errors = validate_version_consistency(
            tag="v0.1.0",
            pyproject_path=str(pyproject),
            init_path=str(init_file),
        )
        assert len(errors) == 1
        assert "__init__.py" in errors[0]

    def test_all_mismatch(self, tmp_path: pytest.TempPathFactory) -> None:
        pyproject = tmp_path / "pyproject.toml"  # type: ignore[operator]
        pyproject.write_text('[project]\nname = "test"\nversion = "0.3.0"\n')
        init_file = tmp_path / "__init__.py"  # type: ignore[operator]
        init_file.write_text('__version__ = "0.4.0"\n')

        errors = validate_version_consistency(
            tag="v0.1.0",
            pyproject_path=str(pyproject),
            init_path=str(init_file),
        )
        assert len(errors) == 2

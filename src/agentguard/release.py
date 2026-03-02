"""Release version validation utilities.

Provides functions to validate that version tags, pyproject.toml, and
__init__.py all agree on the package version. Used by the release
workflow to catch version mismatches before publishing.
"""

from __future__ import annotations

import re
import sys

# PEP 440 compatible version pattern (simplified)
_VERSION_RE = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)"
    r"(?:\.?(dev|post|rc|a|b)\d+)?$"
)

_TAG_RE = re.compile(r"^v?(.+)$")


def parse_version_tag(tag: str) -> str:
    """Extract a version string from a git tag.

    Accepts tags like ``v0.1.0`` or ``0.1.0``. Strips the leading
    ``v`` prefix if present.

    Args:
        tag: The git tag string.

    Returns:
        The version string without the ``v`` prefix.

    Raises:
        ValueError: If the tag does not contain a valid version.
    """
    match = _TAG_RE.match(tag)
    if not match:
        raise ValueError(f"Invalid version tag: {tag!r}")

    version = match.group(1)
    if not _VERSION_RE.match(version):
        raise ValueError(f"Invalid version tag: {tag!r}")

    return version


def read_pyproject_version(path: str = "pyproject.toml") -> str:
    """Read the version from a pyproject.toml file.

    Uses a simple regex parser to avoid requiring a TOML library
    (keeping the zero-dependency constraint for Python 3.10).

    Args:
        path: Path to the pyproject.toml file.

    Returns:
        The version string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If no version field is found.
    """
    with open(path, encoding="utf-8") as f:
        content = f.read()

    # Find the [project] section and match version = "x.y.z" or 'x.y.z'
    project_match = re.search(r"^\[project\]\s*$", content, re.MULTILINE)
    if project_match:
        # Search only within [project] section (up to next [section])
        section_start = project_match.end()
        next_section = re.search(r"^\[", content[section_start:], re.MULTILINE)
        section = (
            content[section_start : section_start + next_section.start()]
            if next_section
            else content[section_start:]
        )
    else:
        section = content

    match = re.search(r"^version\s*=\s*[\"']([^\"']+)[\"']", section, re.MULTILINE)
    if not match:
        raise ValueError(f"version field not found in {path}")

    return match.group(1)


def read_init_version(path: str = "src/agentguard/__init__.py") -> str:
    """Read __version__ from a Python init file.

    Args:
        path: Path to the __init__.py file.

    Returns:
        The version string.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If no __version__ assignment is found.
    """
    with open(path, encoding="utf-8") as f:
        content = f.read()

    match = re.search(r"^__version__\s*=\s*[\"']([^\"']+)[\"']", content, re.MULTILINE)
    if not match:
        raise ValueError(f"__version__ assignment not found in {path}")

    return match.group(1)


def validate_version_consistency(
    tag: str,
    pyproject_path: str = "pyproject.toml",
    init_path: str = "src/agentguard/__init__.py",
) -> list[str]:
    """Validate that a git tag matches the versions in source files.

    Args:
        tag: The git tag (e.g. ``v0.1.0``).
        pyproject_path: Path to pyproject.toml.
        init_path: Path to __init__.py.

    Returns:
        A list of error messages. Empty if all versions match.
    """
    errors: list[str] = []
    tag_version = parse_version_tag(tag)

    pyproject_version = read_pyproject_version(pyproject_path)
    if pyproject_version != tag_version:
        errors.append(
            f"pyproject.toml version {pyproject_version!r} "
            f"does not match tag version {tag_version!r}"
        )

    init_version = read_init_version(init_path)
    if init_version != tag_version:
        errors.append(
            f"__init__.py version {init_version!r} "
            f"does not match tag version {tag_version!r}"
        )

    return errors


def main() -> None:
    """CLI entry point for version validation.

    Usage: python -m agentguard.release <tag>
    """
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <tag>", file=sys.stderr)
        sys.exit(2)

    tag = sys.argv[1]

    try:
        errors = validate_version_consistency(tag)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if errors:
        for error in errors:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)

    version = parse_version_tag(tag)
    print(f"Version {version} is consistent across all sources.")


if __name__ == "__main__":
    main()

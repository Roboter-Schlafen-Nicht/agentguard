"""Scanning engine for MCP server packages.

Walks a package directory, applies detection rules line-by-line to
every Python file, and collects findings into a :class:`ScanResult`.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

from agentguard.scanner.models import Finding, ScanResult
from agentguard.scanner.rules import Rule, builtin_rules

if TYPE_CHECKING:
    from collections.abc import Sequence

# File extensions the scanner examines by default.
_DEFAULT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyw",
        ".sh",
        ".bash",
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
    }
)

# Directories skipped during traversal.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "*.egg-info",
    }
)


class Scanner:
    """Line-by-line regex scanner for MCP server packages.

    Parameters:
        rules: Detection rules to apply.  Defaults to :func:`builtin_rules`.
        extensions: File extensions to scan.  Defaults to Python / shell / JS.
        max_file_size: Skip files larger than this (bytes).  Default 1 MiB.
    """

    def __init__(
        self,
        rules: Sequence[Rule] | None = None,
        extensions: frozenset[str] | None = None,
        max_file_size: int = 1_048_576,
    ) -> None:
        self._rules: Sequence[Rule] = rules if rules is not None else builtin_rules()
        self._extensions: frozenset[str] = (
            extensions if extensions is not None else _DEFAULT_EXTENSIONS
        )
        self._max_file_size = max_file_size

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, path: str | Path) -> ScanResult:
        """Scan a package directory (or single file) and return results.

        Args:
            path: Path to a directory or single file to scan.

        Returns:
            A :class:`ScanResult` with all findings.

        Raises:
            FileNotFoundError: If *path* does not exist.
        """
        target = Path(path).resolve()
        if not target.exists():
            raise FileNotFoundError(f"Scan target not found: {target}")

        result = ScanResult(package_path=str(target))

        if target.is_file():
            findings = self._scan_file(target, target.parent)
            if findings is not None:
                result.files_scanned = 1
                result.findings.extend(findings)
        else:
            self._scan_directory(target, result)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_directory(self, root: Path, result: ScanResult) -> None:
        """Recursively scan *root*, populating *result*."""
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune skipped directories in-place.
            dirnames[:] = [
                d
                for d in dirnames
                if d not in _SKIP_DIRS and not d.endswith(".egg-info")
            ]

            for filename in filenames:
                filepath = Path(dirpath) / filename
                findings = self._scan_file(filepath, root)
                if findings is not None:
                    result.files_scanned += 1
                    result.findings.extend(findings)

    def _scan_file(self, filepath: Path, root: Path) -> list[Finding] | None:
        """Scan a single file.  Returns ``None`` if the file was skipped."""
        if filepath.suffix not in self._extensions:
            return None

        try:
            size = filepath.stat().st_size
        except OSError:
            return None

        if size > self._max_file_size:
            return None

        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        try:
            rel = str(filepath.relative_to(root))
        except ValueError:
            rel = str(filepath)

        findings: list[Finding] = []
        for line_no, line in enumerate(text.splitlines(), start=1):
            for rule in self._rules:
                match = rule.pattern.search(line)
                if match:
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            category=rule.category,
                            severity=rule.severity,
                            message=rule.message,
                            file_path=rel,
                            line_number=line_no,
                            matched_text=match.group(0),
                        )
                    )
        return findings

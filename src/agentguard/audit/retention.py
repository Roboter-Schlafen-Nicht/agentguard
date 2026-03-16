"""Audit log retention policy.

Provides configurable retention for rotated JSONL audit files.
The :func:`enforce_retention` function deletes old rotated files
based on file count, age, or cumulative size thresholds.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class RetentionConfig:
    """Configuration for audit log retention.

    All criteria are applied independently — a file is deleted if
    **any** criterion marks it for removal.  With no thresholds set,
    retention enforcement is a no-op.

    Args:
        max_files: Maximum number of ``.jsonl`` files to keep.
            Oldest files (by mtime) are deleted first.
            Must be positive if set.
        max_age_seconds: Delete files whose mtime is older than
            this many seconds.  Must be positive if set.
        max_total_bytes: Delete oldest files until cumulative
            size of remaining files is within this limit.
            Must be positive if set.
    """

    max_files: int | None = None
    max_age_seconds: float | None = None
    max_total_bytes: int | None = None

    def __post_init__(self) -> None:
        if self.max_files is not None and self.max_files <= 0:
            msg = "max_files must be positive"
            raise ValueError(msg)
        if self.max_age_seconds is not None and self.max_age_seconds <= 0:
            msg = "max_age_seconds must be positive"
            raise ValueError(msg)
        if self.max_total_bytes is not None and self.max_total_bytes <= 0:
            msg = "max_total_bytes must be positive"
            raise ValueError(msg)


def enforce_retention(
    audit_dir: str | Path,
    config: RetentionConfig,
    *,
    active_file: str | Path | None = None,
) -> list[Path]:
    """Delete old audit files according to *config*.

    Scans *audit_dir* for ``.jsonl`` files, sorts by mtime
    (oldest first), and deletes files that exceed the configured
    thresholds.  The *active_file* (if provided) is never deleted.

    Args:
        audit_dir: Directory containing audit ``.jsonl`` files.
        config: Retention thresholds.
        active_file: Path to the current active log file that
            must not be deleted.

    Returns:
        List of :class:`~pathlib.Path` objects that were deleted.

    Raises:
        FileNotFoundError: If *audit_dir* does not exist.
    """
    dir_path = Path(audit_dir)
    if not dir_path.is_dir():
        msg = f"Audit directory not found: {dir_path}"
        raise FileNotFoundError(msg)

    active = Path(active_file).resolve() if active_file else None

    # No thresholds → nothing to do.
    if (
        config.max_files is None
        and config.max_age_seconds is None
        and config.max_total_bytes is None
    ):
        return []

    # Gather .jsonl files sorted by mtime (oldest first).
    files = sorted(
        dir_path.glob("*.jsonl"),
        key=lambda p: p.stat().st_mtime,
    )

    # Exclude the active file from candidates.
    candidates = [f for f in files if active is None or f.resolve() != active]

    to_delete: set[Path] = set()
    now = time.time()

    # ── max_age_seconds ──────────────────────────────────────
    if config.max_age_seconds is not None:
        for f in candidates:
            age = now - f.stat().st_mtime
            if age >= config.max_age_seconds:
                to_delete.add(f)

    # ── max_files ────────────────────────────────────────────
    if config.max_files is not None:
        # candidates is sorted oldest-first; keep the newest N.
        surviving = [f for f in candidates if f not in to_delete]
        all_candidates = candidates  # original order
        # Total eligible = candidates not yet marked for delete
        # We want at most max_files remaining (excluding active).
        # But we must also count the active file if present.
        # "max_files" is the total count of .jsonl files to keep
        # (excluding the active file).
        if len(surviving) > config.max_files:
            excess = len(surviving) - config.max_files
            # Delete the oldest 'excess' survivors
            survivors_oldest_first = [f for f in all_candidates if f in set(surviving)]
            for f in survivors_oldest_first[:excess]:
                to_delete.add(f)

    # ── max_total_bytes ──────────────────────────────────────
    if config.max_total_bytes is not None:
        # Compute total size of files that will survive.
        surviving = [f for f in files if f not in to_delete]
        total = sum(f.stat().st_size for f in surviving)
        if total > config.max_total_bytes:
            # Remove oldest candidates first until within budget.
            for f in candidates:
                if f in to_delete:
                    continue
                if total <= config.max_total_bytes:
                    break
                total -= f.stat().st_size
                to_delete.add(f)

    # Perform deletions.
    deleted: list[Path] = []
    for f in sorted(to_delete):
        f.unlink()
        deleted.append(f)

    return deleted

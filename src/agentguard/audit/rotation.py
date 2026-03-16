"""Audit log rotation configuration.

Provides size-based and time-based rotation for JSONL audit files.
The :class:`RotationConfig` is passed to :meth:`AuditLog.append` to
control when the active log file is rotated to an archive file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RotationConfig:
    """Configuration for audit log file rotation.

    Rotation triggers when **either** threshold is exceeded.
    With no thresholds set, rotation is disabled (the default).

    Args:
        max_bytes: Rotate when file size reaches this many bytes.
            Must be positive if set.
        max_age_seconds: Rotate when file age exceeds this many
            seconds. Must be positive if set. Accepts float for
            sub-second precision in tests.
    """

    max_bytes: int | None = None
    max_age_seconds: float | None = None

    def __post_init__(self) -> None:
        if self.max_bytes is not None and self.max_bytes <= 0:
            msg = "max_bytes must be positive"
            raise ValueError(msg)
        if self.max_age_seconds is not None and self.max_age_seconds <= 0:
            msg = "max_age_seconds must be positive"
            raise ValueError(msg)

    def should_rotate(self, file_bytes: int, file_age: float) -> bool:
        """Return True if the file should be rotated.

        Args:
            file_bytes: Current file size in bytes.
            file_age: Seconds since last file modification.

        Returns:
            True if either threshold is exceeded.
        """
        if self.max_bytes is not None and file_bytes >= self.max_bytes:
            return True
        return self.max_age_seconds is not None and file_age >= self.max_age_seconds

"""Cross-session audit report generation.

Aggregates statistics across multiple audit log files in a
directory, producing a summary report with action counts,
result breakdowns, actor lists, time ranges, and per-session
hash-chain integrity verification.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agentguard.audit.log import AuditLog

if TYPE_CHECKING:
    from datetime import datetime
    from pathlib import Path


@dataclass
class CrossSessionReport:
    """Aggregated statistics across multiple audit sessions.

    Attributes:
        total_sessions: Number of session files loaded.
        total_entries: Total audit entries across all sessions.
        actions_by_type: Count of entries per action type.
        results_summary: Count of entries per result value.
        actors: Deduplicated sorted list of actor identifiers.
        time_range: Tuple of (earliest, latest) entry timestamps,
            or None if no entries exist.
        sessions_verified: Number of sessions with valid hash chains.
        sessions_failed: Number of sessions with broken hash chains.
        failed_sessions: Session IDs of sessions that failed verification.
    """

    total_sessions: int
    total_entries: int
    actions_by_type: dict[str, int]
    results_summary: dict[str, int]
    actors: list[str]
    time_range: tuple[datetime, datetime] | None
    sessions_verified: int
    sessions_failed: int
    failed_sessions: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report to a dictionary.

        Returns:
            Dictionary representation suitable for JSON output.
        """
        time_range_dict: dict[str, str] | None = None
        if self.time_range is not None:
            time_range_dict = {
                "start": self.time_range[0].isoformat(),
                "end": self.time_range[1].isoformat(),
            }

        return {
            "total_sessions": self.total_sessions,
            "total_entries": self.total_entries,
            "actions_by_type": dict(self.actions_by_type),
            "results_summary": dict(self.results_summary),
            "actors": list(self.actors),
            "time_range": time_range_dict,
            "integrity": {
                "verified": self.sessions_verified,
                "failed": self.sessions_failed,
                "failed_sessions": list(self.failed_sessions),
            },
        }


def generate_cross_session_report(
    audit_dir: str | Path,
    *,
    after: datetime | None = None,
    before: datetime | None = None,
) -> CrossSessionReport:
    """Generate an aggregated report across all sessions in a directory.

    Loads every ``.jsonl`` file in *audit_dir*, verifies each session's
    hash chain independently, and aggregates statistics.

    Args:
        audit_dir: Directory containing ``.jsonl`` audit files.
        after: Only include entries after this timestamp.
        before: Only include entries before this timestamp.

    Returns:
        A :class:`CrossSessionReport` with aggregated data.

    Raises:
        FileNotFoundError: If *audit_dir* does not exist.
    """
    logs = AuditLog.load_directory(audit_dir)

    action_counts: Counter[str] = Counter()
    result_counts: Counter[str] = Counter()
    actor_set: set[str] = set()
    all_timestamps: list[datetime] = []
    verified = 0
    failed = 0
    failed_sessions: list[str] = []
    total_entries = 0

    for log in logs:
        if log.verify():
            verified += 1
        else:
            failed += 1
            failed_sessions.append(log.session_id)

        entries = log.entries
        # Apply time filters
        if after is not None:
            entries = [e for e in entries if e.timestamp > after]
        if before is not None:
            entries = [e for e in entries if e.timestamp < before]

        total_entries += len(entries)
        for entry in entries:
            action_counts[entry.action] += 1
            result_counts[entry.result] += 1
            actor_set.add(entry.actor)
            all_timestamps.append(entry.timestamp)

    time_range: tuple[datetime, datetime] | None = None
    if all_timestamps:
        time_range = (min(all_timestamps), max(all_timestamps))

    return CrossSessionReport(
        total_sessions=len(logs),
        total_entries=total_entries,
        actions_by_type=dict(action_counts),
        results_summary=dict(result_counts),
        actors=sorted(actor_set),
        time_range=time_range,
        sessions_verified=verified,
        sessions_failed=failed,
        failed_sessions=failed_sessions,
    )

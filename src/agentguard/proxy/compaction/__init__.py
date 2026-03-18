"""Context compaction for LLM API proxy.

Reduces token usage by truncating old tool outputs and summarizing
stale conversation segments before forwarding to the upstream LLM.
"""

from agentguard.proxy.compaction.config import CompactionConfig
from agentguard.proxy.compaction.engine import CompactionEngine, CompactionResult

__all__ = ["CompactionConfig", "CompactionEngine", "CompactionResult"]

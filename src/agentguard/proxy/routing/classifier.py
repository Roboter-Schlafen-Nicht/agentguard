"""HTTP client for the difficulty classification endpoint.

Calls the XPU inference server's ``/api/classify`` endpoint to
classify request content as Simple (1), Medium (2), or Complex (3).
Fails open: returns 0 on any error so the router can fall back to
token/message/pattern-based routing.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Maps the label strings returned by the classifier model
# (Shaheer001/Query-Complexity-Classifier) to integer difficulty
# levels used by the routing tier constraints.
_LABEL_TO_DIFFICULTY: dict[str, int] = {
    "Simple": 1,
    "Medium": 2,
    "Complex": 3,
}


class DifficultyClassifier:
    """Async HTTP client for difficulty classification.

    Args:
        url: Base URL of the XPU inference server
            (e.g. ``http://localhost:11435``).
        timeout: Request timeout in seconds.
    """

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        self._url = url.rstrip("/")
        self._timeout = timeout

    async def classify(self, content: str) -> int:
        """Classify content difficulty.

        Args:
            content: Text content to classify.  Truncated to 2000
                characters before sending.

        Returns:
            Difficulty level: 1 (Simple), 2 (Medium), 3 (Complex),
            or 0 on any failure (fail-open).
        """
        import httpx

        url = f"{self._url}/api/classify"
        truncated = content[:2000]

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, json={"text": truncated})
                resp.raise_for_status()
                data = resp.json()
                label = data.get("label", "")
                difficulty = _LABEL_TO_DIFFICULTY.get(label, 0)
                if difficulty:
                    logger.debug(
                        "classify_success label=%s difficulty=%d url=%s",
                        label,
                        difficulty,
                        self._url,
                    )
                else:
                    logger.warning(
                        "classify_unknown_label label=%s url=%s",
                        label,
                        self._url,
                    )
                return difficulty
        except Exception as exc:
            logger.warning(
                "classify_failed error_type=%s error=%s url=%s",
                type(exc).__name__,
                str(exc),
                self._url,
            )
            return 0

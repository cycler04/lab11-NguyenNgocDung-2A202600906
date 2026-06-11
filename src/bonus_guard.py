"""Bonus safety layer for the defense-in-depth pipeline.

This module adds an extra check for suspicious or malformed prompts to
complement the main input and output guardrails.
"""

import re


class BonusGuard:
    """Reject empty, emoji-only, or overly short inputs as low-quality abuse."""

    def check(self, text: str) -> dict:
        cleaned = text.strip()
        emoji_only = bool(re.fullmatch(r"[\W\d_\s]+", cleaned)) and not any(ch.isalpha() for ch in cleaned)
        if not cleaned or len(cleaned) < 2 or emoji_only:
            return {"blocked": True, "reason": "empty_or_emoji_only"}
        return {"blocked": False, "reason": None}

"""Canonicalisation applied before any alias matching."""
from __future__ import annotations

import unicodedata

# Zero-width / formatting characters commonly used to split keywords.
_INVISIBLE = dict.fromkeys(
    map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"), None)


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).casefold()
    return " ".join(t.replace("_", "-").split())

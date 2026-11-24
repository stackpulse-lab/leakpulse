"""Shannon entropy helpers used to spot unknown, high-randomness secrets."""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

from .rules import is_placeholder

QUOTED_CANDIDATE = re.compile(r"""["']([A-Za-z0-9+/=_\-]{24,})["']""")
BARE_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_\-])([A-Za-z0-9+/=_\-]{40,})(?![A-Za-z0-9+/=_\-])")
URL_LIKE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://\S+")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def shannon_entropy(value: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_random(value: str, threshold: float = 3.6, min_length: int = 24) -> bool:
    """Heuristic: is this string likely to be a generated secret?"""
    if len(value) < min_length:
        return False
    if is_placeholder(value):
        return False
    if _UUID.match(value):
        return False
    if not any(ch.isdigit() for ch in value):
        return False
    if not any(ch.isalpha() for ch in value):
        return False
    # Require some character-class variety; long lowercase identifiers are code.
    has_upper = any(ch.isupper() for ch in value)
    has_lower = any(ch.islower() for ch in value)
    has_symbol = any(ch in "+/=_-" for ch in value)
    if not (has_upper or has_symbol):
        return False
    if not has_lower:
        return False
    return shannon_entropy(value) >= threshold


def candidates(line: str) -> List[Tuple[int, int, str]]:
    """Yield (start, end, value) for strings worth an entropy check."""
    urls = [match.span() for match in URL_LIKE.finditer(line)]
    found: List[Tuple[int, int, str]] = []
    for regex in (QUOTED_CANDIDATE, BARE_CANDIDATE):
        for match in regex.finditer(line):
            start, end = match.start(1), match.end(1)
            if any(start < url_end and end > url_start for url_start, url_end in urls):
                continue
            found.append((start, end, match.group(1)))
    # Longest first so overlapping quoted/bare matches are reported once.
    found.sort(key=lambda item: (item[1] - item[0]), reverse=True)
    deduped: List[Tuple[int, int, str]] = []
    for start, end, value in found:
        if any(start >= s and end <= e for s, e, _ in deduped):
            continue
        deduped.append((start, end, value))
    return deduped

"""
FlagDetector — Scans decoded output for CTF flag patterns.

Default patterns cover: FLAG{}, CTF{}, flag{}, picoCTF{}, HTB{}, THM{},
DUCTF{}, and a generic two-to-eight uppercase prefix format.

Custom patterns can be added at runtime or via the --flag-pattern CLI option.
"""

from __future__ import annotations
import os
import re
from dataclasses import dataclass
from typing import List, Optional

# Core flag patterns (from CORE_CONCEPTS.md)
_DEFAULT_PATTERNS: List[str] = [
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"DUCTF\{[^}]+\}",
    r"[a-zA-Z0-9_]{2,12}\{[A-Za-z0-9_\-!@#$%^&*]+\}",   # generic format
]


@dataclass
class FlagMatch:
    pattern: str
    value: str
    start: int
    end: int


class FlagDetector:
    def __init__(self, extra_patterns: Optional[List[str]] = None):
        patterns = list(_DEFAULT_PATTERNS)

        # Environment-variable override
        env_pat = os.environ.get("FLAG_PATTERN")
        if env_pat:
            patterns.append(env_pat)

        if extra_patterns:
            patterns.extend(extra_patterns)

        self._compiled = [(p, re.compile(p)) for p in patterns]

    def detect(self, data: bytes) -> List[FlagMatch]:
        """Return all flag matches found in the decoded output."""
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return []

        seen: set[str] = set()
        matches: List[FlagMatch] = []

        for raw_pattern, compiled in self._compiled:
            for m in compiled.finditer(text):
                val = m.group()
                if val not in seen:
                    seen.add(val)
                    matches.append(FlagMatch(
                        pattern=raw_pattern,
                        value=val,
                        start=m.start(),
                        end=m.end(),
                    ))

        return matches

    def has_flag(self, data: bytes) -> bool:
        return len(self.detect(data)) > 0

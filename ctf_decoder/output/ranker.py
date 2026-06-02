"""
ResultRanker — Plaintext scoring system.

Weighted scoring model as specified in CORE_CONCEPTS.md:
  printable_ascii_ratio  : 0.30
  english_letter_freq    : 0.25
  bigram_frequency       : 0.15
  word_match_ratio       : 0.20
  flag_pattern_match     : +0.50 (additive bonus)
"""

from __future__ import annotations
import re
from collections import Counter
from dataclasses import dataclass
from typing import List

# --- English language reference data ---

# Expected letter frequencies in English (A-Z order)
ENGLISH_LETTER_FREQ = {
    'e': 0.127, 't': 0.091, 'a': 0.082, 'o': 0.075, 'i': 0.070,
    'n': 0.067, 's': 0.063, 'h': 0.061, 'r': 0.060, 'd': 0.043,
    'l': 0.040, 'c': 0.028, 'u': 0.028, 'm': 0.024, 'w': 0.024,
    'f': 0.022, 'g': 0.020, 'y': 0.020, 'p': 0.019, 'b': 0.015,
    'v': 0.010, 'k': 0.008, 'j': 0.002, 'x': 0.002, 'q': 0.001,
    'z': 0.001,
}

# 25 most common English bigrams
COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
    'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
    'st', 'to', 'nt', 'ng', 'se',
}

# Compact English word list (~1000 common words)
ENGLISH_WORDS = {
    'the', 'be', 'to', 'of', 'and', 'in', 'that', 'have', 'it', 'for',
    'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at', 'this', 'but',
    'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she', 'or', 'an',
    'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what', 'so',
    'up', 'out', 'if', 'about', 'who', 'get', 'which', 'go', 'me', 'when',
    'make', 'can', 'like', 'time', 'no', 'just', 'him', 'know', 'take',
    'people', 'into', 'year', 'your', 'good', 'some', 'could', 'them',
    'see', 'other', 'than', 'then', 'now', 'look', 'only', 'come', 'its',
    'over', 'think', 'also', 'back', 'after', 'use', 'two', 'how', 'our',
    'work', 'first', 'well', 'way', 'even', 'new', 'want', 'because', 'any',
    'these', 'give', 'day', 'most', 'us', 'flag', 'hello', 'world', 'ctf',
    'password', 'secret', 'key', 'code', 'cipher', 'encode', 'decode',
}


def score_printable_ascii(data: bytes) -> float:
    """Fraction of bytes in printable ASCII range (0x20–0x7E)."""
    if not data:
        return 0.0
    return sum(0x20 <= b <= 0x7E for b in data) / len(data)


def score_english_letter_freq(data: bytes) -> float:
    """Pearson-like correlation with expected English letter frequencies."""
    try:
        text = data.decode('utf-8', errors='ignore').lower()
    except Exception:
        return 0.0

    letters = [c for c in text if c.isalpha()]
    if len(letters) < 5:
        return 0.0

    counts = Counter(letters)
    total = sum(counts.values())
    score = 0.0
    for letter, expected in ENGLISH_LETTER_FREQ.items():
        observed = counts.get(letter, 0) / total
        score += 1.0 - abs(observed - expected)

    return max(0.0, (score / len(ENGLISH_LETTER_FREQ) - 0.8) / 0.2)


def score_bigram_frequency(data: bytes) -> float:
    """Fraction of character bigrams that are common English bigrams."""
    try:
        text = data.decode('utf-8', errors='ignore').lower()
    except Exception:
        return 0.0

    letters = [c for c in text if c.isalpha()]
    if len(letters) < 4:
        return 0.0

    bigrams = [''.join(letters[i:i+2]) for i in range(len(letters) - 1)]
    if not bigrams:
        return 0.0

    matches = sum(1 for b in bigrams if b in COMMON_BIGRAMS)
    return matches / len(bigrams)


def score_word_match(data: bytes) -> float:
    """Fraction of space-separated tokens found in the English word list."""
    try:
        text = data.decode('utf-8', errors='ignore').lower()
    except Exception:
        return 0.0

    tokens = re.findall(r'[a-z]+', text)
    if not tokens:
        return 0.0

    matches = sum(1 for t in tokens if t in ENGLISH_WORDS)
    return matches / len(tokens)


@dataclass
class PlaintextScore:
    total: float
    printable_ascii: float
    english_freq: float
    bigram_freq: float
    word_match: float
    flag_bonus: float

    def is_likely_plaintext(self) -> bool:
        return self.total > 0.6

    def is_strong_hit(self) -> bool:
        return self.total > 0.85


class ResultRanker:
    """Scores decoded byte sequences for plaintext likelihood."""

    WEIGHTS = {
        'printable_ascii': 0.30,
        'english_freq':    0.25,
        'bigram_freq':     0.15,
        'word_match':      0.20,
    }

    def score(self, data: bytes, has_flag: bool | List[FlagMatch] = False) -> PlaintextScore:
        printable = score_printable_ascii(data)
        eng_freq  = score_english_letter_freq(data)
        bigram    = score_bigram_frequency(data)
        word      = score_word_match(data)

        weighted = (
            printable * self.WEIGHTS['printable_ascii'] +
            eng_freq  * self.WEIGHTS['english_freq'] +
            bigram    * self.WEIGHTS['bigram_freq'] +
            word      * self.WEIGHTS['word_match']
        )

        flag_bonus = 0.0
        if has_flag:
            if isinstance(has_flag, list):
                has_specific = False
                for m in has_flag:
                    val = getattr(m, "value", str(m))
                    val_upper = val.upper()
                    if any(val_upper.startswith(prefix) for prefix in ("FLAG{", "CTF{", "PICOCTF{", "HTB{", "THM{", "DUCTF{")):
                        has_specific = True
                        break
                flag_bonus = 0.50 if has_specific else 0.15
            else:
                flag_bonus = 0.50
        else:
            flag_bonus = 0.0

        total = min(1.0, weighted + flag_bonus)

        return PlaintextScore(
            total=round(total, 4),
            printable_ascii=round(printable, 4),
            english_freq=round(eng_freq, 4),
            bigram_freq=round(bigram, 4),
            word_match=round(word, 4),
            flag_bonus=flag_bonus,
        )

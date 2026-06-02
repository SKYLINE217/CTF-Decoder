"""
AlphaHex Decoder
================
Encodes bytes as hex, then substitutes uppercase hex digits A-F with
visually-similar alphabetic characters:

    A → h    B → i    C → j    D → k    E → l (or lookalike '1')    F → m

This is a classic CTF obfuscation trick — the result looks like a
random mix of numbers and lowercase letters, and the 'l'↔'1' swap
provides an extra layer of visual confusion.

Example:
    Z0mb1e{...}  →  hex encode  →  5A306D6231657B...
                 →  substitute  →  5h306k6231657i...
"""

from __future__ import annotations
import re
from ctf_decoder.decoders.base import BaseDecoder

# Substitution maps
_DECODE_MAP = str.maketrans("hijklmHIJKLM", "abcdefABCDEF")

# Pattern: only hex digits 0-9 + letters h i j k l m
_ALPHAHEX_RE = re.compile(r'^[0-9hijklm]+$', re.IGNORECASE)


def _alphahex_to_hex(data: str) -> str:
    """Convert an alphahex string back to a standard uppercase hex string."""
    return data.translate(_DECODE_MAP)


class AlphaHexDecoder(BaseDecoder):
    name        = "alphahex"
    aliases     = ["alpha-hex", "hexalpha", "visual-hex"]
    description = (
        "Hex encoding with A-F replaced by look-alike letters "
        "(A=h, B=i, C=j, D=k, E=l/1, F=m). Common CTF obfuscation."
    )

    def can_decode(self, data: bytes) -> float:
        try:
            s = data.decode("ascii").strip()
        except (UnicodeDecodeError, ValueError):
            return 0.0

        if not s or len(s) % 2 != 0:
            return 0.0

        if not _ALPHAHEX_RE.match(s):
            return 0.0

        # Must contain at least one substitution letter to distinguish from plain hex
        has_alpha = any(c in s.lower() for c in 'hijklm')
        if not has_alpha:
            return 0.0

        # Strong signal: looks like alphahex
        return 0.75

    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii").strip()
        except UnicodeDecodeError:
            raise ValueError("AlphaHex input must be ASCII")

        if len(s) % 2 != 0:
            raise ValueError(f"AlphaHex string has odd length ({len(s)}); cannot decode")

        if not _ALPHAHEX_RE.match(s):
            raise ValueError("Input contains characters outside the alphahex alphabet")

        hex_str = _alphahex_to_hex(s)
        try:
            return bytes.fromhex(hex_str)
        except ValueError as e:
            raise ValueError(f"AlphaHex → hex conversion produced invalid hex: {e}")

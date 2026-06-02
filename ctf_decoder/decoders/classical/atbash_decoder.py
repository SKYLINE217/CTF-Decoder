from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class AtbashDecoder(BaseDecoder):
    name = "atbash"
    aliases = ["mirror"]
    description = "Decodes Atbash cipher (A<->Z)."
    
    def can_decode(self, data: bytes) -> float:
        try:
            s = data.decode('ascii').strip()
            if not s: return 0.0
            alpha = sum(1 for c in s if c.isalpha())
            # Atbash only makes sense on alpha-heavy text
            if alpha / len(s) > 0.5:
                return 0.2  # Low-confidence (very ambiguous cipher)
            return 0.0
        except Exception:
            return 0.0

    def decode(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8")
            decoded = []
            for c in text:
                if 'A' <= c <= 'Z':
                    decoded.append(chr(ord('Z') - (ord(c) - ord('A'))))
                elif 'a' <= c <= 'z':
                    decoded.append(chr(ord('z') - (ord(c) - ord('a'))))
                else:
                    decoded.append(c)
            return "".join(decoded).encode("utf-8")
        except Exception as e:
            raise DecodeError(f"Atbash decoding failed: {e}")

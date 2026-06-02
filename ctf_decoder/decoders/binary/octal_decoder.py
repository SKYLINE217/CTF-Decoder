from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class OctalDecoder(BaseDecoder):
    name = "octal"
    aliases = ["oct", "base8"]
    description = "Decodes octal strings."
    
    def can_decode(self, data: bytes) -> float:
        try:
            s = data.decode("ascii").strip()
            if not s: return 0.0
            
            # Common formats: space separated "110 145 154" or continuous "110145154"
            import re
            s_clean = re.sub(r'[\s]+', '', s)
            if not s_clean: return 0.0
            
            # Check if all chars are octal digits 0-7
            valid_chars = sum(1 for c in s_clean if c in "01234567")
            if valid_chars / len(s_clean) > 0.95:
                return 0.8
            return 0.0
        except Exception:
            return 0.0
    
    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii", errors="replace")
            s = s.replace(" ", "").replace("\n", "").replace("\r", "")
            
            if not s:
                return b""
                
            # Octal bytes are typically represented as 3 digits (e.g. 101 for 'A')
            # If not a multiple of 3, maybe it's missing leading zeros. But usually it's padded.
            # We'll just take chunks of 3.
            if len(s) % 3 != 0:
                raise ValueError("Octal string length not a multiple of 3")
                
            chunks = [s[i:i+3] for i in range(0, len(s), 3)]
            return bytes(int(c, 8) for c in chunks)
        except Exception as e:
            raise DecodeError(f"Octal decoding failed: {e}")

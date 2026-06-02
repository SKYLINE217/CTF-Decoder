from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class BinaryDecoder(BaseDecoder):
    name = "binary"
    aliases = ["bin", "base2"]
    description = "Decodes binary strings (0s and 1s)."
    
    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii", errors="replace")
            s = s.replace(" ", "").replace("\n", "").replace("\r", "")
            
            if not s:
                return b""
                
            if len(s) % 8 != 0:
                if len(s) % 7 == 0:
                    chunks = [s[i:i+7] for i in range(0, len(s), 7)]
                else:
                    raise ValueError("Binary string length not a multiple of 8 (or 7)")
            else:
                chunks = [s[i:i+8] for i in range(0, len(s), 8)]
                
            return bytes(int(c, 2) for c in chunks)
        except Exception as e:
            raise DecodeError(f"Binary decoding failed: {e}")

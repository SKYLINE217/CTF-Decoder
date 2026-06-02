import binascii
import re
from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class HexDecoder(BaseDecoder):
    name = "hex"
    aliases = ["base16", "b16"]
    description = "Decodes hexadecimal strings, including \\xNN and 0xNN formats."
    
    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii", errors="replace")
            s = re.sub(r'(?:0x|\\x|%|:| )', '', s, flags=re.IGNORECASE).strip()
            
            if len(s) % 2 != 0:
                raise ValueError("Odd-length string")
                
            return binascii.unhexlify(s)
        except Exception as e:
            raise DecodeError(f"Hex decoding failed: {e}")

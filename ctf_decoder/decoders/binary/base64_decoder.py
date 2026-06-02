import base64
from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class Base64Decoder(BaseDecoder):
    name = "base64"
    aliases = ["b64", "base-64"]
    description = "Decodes standard, URL-safe, and MIME Base64 encodings."
    
    def decode(self, data: bytes) -> bytes:
        try:
            s = data.decode("ascii", errors="replace").translate(str.maketrans("", "", " \t\r\n"))
            padding_needed = len(s) % 4
            if padding_needed:
                s += "=" * (4 - padding_needed)
            return base64.urlsafe_b64decode(s.encode("ascii"))
        except Exception as e:
            raise DecodeError(f"Base64 decoding failed: {e}")

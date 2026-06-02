import urllib.parse
from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class UrlDecoder(BaseDecoder):
    name = "url"
    aliases = ["urlencode", "percent"]
    description = "Decodes URL/percent-encoded strings."

    def can_decode(self, data: bytes) -> float:
        try:
            s = data.decode("ascii").strip()
            if not s: return 0.0
            
            import re
            matches = len(re.findall(r'%[0-9a-fA-F]{2}', s))
            if matches > 0:
                # E.g. if it has lots of % signs, it's very likely URL encoded
                # 3 matches is enough to be very confident
                return min(0.95, 0.4 + (matches * 0.2))
            return 0.0
        except Exception:
            return 0.0
    
    def decode(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8", errors="replace")
            decoded = urllib.parse.unquote_plus(text)
            return decoded.encode("utf-8")
        except Exception as e:
            raise DecodeError(f"URL decoding failed: {e}")

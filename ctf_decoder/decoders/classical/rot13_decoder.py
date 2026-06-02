import codecs
from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import DecodeError

class Rot13Decoder(BaseDecoder):
    name = "rot13"
    aliases = ["rot-13", "caesar"]
    description = "Decodes ROT13 cipher (shift by 13)."
    
    def decode(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8")
            decoded_text = codecs.encode(text, 'rot_13')
            return decoded_text.encode("utf-8")
        except Exception as e:
            raise DecodeError(f"ROT13 decoding failed: {e}")

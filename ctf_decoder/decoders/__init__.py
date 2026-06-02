from ctf_decoder.registry import registry
from ctf_decoder.decoders.binary.base64_decoder import Base64Decoder
from ctf_decoder.decoders.binary.hex_decoder import HexDecoder
from ctf_decoder.decoders.binary.binary_decoder import BinaryDecoder
from ctf_decoder.decoders.binary.octal_decoder import OctalDecoder
from ctf_decoder.decoders.classical.rot13_decoder import Rot13Decoder
from ctf_decoder.decoders.classical.atbash_decoder import AtbashDecoder
from ctf_decoder.decoders.web.url_decoder import UrlDecoder
from ctf_decoder.decoders.crypto.xor_decoder import SingleByteXorDecoder
from ctf_decoder.decoders.archive.compression import GzipDecoder, ZlibDecoder, Bzip2Decoder
from ctf_decoder.decoders.classical.alphahex_decoder import AlphaHexDecoder
from ctf_decoder.decoders.classical.morse_decoder import MorseDecoder

def register_all():
    """Register all built-in decoders."""
    registry.register(Base64Decoder)
    registry.register(HexDecoder)
    registry.register(BinaryDecoder)
    registry.register(OctalDecoder)
    registry.register(Rot13Decoder)
    registry.register(AtbashDecoder)
    registry.register(UrlDecoder)
    registry.register(SingleByteXorDecoder)
    registry.register(GzipDecoder)
    registry.register(ZlibDecoder)
    registry.register(Bzip2Decoder)
    registry.register(AlphaHexDecoder)
    registry.register(MorseDecoder)

register_all()

import gzip
import zlib
import bz2
import base64
import re
from ctf_decoder.decoders.base import BaseDecoder

MAX_DECOMPRESS_BYTES = 10 * 1024 * 1024  # 10 MB

# ── Helpers ───────────────────────────────────────────────────────────────────

def _try_unwrap_b64(data: bytes) -> bytes:
    """Auto-decode base64 so users can paste base64-encoded compressed blobs
    directly into the UI text box (the common CTF workflow).
    Returns decoded bytes if they look like binary; original data otherwise."""
    s = data.strip()
    try:
        if re.match(rb'^[A-Za-z0-9+/\-_=\r\n]+$', s):
            candidate = base64.b64decode(s + b'==')   # pad defensively
            if len(candidate) > 0:
                return candidate
    except Exception:
        pass
    return data


def _chunked_decompress(decompressor, data: bytes, chunk_size: int = 65536) -> bytes:
    """Stream data through a decompressor in chunks, enforcing the size cap.
    Calls flush() at the end so zlib decompressobj emits any remaining bytes."""
    result = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        result.extend(decompressor.decompress(chunk))
        if len(result) > MAX_DECOMPRESS_BYTES:
            raise ValueError(
                f"Decompressed output exceeded {MAX_DECOMPRESS_BYTES} bytes"
            )
    if hasattr(decompressor, 'flush'):
        remainder = decompressor.flush()
        result.extend(remainder)
        if len(result) > MAX_DECOMPRESS_BYTES:
            raise ValueError("Decompressed output exceeded size limit after flush")
    return bytes(result)


# ── Decoders ──────────────────────────────────────────────────────────────────

class GzipDecoder(BaseDecoder):
    name        = "gzip"
    aliases     = ["gz"]
    description = "Decompresses gzip data. Auto-unwraps base64 if needed."

    def can_decode(self, data: bytes) -> float:
        # Raw gzip magic bytes
        if data.startswith(b'\x1f\x8b'):
            return 0.95
        # Check if it's base64-encoded gzip
        try:
            unwrapped = _try_unwrap_b64(data)
            if unwrapped is not data and unwrapped.startswith(b'\x1f\x8b'):
                return 0.90
        except Exception:
            pass
        return 0.0

    def decode(self, data: bytes) -> bytes:
        # Auto-unwrap base64 if necessary
        if not data.startswith(b'\x1f\x8b'):
            data = _try_unwrap_b64(data)
        if not data.startswith(b'\x1f\x8b'):
            raise ValueError("Not a gzip stream (magic bytes \\x1f\\x8b not found)")
        try:
            decompressor = zlib.decompressobj(wbits=31)  # wbits=31 = gzip format
            return _chunked_decompress(decompressor, data)
        except Exception as e:
            raise ValueError(f"Gzip decompression failed: {e}")


class ZlibDecoder(BaseDecoder):
    name        = "zlib"
    aliases     = ["deflate"]
    description = "Decompresses zlib/deflate data. Auto-unwraps base64 if needed."

    _ZLIB_HEADERS = (0x01, 0x5e, 0x9c, 0xda)  # low nibble of second byte

    def can_decode(self, data: bytes) -> float:
        if len(data) >= 2 and data[0] == 0x78 and data[1] in self._ZLIB_HEADERS:
            return 0.95
        # Base64-wrapped check
        try:
            unwrapped = _try_unwrap_b64(data)
            if (unwrapped is not data and len(unwrapped) >= 2
                    and unwrapped[0] == 0x78 and unwrapped[1] in self._ZLIB_HEADERS):
                return 0.90
        except Exception:
            pass
        return 0.0

    def decode(self, data: bytes) -> bytes:
        if not (len(data) >= 2 and data[0] == 0x78 and data[1] in self._ZLIB_HEADERS):
            data = _try_unwrap_b64(data)
        if len(data) < 2:
            raise ValueError("Too short for zlib")
        try:
            decompressor = zlib.decompressobj()
            return _chunked_decompress(decompressor, data)
        except Exception as e:
            raise ValueError(f"Zlib decompression failed: {e}")


class Bzip2Decoder(BaseDecoder):
    name        = "bzip2"
    aliases     = ["bz2"]
    description = "Decompresses bzip2 data. Auto-unwraps base64 if needed."

    def can_decode(self, data: bytes) -> float:
        if data.startswith(b'BZh'):
            return 0.95
        try:
            unwrapped = _try_unwrap_b64(data)
            if unwrapped is not data and unwrapped.startswith(b'BZh'):
                return 0.90
        except Exception:
            pass
        return 0.0

    def decode(self, data: bytes) -> bytes:
        if not data.startswith(b'BZh'):
            data = _try_unwrap_b64(data)
        if not data.startswith(b'BZh'):
            raise ValueError("Not a bzip2 stream (magic bytes BZh not found)")
        try:
            decompressor = bz2.BZ2Decompressor()
            return _chunked_decompress(decompressor, data)
        except Exception as e:
            raise ValueError(f"Bzip2 decompression failed: {e}")

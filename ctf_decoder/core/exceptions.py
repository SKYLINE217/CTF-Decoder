class DecodeError(Exception):
    """Base exception for all decoding errors."""
    pass

class DecompressionLimitError(DecodeError):
    """Raised when decompressed output exceeds the configured maximum size."""
    pass

class InvalidChainError(Exception):
    """Raised when a requested decoder chain contains invalid or unknown codecs."""
    pass

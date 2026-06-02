from dataclasses import dataclass, field
from typing import Optional, List

@dataclass(frozen=True)
class DecodeRequest:
    """Represents a request to decode data."""
    input_bytes: bytes
    target_codec: Optional[str] = None
    chain: Optional[List[str]] = None
    max_depth: int = 20
    strict_mode: bool = False
    
    # Custom settings can be passed here
    settings: dict = field(default_factory=dict)

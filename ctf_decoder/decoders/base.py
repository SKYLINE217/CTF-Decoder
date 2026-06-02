from abc import ABC, abstractmethod
from typing import List

class BaseDecoder(ABC):
    """Abstract base class for all CTF Decoder codecs."""
    
    name: str
    aliases: List[str] = []
    description: str = ""
    
    @abstractmethod
    def decode(self, data: bytes) -> bytes:
        """
        Decodes the given byte sequence.
        
        Args:
            data: The encoded bytes.
            
        Returns:
            The decoded bytes.
            
        Raises:
            DecodeError: If decoding fails.
        """
        pass
        
    def can_decode(self, data: bytes) -> float:
        """
        Optional heuristic check to see if this decoder applies.
        
        Args:
            data: The encoded bytes.
            
        Returns:
            A confidence score between 0.0 and 1.0.
        """
        return 0.0

from typing import List
from ctf_decoder.registry import registry
from ctf_decoder.decoders.base import BaseDecoder
from ctf_decoder.core.exceptions import InvalidChainError

class ChainResolver:
    @staticmethod
    def resolve(chain_str: str) -> List[BaseDecoder]:
        """
        Parses a comma-separated chain string and returns a list of decoder instances.
        Raises InvalidChainError if any codec is unknown.
        """
        if not chain_str or not chain_str.strip():
            return []
            
        parts = [p.strip() for p in chain_str.split(',')]
        decoders = []
        
        for part in parts:
            if not part:
                continue
            decoder = registry.get(part)
            if not decoder:
                raise InvalidChainError(f"Unknown codec in chain: '{part}'")
            decoders.append(decoder)
            
        return decoders

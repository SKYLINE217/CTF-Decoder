from typing import Dict, List, Type, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ctf_decoder.decoders.base import BaseDecoder

class DecoderRegistry:
    """Singleton registry for all decoders."""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DecoderRegistry, cls).__new__(cls)
            cls._instance._decoders: Dict[str, 'BaseDecoder'] = {}
            cls._instance._aliases: Dict[str, str] = {}
        return cls._instance
        
    def register(self, decoder_cls: Type['BaseDecoder']) -> None:
        """Register a decoder class."""
        decoder = decoder_cls()
        name = decoder.name.lower()
        self._decoders[name] = decoder
        
        for alias in decoder.aliases:
            self._aliases[alias.lower()] = name
            
    def get(self, name: str) -> Optional['BaseDecoder']:
        """Get a decoder by name or alias."""
        name = name.lower()
        if name in self._decoders:
            return self._decoders[name]
        if name in self._aliases:
            return self._decoders[self._aliases[name]]
        return None
        
    def all_codecs(self) -> List['BaseDecoder']:
        """Return all registered decoder instances."""
        return list(self._decoders.values())
        
    def clear(self) -> None:
        """Clear the registry (useful for testing)."""
        self._decoders.clear()
        self._aliases.clear()

registry = DecoderRegistry()

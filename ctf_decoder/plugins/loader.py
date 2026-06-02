import importlib.metadata
import logging
from typing import List, Optional

from ctf_decoder.registry import registry
from ctf_decoder.decoders.base import BaseDecoder

logger = logging.getLogger(__name__)

def load_plugins(allowlist: Optional[List[str]] = None) -> None:
    """
    Discover and load third-party decoder plugins.
    
    Args:
        allowlist: If provided, only plugins with these entry point names are loaded.
    """
    # Use standard library approach for Python 3.10+
    try:
        eps = importlib.metadata.entry_points(group="ctf_decoder.plugins")
    except KeyError:
        # No entry points for this group
        return
        
    for ep in eps:
        if allowlist is not None and ep.name not in allowlist:
            logger.warning(f"Skipping plugin '{ep.name}' (not in allowlist).")
            continue
            
        try:
            plugin_cls = ep.load()
            if issubclass(plugin_cls, BaseDecoder):
                registry.register(plugin_cls)
                logger.debug(f"Loaded plugin: {ep.name}")
            else:
                logger.error(f"Plugin '{ep.name}' does not inherit from BaseDecoder.")
        except Exception as e:
            logger.error(f"Failed to load plugin '{ep.name}': {e}")

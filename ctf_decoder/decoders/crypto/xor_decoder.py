from typing import Optional, List
from ctf_decoder.decoders.base import BaseDecoder

class SingleByteXorDecoder(BaseDecoder):
    name = "xor"
    aliases = ["single-byte-xor"]
    description = "Decodes single-byte XOR encryption by finding the key with the highest plaintext score."

    def decode(self, data: bytes) -> bytes:
        from ctf_decoder.output.ranker import ResultRanker
        from ctf_decoder.output.flag_detector import FlagDetector
        from ctf_decoder.decoders.binary.hex_decoder import HexDecoder
        from ctf_decoder.decoders.binary.base64_decoder import Base64Decoder
        
        # Auto-unwrap Hex or Base64 if the user pasted a formatted string instead of raw bytes
        try:
            if HexDecoder().can_decode(data) > 0.5:
                data = HexDecoder().decode(data)
            elif Base64Decoder().can_decode(data) > 0.5:
                data = Base64Decoder().decode(data)
        except Exception:
            pass

        ranker = ResultRanker()
        detector = FlagDetector()
        
        best_output = b""
        best_score = -1.0
        
        for key in range(256):
            output = bytes(b ^ key for b in data)
            
            matches = detector.detect(output)
            score = ranker.score(output, has_flag=matches).total
            if score > best_score:
                best_score = score
                best_output = output
                
        if best_score < 0.2:
            raise ValueError("No plausible XOR key found (score too low)")
            
        return best_output

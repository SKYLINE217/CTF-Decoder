from dataclasses import dataclass
from typing import List, Optional
from ctf_decoder.core.request import DecodeRequest
from ctf_decoder.registry import registry
from ctf_decoder.detection.engine import DetectionEngine
from ctf_decoder.core.chain import ChainResolver
from ctf_decoder.core.exceptions import InvalidChainError

MAX_INPUT_BYTES = 1024 * 1024  # 1 MB

@dataclass
class DecodeStep:
    codec: str
    output: bytes
    error: Optional[str] = None

@dataclass
class PipelineResult:
    final_output: Optional[bytes]
    steps: List[DecodeStep]
    success: bool
    error: Optional[str] = None

class PipelineManager:
    def __init__(self):
        self.detection_engine = DetectionEngine()
        
    def _validate_request(self, request: DecodeRequest) -> None:
        if len(request.input_bytes) > MAX_INPUT_BYTES:
            raise ValueError(f"Input exceeds maximum allowed size ({MAX_INPUT_BYTES} bytes)")
            
    def run_single(self, request: DecodeRequest) -> PipelineResult:
        try:
            self._validate_request(request)
        except ValueError as e:
            return PipelineResult(None, [], False, str(e))
            
        target_codec_name = request.target_codec
        
        if not target_codec_name:
            candidates = self.detection_engine.detect(request.input_bytes)
            if not candidates:
                return PipelineResult(None, [], False, "Auto-detection failed: no suitable codec found")
            target_codec_name = candidates[0][1]
            
        decoder = registry.get(target_codec_name)
        if not decoder:
            return PipelineResult(None, [], False, f"Unknown codec: {target_codec_name}")
            
        try:
            output = decoder.decode(request.input_bytes)
            step = DecodeStep(decoder.name, output)
            return PipelineResult(output, [step], True)
        except Exception as e:
            step = DecodeStep(decoder.name, b"", str(e))
            return PipelineResult(None, [step], False, f"Decoding failed: {str(e)}")
            
    def run_chain(self, request: DecodeRequest) -> PipelineResult:
        try:
            self._validate_request(request)
        except ValueError as e:
            return PipelineResult(None, [], False, str(e))
            
        if not request.chain:
            return PipelineResult(None, [], False, "No chain specified")
            
        try:
            decoders = ChainResolver.resolve(",".join(request.chain))
        except InvalidChainError as e:
            return PipelineResult(None, [], False, str(e))
            
        current_data = request.input_bytes
        steps = []
        
        for decoder in decoders:
            try:
                current_data = decoder.decode(current_data)
                steps.append(DecodeStep(decoder.name, current_data))
            except Exception as e:
                steps.append(DecodeStep(decoder.name, b"", str(e)))
                if not request.strict_mode:
                    return PipelineResult(None, steps, False, f"Chain broken at {decoder.name}: {e}")
                
        return PipelineResult(current_data, steps, True)

    def run_autopilot(self, request: DecodeRequest, max_depth: int = 5) -> PipelineResult:
        """
        AI-guided smart search that recursively decodes the input using ML predictions
        and stops when a flag is found or all promising paths are exhausted.
        """
        try:
            self._validate_request(request)
        except ValueError as e:
            return PipelineResult(None, [], False, str(e))
            
        from ctf_decoder.output.flag_detector import FlagDetector
        detector = FlagDetector()
        
        import hashlib
        seen_states = set()
        best_result = None
        
        def dfs(data: bytes, path_steps: List[DecodeStep], depth: int) -> Optional[PipelineResult]:
            nonlocal best_result
            
            # Check for flag matches
            matches = detector.detect(data)
            if matches:
                # Check if we have a specific known flag format (e.g. FLAG{, CTF{, etc.)
                has_specific = False
                for m in matches:
                    val_upper = m.value.upper()
                    if any(val_upper.startswith(prefix) for prefix in ("FLAG{", "CTF{", "PICOCTF{", "HTB{", "THM{", "DUCTF{")):
                        has_specific = True
                        break
                
                # Check if there is still a high-confidence next step to try
                candidates = self.detection_engine.detect(data)
                best_codec_prob = 0.0
                if candidates:
                    valid_c = [c for c in candidates if c[1] != "none"]
                    if valid_c:
                        best_codec_prob = valid_c[0][0]
                
                # Stop if it is a specific flag format, or if no high-confidence codec (> 0.5) is available
                if has_specific or best_codec_prob < 0.5:
                    return PipelineResult(data, path_steps, True)
                
            if depth >= max_depth:
                if not best_result or len(path_steps) > len(best_result.steps):
                    best_result = PipelineResult(data, path_steps, False, "Max depth reached without finding a flag")
                return None
                
            data_hash = hashlib.sha256(data).hexdigest()
            if data_hash in seen_states:
                return None
            seen_states.add(data_hash)
            
            # Get candidates from detection engine
            candidates = self.detection_engine.detect(data)
            if not candidates:
                return None
                
            # Filter low confidence candidates
            candidates = [c for c in candidates if c[0] >= 0.1 and c[1] != "none"]
            
            # Try candidates in order of confidence
            for score, codec_name in candidates:
                decoder = registry.get(codec_name)
                if not decoder:
                    continue
                try:
                    output = decoder.decode(data)
                    if not output or output == data:
                        continue
                    new_step = DecodeStep(codec_name, output)
                    res = dfs(output, path_steps + [new_step], depth + 1)
                    if res and res.success:
                        return res
                except Exception:
                    continue
            return None

        # Start search
        result = dfs(request.input_bytes, [], 0)
        if result:
            return result
            
        # If no path found the flag, but we solved a few steps, return the longest step progression
        if best_result:
            return best_result
            
        return PipelineResult(None, [], False, "Auto-detection could not find a valid decoding path to a flag")

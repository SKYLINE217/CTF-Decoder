import threading
from typing import List, Tuple
from ctf_decoder.detection.pattern import analyze_patterns
from ctf_decoder.detection.scorer import score_candidates

class DetectionTimeoutError(Exception):
    pass

class DetectionEngine:
    def __init__(self, timeout_ms: int = 500):
        self.timeout_ms = timeout_ms
        # Pre-load the ML model outside the detection thread
        try:
            from ctf_decoder.detection.ml_model import MLModelManager
            MLModelManager.load_model()
        except Exception:
            pass
        
    def detect(self, data: bytes) -> List[Tuple[float, str]]:
        """
        Runs the detection pipeline on the input data.
        Returns a list of (confidence_score, codec_name).
        """
        result = []
        error = None
        
        def run_detection():
            nonlocal result, error
            try:
                pattern_scores = analyze_patterns(data)
                result = score_candidates(data, pattern_scores)
            except Exception as e:
                error = e
                
        # Run in thread for timeout (basic mitigation for ReDoS)
        thread = threading.Thread(target=run_detection)
        thread.start()
        thread.join(timeout=self.timeout_ms / 1000.0)
        
        if thread.is_alive():
            raise DetectionTimeoutError(f"Detection timed out after {self.timeout_ms}ms")
            
        if error:
            raise error
            
        return result

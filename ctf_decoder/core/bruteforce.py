from typing import List, Optional, Set
from dataclasses import dataclass
import heapq
import time

from ctf_decoder.core.pipeline import PipelineManager, PipelineResult, DecodeRequest
from ctf_decoder.registry import registry
from ctf_decoder.adaptive.memory import memory_db, session
from ctf_decoder.detection.engine import DetectionEngine
from ctf_decoder.output.ranker import ResultRanker
from ctf_decoder.output.flag_detector import FlagDetector

@dataclass
class SearchNode:
    score: float
    depth: int
    data: bytes
    chain: List[str]
    
    def __lt__(self, other):
        return self.score < other.score

class BruteForceEngine:
    def __init__(self, max_depth: int = 3, timeout_sec: float = 10.0, flag_patterns: Optional[List[str]] = None):
        self.max_depth = max_depth
        self.timeout_sec = timeout_sec
        self.pipeline = PipelineManager()
        self.detection = DetectionEngine()
        self.ranker = ResultRanker()
        self.flag_detector = FlagDetector(extra_patterns=flag_patterns)
        
    def search(self, initial_data: bytes) -> Optional[PipelineResult]:
        start_time = time.time()
        
        queue: List[SearchNode] = []
        heapq.heappush(queue, SearchNode(score=0.0, depth=0, data=initial_data, chain=[]))
        
        seen_data: Set[bytes] = set()
        codecs = [c.name for c in registry.all_codecs()]
        
        while queue:
            if time.time() - start_time > self.timeout_sec:
                break
                
            node = heapq.heappop(queue)
            
            if node.data in seen_data:
                continue
            seen_data.add(node.data)
            
            if self.flag_detector.has_flag(node.data) and node.depth > 0:
                request = DecodeRequest(input_bytes=initial_data, chain=node.chain, strict_mode=False)
                return self.pipeline.run_chain(request)
                
            if node.depth >= self.max_depth:
                continue
                
            candidates = self.detection.detect(node.data)
            
            if not candidates:
                candidates = [(0.1, c) for c in codecs]
                
            for conf, codec_name in candidates:
                decoder = registry.get(codec_name)
                if not decoder:
                    continue
                try:
                    next_data = decoder.decode(node.data)
                    
                    if next_data == node.data or next_data in seen_data:
                        continue
                        
                    heuristic_score = conf
                    
                    new_chain = node.chain + [codec_name]
                    templates = memory_db.get_chain_templates(platform=session.platform_hint)
                    for t in templates:
                        if len(t.chain) >= len(new_chain) and t.chain[:len(new_chain)] == new_chain:
                            heuristic_score += 0.5
                            break
                            
                    next_node = SearchNode(
                        score=-heuristic_score,
                        depth=node.depth + 1,
                        data=next_data,
                        chain=new_chain
                    )
                    heapq.heappush(queue, next_node)
                    
                except Exception:
                    pass
                    
        return None

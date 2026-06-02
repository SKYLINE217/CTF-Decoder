import re
import sys
from typing import List, Dict, Any
from dataclasses import dataclass
from ctf_decoder.core.pipeline import PipelineManager, PipelineResult, DecodeRequest

# Regex patterns for extracting potential encoded blobs from noisy/garbage data
POTENTIAL_BLOBS = {
    "base64": re.compile(r"[A-Za-z0-9+/]{8,}=*"),
    "hex": re.compile(r"(?:0x|\\x)?(?:[a-fA-F0-9]{2}){4,}\b"),
    "binary": re.compile(r"\b[01]{8,}\b"),
    "morse": re.compile(r"[.\-\s/]{8,}"),
    "octal": re.compile(r"\b[0-7]{8,}\b"),
    "url": re.compile(r"(?:%[0-9a-fA-F]{2}){2,}")
}

@dataclass
class SolveCandidate:
    raw_match: str
    match_type: str
    start: int
    end: int

@dataclass
class ChallengeSolve:
    candidate: SolveCandidate
    result: PipelineResult
    flag: str

class ChallengeSolver:
    """
    Scans files, raw text, or noisy streams for hidden encoded patterns,
    running autopilot recursively on each candidate to extract flags.
    """
    def __init__(self):
        self.pipeline = PipelineManager()

    def extract_candidates(self, text: str) -> List[SolveCandidate]:
        candidates = []
        seen = set()
        
        # 1. First add the full text as a candidate if it's not empty
        cleaned_full = text.strip()
        if cleaned_full:
            candidates.append(SolveCandidate(
                raw_match=cleaned_full,
                match_type="full_input",
                start=0,
                end=len(text)
            ))
            seen.add(cleaned_full)
            
        # 2. Extract substrings matching known encoding patterns
        for match_type, regex in POTENTIAL_BLOBS.items():
            for match in regex.finditer(text):
                raw = match.group().strip()
                # Skip trivial matches or matches that overlap too much
                if len(raw) < 8 or raw in seen:
                    continue
                candidates.append(SolveCandidate(
                    raw_match=raw,
                    match_type=match_type,
                    start=match.start(),
                    end=match.end()
                ))
                seen.add(raw)
                
        # 3. Add lines as candidates if multiple lines exist
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if len(lines) > 1:
            for i, line in enumerate(lines):
                if line not in seen and len(line) >= 6:
                    candidates.append(SolveCandidate(
                        raw_match=line,
                        match_type=f"line_{i+1}",
                        start=text.find(line),
                        end=text.find(line) + len(line)
                    ))
                    seen.add(line)
                    
        return candidates

    def solve(self, text: str, extra_flag_patterns: List[str] = None) -> List[ChallengeSolve]:
        candidates = self.extract_candidates(text)
        solves = []
        
        from ctf_decoder.output.flag_detector import FlagDetector
        detector = FlagDetector(extra_patterns=extra_flag_patterns)
        
        for cand in candidates:
            # Prepare request bytes
            input_bytes = cand.raw_match.encode("utf-8", errors="ignore")
            request = DecodeRequest(input_bytes=input_bytes)
            
            # Execute autopilot
            res = self.pipeline.run_autopilot(request)
            
            # Verify if result has a flag
            if res.success and res.final_output:
                flags = detector.detect(res.final_output)
                if flags:
                    solves.append(ChallengeSolve(
                        candidate=cand,
                        result=res,
                        flag=flags[0].value
                    ))
                    
        return solves

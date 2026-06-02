"""
CTF Decoder — FastAPI Application
POST /api/decode   – single codec or auto-detect
POST /api/brute    – best-first brute force
POST /api/detect   – candidate list only (no decode)
GET  /api/codecs   – all registered decoders
GET  /api/memory   – adaptive memory snapshot
POST /api/feedback – explicit user feedback
GET  /             – SPA (index.html)
"""

from __future__ import annotations

import base64
import time
import re
from pathlib import Path
from typing import List, Optional

import mimetypes
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from ctf_decoder.core.pipeline import PipelineManager, DecodeRequest
from ctf_decoder.core.bruteforce import BruteForceEngine
from ctf_decoder.output.ranker import ResultRanker
from ctf_decoder.output.flag_detector import FlagDetector
from ctf_decoder.detection.engine import DetectionEngine
from ctf_decoder.registry import registry
from ctf_decoder.adaptive.memory import memory_db, session

# ── App & CORS ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="CTF Decoder API",
    description="Adaptive CTF decoding engine — REST interface",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-eval' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "object-src 'none';"
    )
    response.headers["Content-Security-Policy"] = csp
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

_pipeline = PipelineManager()
_ranker   = ResultRanker()
_detector = DetectionEngine()

MAX_INPUT_BYTES = 1 * 1024 * 1024  # 1 MB


# ── Schemas ──────────────────────────────────────────────────────────────────

class DataPayload(BaseModel):
    """All decode endpoints accept input as a base64 string for safe transport."""
    data_b64: str

    @field_validator("data_b64")
    @classmethod
    def validate_size(cls, v: str) -> str:
        try:
            raw = base64.b64decode(v, validate=True)
        except Exception:
            raise ValueError("data_b64 must be a valid base64 string")
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError(f"Input exceeds {MAX_INPUT_BYTES} byte limit")
        return v

    def raw(self) -> bytes:
        return base64.b64decode(self.data_b64)


class DecodePayload(DataPayload):
    codec: Optional[str]      = None
    chain: Optional[List[str]] = None
    strict_mode: bool          = False
    flag_patterns: Optional[List[str]] = None


class BrutePayload(DataPayload):
    depth:         int          = 3
    timeout:       float        = 10.0
    flag_patterns: Optional[List[str]] = None


class FeedbackPayload(BaseModel):
    codec:    str
    success:  bool
    platform: Optional[str] = None


class CodePayload(BaseModel):
    code: str
    language: str
    run_dynamically: bool = False
    flag_pattern: Optional[str] = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def safe_decode(data: bytes) -> str:
    res = ""
    for b in data:
        # Printable ASCII or standard whitespace (tab, newline, carriage return)
        if 32 <= b <= 126 or b in (9, 10, 13):
            res += chr(b)
        else:
            res += f"\\x{b:02x}"
    return res

def _serialize_result(result, flag_patterns: Optional[List[str]] = None) -> dict:
    if not result.success:
        return {"success": False, "error": result.error}

    detector = FlagDetector(extra_patterns=flag_patterns)
    flags    = detector.detect(result.final_output)
    score    = _ranker.score(result.final_output, has_flag=flags)

    # Implicit adaptive feedback on flag-verified solves
    if flags:
        codec_chain = [s.codec for s in result.steps]
        for step in result.steps:
            prior = memory_db.get_prior(step.codec)
            memory_db.set_prior(step.codec, prior.alpha + 0.8, prior.beta)
        memory_db.upsert_chain_template(codec_chain)

        # Platform inference
        FLAG_MAP = {
            r"picoCTF\{": "picoCTF", r"HTB\{": "HackTheBox",
            r"THM\{": "TryHackMe", r"DUCTF\{": "DownUnderCTF",
        }
        for pattern, platform in FLAG_MAP.items():
            if re.search(pattern, flags[0].value):
                session.platform_hint = platform
                memory_db.update_platform_profile(platform, codec_chain)
                break

    return {
        "success":          True,
        "final_output_b64": base64.b64encode(result.final_output).decode(),
        "final_output_str": safe_decode(result.final_output),
        "steps": [
            {
                "codec":      s.codec,
                "output_str": safe_decode(s.output),
                "output_b64": base64.b64encode(s.output).decode(),
                "error":      s.error,
            }
            for s in result.steps
        ],
        "score": {
            "total":          score.total,
            "printable_ascii":score.printable_ascii,
            "english_freq":   score.english_freq,
            "bigram_freq":    score.bigram_freq,
            "word_match":     score.word_match,
            "flag_bonus":     score.flag_bonus,
        },
        "flags": [{"value": f.value, "position": f.start} for f in flags],
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/api/decode")
@limiter.limit("60/minute")
def route_decode(request: Request, payload: DecodePayload):
    raw = payload.raw()

    if payload.chain:
        req    = DecodeRequest(input_bytes=raw, chain=payload.chain, strict_mode=payload.strict_mode)
        result = _pipeline.run_chain(req)
    elif payload.codec:
        req    = DecodeRequest(input_bytes=raw, target_codec=payload.codec)
        result = _pipeline.run_single(req)
    else:
        candidates = _detector.detect(raw)
        if candidates:
            top_codec = candidates[0][1]
            # Try to resolve a chain from memory templates
            templates = memory_db.get_chain_templates()
            best_chain = None
            for t in templates:
                if len(t.chain) > 1 and t.chain[0] == top_codec:
                    best_chain = t.chain
                    break
            
            if best_chain:
                req = DecodeRequest(input_bytes=raw, chain=best_chain)
                result = _pipeline.run_chain(req)
                if result.success:
                    return _serialize_result(result, payload.flag_patterns)
                    
        # Fallback to single if no chain or chain failed
        req    = DecodeRequest(input_bytes=raw)
        result = _pipeline.run_single(req)

    return _serialize_result(result, payload.flag_patterns)


@app.post("/api/brute")
@limiter.limit("5/minute")
def route_brute(request: Request, payload: BrutePayload):
    raw    = payload.raw()
    engine = BruteForceEngine(
        max_depth=payload.depth,
        timeout_sec=payload.timeout,
        flag_patterns=payload.flag_patterns,
    )
    t0     = time.time()
    result = engine.search(raw)
    elapsed = round(time.time() - t0, 3)

    if not result:
        return {
            "success":  False,
            "error":    "No flag found within depth/timeout constraints.",
            "elapsed":  elapsed,
        }

    out = _serialize_result(result, payload.flag_patterns)
    out["elapsed"] = elapsed
    return out


@app.post("/api/solve-code")
@limiter.limit("20/minute")
def route_solve_code(request: Request, payload: CodePayload):
    from ctf_decoder.core.code_solver import CodeSolver
    solver = CodeSolver()
    result = solver.solve_code(
        code=payload.code,
        language=payload.language,
        run_dynamically=payload.run_dynamically,
        flag_pattern=payload.flag_pattern
    )
    return result


@app.post("/api/detect")
@limiter.limit("60/minute")
def route_detect(request: Request, payload: DataPayload):
    candidates = _detector.detect(payload.raw())
    return {
        "candidates": [
            {"codec": name, "confidence": round(conf, 4)}
            for conf, name in candidates
        ]
    }


@app.get("/api/codecs")
def route_codecs():
    return {
        "codecs": [
            {
                "name":        c.name,
                "aliases":     c.aliases,
                "description": c.description,
            }
            for c in registry.all_codecs()
        ]
    }


@app.get("/api/memory")
def route_memory():
    priors    = memory_db.get_all_priors()
    templates = memory_db.get_chain_templates()
    return {
        "session": session.summary(),
        "platform_hint": session.platform_hint,
        "priors": [
            {
                "codec":          codec,
                "alpha":          round(p.alpha, 3),
                "beta":           round(p.beta, 3),
                "success_rate":   round(p.expected_value, 4),
                "last_updated":   p.last_updated[:10],
            }
            for codec, p in sorted(priors, key=lambda x: -x[1].expected_value)
        ],
        "templates": [
            {
                "chain":        t.chain,
                "frequency":    t.frequency,
                "success_rate": t.success_rate,
                "platform":     t.platform,
            }
            for t in templates[:10]
        ],
        "recent_solves": len(memory_db.get_recent_solve_events(days=7)),
    }


@app.post("/api/feedback")
def route_feedback(payload: FeedbackPayload):
    dec = registry.get(payload.codec)
    if not dec:
        raise HTTPException(status_code=404, detail=f"Unknown codec: {payload.codec}")
    memory_db.update_prior(dec.name, was_correct=payload.success)
    if payload.platform and payload.success:
        memory_db.update_platform_profile(payload.platform, [dec.name])
    prior = memory_db.get_prior(dec.name)
    return {
        "status":       "ok",
        "codec":        dec.name,
        "success":      payload.success,
        "new_prior": {
            "alpha":        round(prior.alpha, 3),
            "beta":         round(prior.beta, 3),
            "success_rate": round(prior.expected_value, 4),
        },
    }


@app.post("/api/memory/decay")
def route_memory_decay():
    memory_db.apply_decay()
    return {"status": "ok", "message": "Decay applied to all codec priors."}


@app.post("/api/memory/clear")
def route_memory_clear():
    memory_db.clear()
    return {"status": "ok", "message": "All adaptive memory cleared."}


# ── Static SPA ────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/{full_path:path}", include_in_schema=False)
def spa_catchall(full_path: str):
    index = STATIC_DIR / "index.html"
    if index.exists():
        headers = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0"
        }
        return FileResponse(str(index), headers=headers)
    return HTMLResponse("<h1>UI not built</h1><p>Run: python -m ctf_decoder serve</p>", status_code=200)

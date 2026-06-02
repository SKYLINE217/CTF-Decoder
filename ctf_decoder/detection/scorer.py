from typing import Dict, List, Tuple
from ctf_decoder.registry import registry
from ctf_decoder.detection.entropy import calculate_entropy, entropy_confidence
from ctf_decoder.adaptive.memory import memory_db, session

# Typical entropy ranges for each codec's OUTPUT
ENTROPY_PROFILES = {
    "base64": (5.8, 6.2),
    "hex":    (3.8, 4.2),
    "binary": (0.8, 1.2),
    "url":    (3.5, 5.0),
    "rot13":  (3.5, 5.0),
    "atbash": (3.5, 5.0),
    "gzip":   (7.5, 8.0),   # raw compressed binary = max entropy
    "zlib":   (7.5, 8.0),
    "bzip2":  (7.5, 8.0),
}


def adjusted_score(codec: str, structural_score: float) -> float:
    prior = memory_db.get_prior(codec)
    learned_rate = prior.alpha / (prior.alpha + prior.beta)
    n = prior.alpha + prior.beta - 2
    if n <= 0:
        blend = 0.0
    else:
        blend = min(0.30, n / (n + 20))
    return structural_score * (1 - blend) + learned_rate * blend


def score_candidates(data: bytes, pattern_scores: Dict[str, float]) -> List[Tuple[float, str]]:
    """
    Combines pattern scores, entropy, and Bayesian priors.
    Returns ranked list of (confidence, codec_name).

    CRITICAL FIX: codecs whose can_decode() is authoritative (gzip, zlib, bzip2)
    must participate even when a text-pattern classifier (base64/hex) dominates,
    because binary magic-byte detection is orthogonal to text pattern detection.
    """
    entropy = calculate_entropy(data)
    candidates = []
    has_positive = any(s > 0.0 for s in pattern_scores.values())

    from ctf_decoder.detection.ml_model import MLModelManager
    
    ml_probs_dict = {}
    if MLModelManager.load_model():
        try:
            ml_probs_dict = {name: prob for prob, name in MLModelManager.predict_codec_probs(data)}
        except Exception:
            pass

    for codec in registry.all_codecs():
        name = codec.name

        # ── Step 1: Custom heuristic (highest authority) ─────────────────────
        # Must run BEFORE any exclusion logic so binary decoders with magic-byte
        # checks (gzip: \x1f\x8b, bzip2: BZh, etc.) can always register.
        custom_conf = codec.can_decode(data)

        # ── Step 2: Pattern classifier base score ────────────────────────────
        if name in pattern_scores:
            base_score = pattern_scores[name]
            # Only exclude if BOTH the classifier AND the heuristic rule it out
            if base_score == 0.0 and custom_conf == 0.0:
                continue
        else:
            # Codec is not covered by the text pattern classifier (e.g. gzip).
            # Use heuristic if available; else fall back based on context.
            if custom_conf > 0.0:
                base_score = custom_conf
            elif has_positive:
                # Another codec's pattern was detected; don't add noise unless
                # the decoder proves it can handle the data via its heuristic.
                base_score = 0.0
            else:
                base_score = 0.3   # nothing detected — be open to anything

        # ── Step 3: Entropy cross-check ──────────────────────────────────────
        if name in ENTROPY_PROFILES and base_score > 0:
            expected_min, expected_max = ENTROPY_PROFILES[name]
            ent_conf = entropy_confidence(entropy, expected_min, expected_max)
            structural_combined = (base_score * 0.7) + (ent_conf * 0.3)
        else:
            structural_combined = base_score

        # ── Step 3b: Blend with ML model score ────────────────────────────────
        if ml_probs_dict:
            ml_score = ml_probs_dict.get(name, 0.0)
            structural_combined = (structural_combined * 0.4) + (ml_score * 0.6)

        # ── Step 4: Bayesian prior ───────────────────────────────────────────
        final_score = adjusted_score(name, structural_combined)

        # ── Step 5: Session short-term boost ─────────────────────────────────
        final_score = min(1.0, final_score + session.within_session_boost(name))

        # ── Step 6: Heuristic always lifts the floor ─────────────────────────
        if custom_conf > 0:
            final_score = max(final_score, custom_conf)

        if final_score > 0.1:
            candidates.append((final_score, name))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

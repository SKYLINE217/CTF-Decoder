import math
import zlib
from typing import List

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freqs = [0.0] * 256
    for b in data:
        freqs[b] += 1.0
    entropy = 0.0
    for f in freqs:
        if f > 0.0:
            p = f / len(data)
            entropy -= p * math.log2(p)
    return entropy

def compute_fingerprint(data: bytes) -> List[float]:
    """
    Computes a 32-dimensional float vector summarizing the structural properties of an input.
    """
    if not data:
        return [0.0] * 32
        
    length = len(data)
    
    # ── Dimensions 0–3: Length Metrics ──────────────────────────────────────
    f_log_len = math.log(length + 1)
    f_mod4 = 1.0 if length % 4 == 0 else 0.0
    f_mod8 = 1.0 if length % 8 == 0 else 0.0
    f_mod16 = 1.0 if length % 16 == 0 else 0.0
    
    # ── Dimension 4: Shannon Entropy ─────────────────────────────────────────
    f_entropy = calculate_entropy(data)
    
    # ── Dimensions 5–10: Byte-value Histogram (6 buckets) ─────────────────────
    # Buckets: 0-31, 32-63, 64-95, 96-127, 128-191, 192-255
    hist = [0.0] * 6
    for b in data:
        if b < 32:
            hist[0] += 1
        elif b < 64:
            hist[1] += 1
        elif b < 96:
            hist[2] += 1
        elif b < 128:
            hist[3] += 1
        elif b < 192:
            hist[4] += 1
        else:
            hist[5] += 1
    for i in range(6):
        hist[i] /= length
        
    # ── Dimensions 11–15: Character Class Ratios ─────────────────────────────
    upper = 0.0
    lower = 0.0
    digit = 0.0
    punct = 0.0
    non_ascii = 0.0
    
    for b in data:
        if 65 <= b <= 90:
            upper += 1
        elif 97 <= b <= 122:
            lower += 1
        elif 48 <= b <= 57:
            digit += 1
        elif 32 <= b <= 126:
            # printable ASCII punctuation
            if not (65 <= b <= 90 or 97 <= b <= 122 or 48 <= b <= 57):
                punct += 1
        else:
            non_ascii += 1
            
    r_upper = upper / length
    r_lower = lower / length
    r_digit = digit / length
    r_punct = punct / length
    r_non_ascii = non_ascii / length
    
    # ── Dimensions 16–19: Advanced Entropy & Run Lengths ─────────────────────
    # Bigram entropy
    bigram_counts = {}
    if length > 1:
        for i in range(length - 1):
            pair = data[i:i+2]
            bigram_counts[pair] = bigram_counts.get(pair, 0) + 1
        bigram_ent = 0.0
        total_bigrams = length - 1
        for count in bigram_counts.values():
            p = count / total_bigrams
            bigram_ent -= p * math.log2(p)
    else:
        bigram_ent = 0.0
        
    # Trigram entropy
    trigram_counts = {}
    if length > 2:
        for i in range(length - 2):
            triple = data[i:i+3]
            trigram_counts[triple] = trigram_counts.get(triple, 0) + 1
        trigram_ent = 0.0
        total_trigrams = length - 2
        for count in trigram_counts.values():
            p = count / total_trigrams
            trigram_ent -= p * math.log2(p)
    else:
        trigram_ent = 0.0
        
    # Gap/separator entropy (spacing of space, comma, tab, semicolon)
    separators = {32, 44, 9, 59, 10, 13}
    gap_lengths = []
    current_gap = 0
    for b in data:
        if b in separators:
            gap_lengths.append(current_gap)
            current_gap = 0
        else:
            current_gap += 1
    gap_lengths.append(current_gap)
    
    gap_counts = {}
    for g in gap_lengths:
        gap_counts[g] = gap_counts.get(g, 0) + 1
    gap_ent = 0.0
    for count in gap_counts.values():
        p = count / len(gap_lengths)
        gap_ent -= p * math.log2(p)
        
    # Run length mean (consecutive identical bytes)
    runs = []
    current_run = 1
    for i in range(1, length):
        if data[i] == data[i-1]:
            current_run += 1
        else:
            runs.append(current_run)
            current_run = 1
    runs.append(current_run)
    run_length_mean = sum(runs) / len(runs)
    
    # ── Dimensions 20–23: Presence Flags ─────────────────────────────────────
    has_eq = 1.0 if b'=' in data else 0.0
    has_0x = 1.0 if b'0x' in data else 0.0
    has_pct = 1.0 if b'%' in data else 0.0
    has_slash = 1.0 if b'/' in data else 0.0
    
    # ── Dimensions 24–27: Index of Coincidence & Repetition ──────────────────
    # Index of Coincidence
    if length > 1:
        freqs_counts = [0] * 256
        for b in data:
            freqs_counts[b] += 1
        ic = sum(f * (f - 1) for f in freqs_counts) / (length * (length - 1))
    else:
        ic = 0.0
        
    # Simple Kasiski estimate (count repeats of 3-grams)
    kasiski = 0.0
    if length > 3:
        seen = set()
        repeats = 0
        for i in range(length - 3):
            tg = data[i:i+3]
            if tg in seen:
                repeats += 1
            else:
                seen.add(tg)
        kasiski = repeats / (length - 3)
        
    # Repetition ratio (unique bytes vs total bytes)
    unique_bytes = len(set(data))
    rep_ratio = unique_bytes / length
    
    # Compression ratio hint
    try:
        compressed_len = len(zlib.compress(data))
        comp_ratio = compressed_len / length
    except Exception:
        comp_ratio = 1.0
        
    # ── Dimensions 28–31: Reserved ───────────────────────────────────────────
    reserved = [0.0] * 4
    
    fingerprint = [
        f_log_len,
        f_mod4,
        f_mod8,
        f_mod16,
        f_entropy,
        *hist,
        r_upper,
        r_lower,
        r_digit,
        r_punct,
        r_non_ascii,
        bigram_ent,
        trigram_ent,
        gap_ent,
        run_length_mean,
        has_eq,
        has_0x,
        has_pct,
        has_slash,
        ic,
        kasiski,
        rep_ratio,
        comp_ratio,
        *reserved
    ]
    
    return fingerprint

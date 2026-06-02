# Adaptive Engine

> CTF Decoder — Self-Learning, Memory & Evolution Reference

---

## Table of Contents

- [Overview](#overview)
- [Core Philosophy](#core-philosophy)
- [Architecture of the Adaptive Engine](#architecture-of-the-adaptive-engine)
- [Memory System](#memory-system)
  - [Short-Term Memory (Session Context)](#short-term-memory-session-context)
  - [Long-Term Memory (Persistent Knowledge Base)](#long-term-memory-persistent-knowledge-base)
  - [Memory Schema](#memory-schema)
- [Learning Algorithms](#learning-algorithms)
  - [Bayesian Codec Prior Updating](#bayesian-codec-prior-updating)
  - [Chain Pattern Mining](#chain-pattern-mining)
  - [Contextual Fingerprinting](#contextual-fingerprinting)
  - [Reinforcement Signal Collection](#reinforcement-signal-collection)
- [Evolution Mechanisms](#evolution-mechanisms)
  - [Detection Weight Drift](#detection-weight-drift)
  - [Codec Confidence Decay & Revival](#codec-confidence-decay--revival)
  - [Automated Chain Template Synthesis](#automated-chain-template-synthesis)
  - [CTF Platform Profiling](#ctf-platform-profiling)
- [Feedback Loops](#feedback-loops)
  - [Explicit Feedback (User-Confirmed Solves)](#explicit-feedback-user-confirmed-solves)
  - [Implicit Feedback (Behavioural Signals)](#implicit-feedback-behavioural-signals)
  - [Flag Verification Feedback](#flag-verification-feedback)
- [Scoring Model Evolution](#scoring-model-evolution)
  - [Plaintext Scorer Weight Tuning](#plaintext-scorer-weight-tuning)
  - [Online Gradient Descent on Scorer Weights](#online-gradient-descent-on-scorer-weights)
- [Novelty Detection & Custom Cipher Learning](#novelty-detection--custom-cipher-learning)
  - [Anomaly Detection on Input Fingerprints](#anomaly-detection-on-input-fingerprints)
  - [Custom Codec Inference](#custom-codec-inference)
- [Knowledge Transfer Across Sessions](#knowledge-transfer-across-sessions)
  - [Session Summarisation](#session-summarisation)
  - [Knowledge Snapshots & Versioning](#knowledge-snapshots--versioning)
  - [Community Knowledge Sync (Optional)](#community-knowledge-sync-optional)
- [Implementation Roadmap](#implementation-roadmap)
- [Configuration Reference](#configuration-reference)
- [Data Privacy Considerations](#data-privacy-considerations)

---

## Overview

The Adaptive Engine transforms CTF Decoder from a static rulebook into a **self-improving system**. After each solved challenge, the engine records what worked — which codec was used, what chain was applied, what the input looked like, and how confident the detection was. Over time, this accumulated experience reshapes the tool's internal priors, heuristics, and search strategies so that it solves familiar challenge patterns faster and handles novel ones more intelligently.

The engine is designed to be fully optional and transparent. Users who want deterministic, stateless behaviour can disable it entirely (`adaptive.enabled = false`). Users who enable it get a tool that measurably improves the more they use it.

---

## Core Philosophy

Three ideas anchor the design:

**1. Experience as signal, not noise.**
Every solved challenge is a labelled training example: the input had these features, the correct decoder was this one. The engine treats the history of solves as a dataset and continuously updates its models from it.

**2. Confidence, not certainty.**
The engine does not hard-code rules. It maintains probability distributions over possible interpretations of any input. A new solve shifts those distributions — it never resets them. The tool remains willing to try unexpected decoders; it just ranks more-likely ones higher.

**3. Graceful degradation.**
If the engine's learned priors are wrong (e.g. a CTF platform suddenly uses encodings it has never seen), detection falls back to the static heuristics in `CORE_CONCEPTS.md`. The adaptive layer amplifies good performance; it does not replace the foundation.

---

## Architecture of the Adaptive Engine

```
┌─────────────────────────────────────────────────────────────────┐
│                        ADAPTIVE ENGINE                          │
│                                                                 │
│  ┌──────────────┐    ┌───────────────────┐    ┌─────────────┐  │
│  │ Memory Store │◄──►│  Learning Module  │◄──►│  Feedback   │  │
│  │  (SQLite /   │    │                   │    │  Collector  │  │
│  │   JSON-L)    │    │ • Bayesian update │    │             │  │
│  └──────┬───────┘    │ • Weight tuning   │    │ • Explicit  │  │
│         │            │ • Chain mining    │    │ • Implicit  │  │
│         ▼            │ • Fingerprinting  │    │ • Flag verify│ │
│  ┌──────────────┐    └────────┬──────────┘    └─────────────┘  │
│  │  Knowledge   │             │                                 │
│  │    Base      │◄────────────┘                                 │
│  │              │                                               │
│  │ • Codec      │    ┌───────────────────────────────────────┐  │
│  │   priors     │───►│         DETECTION ENGINE              │  │
│  │ • Chain      │    │  (weights overridden by learned priors)│  │
│  │   templates  │    └───────────────────────────────────────┘  │
│  │ • Platform   │                                               │
│  │   profiles   │    ┌───────────────────────────────────────┐  │
│  │ • Anomaly    │───►│        BRUTE-FORCE SEARCH             │  │
│  │   embeddings │    │  (search order shaped by chain temps) │  │
│  └──────────────┘    └───────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

The adaptive engine sits **above** the core decode pipeline. It feeds learned priors into the detection engine and shapes the search order of brute-force mode, but never intercepts the actual byte-level decoding, which remains deterministic.

---

## Memory System

### Short-Term Memory (Session Context)

Short-term memory lives in RAM for the duration of a single `ctfdec` session. It tracks:

- The sequence of decode attempts made in this session, in order.
- Which attempts succeeded (confirmed by the user or by flag detection).
- Running statistics: which codec has been used most often so far today.
- A recency-weighted rolling window of input fingerprints (the last 50 inputs).

Short-term memory informs **within-session adaptation**: if the first five challenges in a session all use Base64 + XOR chains, the engine boosts those codec combinations for the remainder of the session without waiting for a persistent write.

```python
@dataclass
class SessionContext:
    session_id: str                      # UUID, generated at startup
    started_at: datetime
    attempts: list[DecodeAttempt]        # ordered log of all attempts
    confirmed_solves: list[SolveRecord]  # subset where the flag was found
    codec_frequency: Counter[str]        # codec usage count this session
    recent_fingerprints: deque[InputFingerprint]  # maxlen=50
    platform_hint: str | None           # e.g. "picoCTF", "HTB", inferred
```

### Long-Term Memory (Persistent Knowledge Base)

Long-term memory persists across sessions in a local SQLite database (`~/.ctf_decoder/memory.db`) and a companion append-only JSON Lines event log (`~/.ctf_decoder/events.jsonl`).

The SQLite schema stores aggregated statistics (codec success rates, chain frequencies, platform profiles). The JSON Lines log stores every individual solve event as an immutable record, enabling the knowledge base to be rebuilt from scratch at any time.

```
~/.ctf_decoder/
├── memory.db          # Aggregated knowledge base (SQLite)
├── events.jsonl       # Immutable solve event log (append-only)
├── snapshots/         # Point-in-time snapshots of memory.db
│   ├── 2025-06-01.db
│   └── 2025-07-01.db
└── config.toml        # Adaptive engine configuration
```

### Memory Schema

**`solve_events`** — one row per confirmed solve

```sql
CREATE TABLE solve_events (
    id              TEXT PRIMARY KEY,   -- UUID
    session_id      TEXT NOT NULL,
    solved_at       TEXT NOT NULL,      -- ISO-8601 timestamp
    input_hash      TEXT NOT NULL,      -- SHA-256 of raw input (not stored)
    input_length    INTEGER NOT NULL,
    input_entropy   REAL NOT NULL,
    codec_chain     TEXT NOT NULL,      -- JSON array e.g. ["base64","xor","rot13"]
    chain_depth     INTEGER NOT NULL,
    detection_rank  INTEGER,            -- rank of correct codec in detection output (1 = top)
    time_to_solve   REAL,               -- seconds from first attempt to flag
    platform        TEXT,               -- e.g. "picoCTF", "HTB", NULL if unknown
    flag_format     TEXT,               -- e.g. "picoCTF{...}", NULL
    fingerprint_vec BLOB                -- serialised float32 array (see Fingerprinting)
);
```

**`codec_priors`** — learned probability of each codec being correct

```sql
CREATE TABLE codec_priors (
    codec           TEXT PRIMARY KEY,
    alpha           REAL NOT NULL DEFAULT 1.0,  -- Beta distribution alpha (successes + 1)
    beta            REAL NOT NULL DEFAULT 1.0,  -- Beta distribution beta  (failures + 1)
    last_updated    TEXT NOT NULL
);
```

**`chain_templates`** — frequently successful decoder chains

```sql
CREATE TABLE chain_templates (
    chain_json      TEXT PRIMARY KEY,   -- JSON array of codec names
    frequency       INTEGER NOT NULL DEFAULT 1,
    success_rate    REAL NOT NULL DEFAULT 1.0,
    last_seen       TEXT NOT NULL,
    platform        TEXT                -- NULL = platform-agnostic
);
```

**`platform_profiles`** — per-platform encoding style models

```sql
CREATE TABLE platform_profiles (
    platform        TEXT PRIMARY KEY,
    codec_weights   TEXT NOT NULL,      -- JSON object: {codec: weight}
    common_chains   TEXT NOT NULL,      -- JSON array of chain arrays
    total_solves    INTEGER NOT NULL DEFAULT 0,
    last_updated    TEXT NOT NULL
);
```

---

## Learning Algorithms

### Bayesian Codec Prior Updating

Each codec maintains a **Beta distribution** over its probability of being the correct decoder for any given input. The Beta distribution is parameterised by `α` (pseudo-successes) and `β` (pseudo-failures), both initialised to 1.0 (uniform prior).

**Update rule after a confirmed solve:**

```python
def update_prior(codec: str, was_correct: bool, db: MemoryDB) -> None:
    prior = db.get_prior(codec)  # returns (alpha, beta)
    if was_correct:
        new_alpha = prior.alpha + 1.0
        new_beta  = prior.beta
    else:
        new_alpha = prior.alpha
        new_beta  = prior.beta + 1.0
    db.set_prior(codec, new_alpha, new_beta)
```

**Using the prior at detection time:**

The expected value of the Beta distribution, `α / (α + β)`, gives the codec's learned success rate. This is multiplied into the structural fitness score produced by the `PatternClassifier`:

```python
def adjusted_score(codec: str, structural_score: float, db: MemoryDB) -> float:
    prior = db.get_prior(codec)
    learned_rate = prior.alpha / (prior.alpha + prior.beta)
    # Blend: structural evidence weighted 70%, learned prior 30%
    # Blend ratio shifts toward learned as sample size grows
    n = prior.alpha + prior.beta - 2  # effective sample count
    blend = min(0.30, n / (n + 20))   # asymptotically approaches 0.30
    return structural_score * (1 - blend) + learned_rate * blend
```

The blending factor grows with sample count, so the prior has little effect early on but becomes significant after dozens of solves.

---

### Chain Pattern Mining

After each solve, the full codec chain is recorded. The engine periodically mines these records for frequent patterns using a simplified **FP-Growth algorithm** over ordered sequences.

**High-level algorithm:**

1. Load all solve events from the last N days (default 90).
2. Extract the `codec_chain` sequence from each.
3. Build a frequency table of all sub-sequences of length 1, 2, and 3.
4. Sub-sequences appearing more than `MIN_CHAIN_FREQUENCY` times (default 5) and with success rate above `MIN_CHAIN_SUCCESS_RATE` (default 0.7) are promoted to **chain templates**.
5. Chain templates are stored in `chain_templates` and injected into brute-force mode as high-priority starting points.

**Effect on brute-force search:**

```python
def prioritised_chain_seeds(input_fingerprint, platform, db) -> list[list[str]]:
    templates = db.get_chain_templates(platform=platform)
    # Score each template by: frequency * success_rate * fingerprint_similarity
    scored = [
        (t.frequency * t.success_rate * cosine_sim(input_fingerprint, t.centroid),
         t.chain_json)
        for t in templates
    ]
    return [chain for _, chain in sorted(scored, reverse=True)]
```

Brute-force mode tries these seeded chains before falling back to the unconstrained best-first search, dramatically reducing time-to-flag for recurring challenge patterns.

---

### Contextual Fingerprinting

A 32-dimensional float vector that summarises the structural properties of an input. It is computed once per decode attempt and stored with each solve event. Its purpose is to enable **similarity-based retrieval** — given a new input, find past inputs that looked similar and check what worked on them.

**Fingerprint dimensions (selected):**

| Dimensions | Feature |
|---|---|
| 0–3 | Input length bucket (log-scale), length mod 4, mod 8, mod 16 |
| 4 | Shannon entropy |
| 5–10 | Byte-value histogram (coarsened to 6 buckets: 0–31, 32–63, 64–95, 96–127, 128–191, 192–255) |
| 11–15 | Character class ratios: uppercase, lowercase, digit, punctuation, non-ASCII |
| 16–19 | Bigram entropy, trigram entropy, gap entropy (spaces/separators), run-length mean |
| 20–23 | Presence flags: `=` padding, `0x` prefix, `%XX` sequences, `/` separators |
| 24–27 | Index of coincidence, Kasiski period estimate, repetition ratio, compression ratio hint |
| 28–31 | Reserved for future features |

**Similarity retrieval:**

```python
def find_similar_past_inputs(
    fingerprint: np.ndarray,
    db: MemoryDB,
    top_k: int = 5
) -> list[SolveRecord]:
    all_solves = db.get_all_fingerprints()  # returns list of (fingerprint, solve_record)
    scored = [
        (cosine_similarity(fingerprint, fp), record)
        for fp, record in all_solves
    ]
    return [record for _, record in sorted(scored, reverse=True)[:top_k]]
```

At detection time, the top-K similar past solves vote for their codec chains, producing a **retrieval-augmented candidate list** that complements the statistical classifier.

---

### Reinforcement Signal Collection

The engine treats each decode session as a sequence of actions (choose-codec, attempt-decode) and outcomes (success/failure). This framing allows a lightweight **multi-armed bandit** policy to learn which action to prioritise.

Each codec is an "arm". The bandit uses **Thompson Sampling**, drawing a sample from each codec's Beta prior and selecting the codec with the highest sample:

```python
def thompson_sample_codec_order(codecs: list[str], db: MemoryDB) -> list[str]:
    samples = {}
    for codec in codecs:
        prior = db.get_prior(codec)
        # Draw one sample from Beta(alpha, beta)
        samples[codec] = np.random.beta(prior.alpha, prior.beta)
    return sorted(codecs, key=lambda c: samples[c], reverse=True)
```

This naturally balances **exploitation** (prefer codecs that have worked before) with **exploration** (occasionally try lower-ranked codecs, discovering new patterns). Over many sessions, the ordering converges toward the true success-rate ranking for the user's typical challenge set.

---

## Evolution Mechanisms

### Detection Weight Drift

The seven heuristic weights in the `HeuristicScorer` (printable ASCII ratio, bigram frequency, word match ratio, etc.) are not fixed constants — they are stored in the knowledge base and subject to slow **weight drift** as evidence accumulates.

**Drift algorithm (runs nightly or on demand):**

1. Pull all solve events from the last 60 days.
2. For each event, re-score the correct codec using the current weights, producing a predicted score.
3. Compare predicted score to detection rank (1 = top, higher = worse).
4. Compute the mean rank error across all events.
5. Run 10 steps of coordinate descent: perturb each weight by ±0.01, keep the perturbation if it reduces mean rank error.
6. Write updated weights back to `memory.db`.

This is a slow, conservative update — no single session can cause large weight swings. The full convergence timescale is weeks to months of regular use.

```python
def drift_detection_weights(db: MemoryDB, events: list[SolveEvent]) -> ScorerWeights:
    weights = db.get_scorer_weights()  # current weights
    for _ in range(10):               # coordinate descent steps
        for i, w_name in enumerate(weights.names):
            for delta in [+0.01, -0.01]:
                candidate = weights.copy()
                candidate[i] += delta
                candidate[i] = max(0.0, min(1.0, candidate[i]))
                err = mean_rank_error(candidate, events)
                if err < mean_rank_error(weights, events):
                    weights = candidate
                    break
    db.set_scorer_weights(weights)
    return weights
```

---

### Codec Confidence Decay & Revival

Codecs that have not been seen in solved challenges for a long time have their Beta distribution alpha counts **decayed** toward the prior mean (1/2). This prevents stale historical dominance — if a CTF platform stops using a particular encoding, the engine gradually forgets the bias.

**Decay rule (applied at each session start):**

```python
DECAY_HALF_LIFE_DAYS = 90

def apply_decay(db: MemoryDB) -> None:
    now = datetime.utcnow()
    for codec, prior in db.get_all_priors():
        days_since_update = (now - prior.last_updated).days
        decay_factor = 0.5 ** (days_since_update / DECAY_HALF_LIFE_DAYS)
        # Decay excess alpha and beta back toward 1.0
        new_alpha = 1.0 + (prior.alpha - 1.0) * decay_factor
        new_beta  = 1.0 + (prior.beta  - 1.0) * decay_factor
        db.set_prior(codec, new_alpha, new_beta, touch=False)
```

**Revival:** A decayed codec's confidence is immediately restored when it is used successfully. The decay is asymmetric — it erodes forgotten knowledge slowly but restores confirmed knowledge instantly.

---

### Automated Chain Template Synthesis

Beyond recording observed chains, the engine synthesises **new candidate chains** by generalising patterns it has seen.

**Synthesis rules:**

- **Prefix extension:** If chain `[A, B]` appears frequently, the engine also registers `[A, B, ?]` as a template with an open slot, which the brute-force engine fills with any codec.
- **Substitution generalisation:** If both `[base64, xor, rot13]` and `[base64, xor, caesar]` are frequent, synthesise `[base64, xor, *rotation_cipher*]` as a category-generalised template.
- **Reversal:** If `[A, B, C]` is seen on platform P, also register the reversed chain `[C, B, A]` at half weight — useful when the challenge description says "encoded multiple times" without specifying order.

These synthesised templates are marked with `synthesised = true` in the database and are tried after confirmed templates but before unconstrained search.

---

### CTF Platform Profiling

Different CTF platforms have characteristic encoding styles. picoCTF favours Base64 and ROT13; HackTheBox tends to use hex and XOR; some platforms use custom encodings unique to their challenges.

The engine builds a **platform profile** by aggregating solve events grouped by platform (detected from the flag format or provided by the user with `--platform`).

```python
@dataclass
class PlatformProfile:
    platform: str
    codec_weights: dict[str, float]   # normalised frequency of each codec
    common_chains: list[list[str]]    # top-10 chains by frequency
    total_solves: int
    last_updated: datetime
```

When a platform is identified at session start (or inferred from a flag format match), its `codec_weights` are injected as an additional prior, stacked multiplicatively with the Bayesian codec prior.

**Platform inference heuristic:**

```python
FLAG_FORMAT_TO_PLATFORM = {
    r"picoCTF\{": "picoCTF",
    r"HTB\{":     "HackTheBox",
    r"THM\{":     "TryHackMe",
    r"DUCTF\{":   "DownUnderCTF",
    r"FLAG\{":    "generic",
}

def infer_platform(decoded_output: str) -> str | None:
    for pattern, platform in FLAG_FORMAT_TO_PLATFORM.items():
        if re.search(pattern, decoded_output):
            return platform
    return None
```

---

## Feedback Loops

### Explicit Feedback (User-Confirmed Solves)

The strongest learning signal. The user explicitly marks a decode as correct:

```bash
# CLI: confirm the last successful decode as a solve
ctfdec confirm --flag "picoCTF{s0lved_1t}"

# Or inline during decode
ctfdec decode "SGVsbG8=" --confirm-if-flag
```

On confirmation, the engine immediately:
1. Writes a `SolveRecord` to `events.jsonl`.
2. Updates Beta priors for all codecs in the chain (positive update for used codecs, no update for unused).
3. Increments chain template frequency or creates a new template.
4. Updates the platform profile if a platform was identified.

### Implicit Feedback (Behavioural Signals)

Weaker signals inferred from user behaviour without explicit confirmation:

| Signal | Inference | Weight |
|---|---|---|
| User immediately copies the output | Likely correct | 0.4 |
| User tries no further decoders after this one | Likely correct | 0.3 |
| User abandons session within 30s of a decode | Neutral | 0.0 |
| User runs the same input through multiple codecs | Prior attempts likely wrong | −0.2 |
| Output matched a flag pattern | Very likely correct | 0.8 |

Implicit signals contribute a fractional update to Beta priors (scaled by their weight), whereas explicit confirmation always contributes a full integer update.

### Flag Verification Feedback

When the decoded output matches a known flag pattern (see `FlagDetector` in `CORE_CONCEPTS.md`), this is treated as a high-confidence implicit confirmation even without user action. The engine applies a 0.8-weight update immediately and schedules a user-visible notification:

```
✓ Flag pattern detected: picoCTF{...}
  [Solve recorded. Run `ctfdec confirm` to strengthen this learning signal]
```

---

## Scoring Model Evolution

### Plaintext Scorer Weight Tuning

The `ResultRanker` uses a weighted sum of five components to score decoded output (see `CORE_CONCEPTS.md` — Plaintext Scoring). The weights start at their default values but are tuned over time using solved examples as ground truth.

**Ground truth construction:**

For each confirmed solve, the decoder chain produces a sequence of intermediate byte arrays. The final output (the flag) is the positive example. All other intermediate outputs, and all outputs from incorrect codec attempts, are negative examples.

A correct scorer should rank the positive example higher than all negatives. This is a **learning-to-rank** problem, solved here with a simplified pairwise ranking update.

### Online Gradient Descent on Scorer Weights

```python
def update_scorer_weights(
    positive: bytes,
    negatives: list[bytes],
    weights: ScorerWeights,
    learning_rate: float = 0.005
) -> ScorerWeights:
    pos_features = extract_score_features(positive)   # 5-element vector
    pos_score = dot(weights.vector, pos_features)

    for neg in negatives:
        neg_features = extract_score_features(neg)
        neg_score = dot(weights.vector, neg_features)

        margin = pos_score - neg_score
        if margin < 1.0:                              # hinge loss
            # Gradient step: increase weight for features
            # where positive > negative
            grad = pos_features - neg_features
            weights.vector += learning_rate * grad
            weights.vector  = clip(weights.vector, 0.0, 1.0)
            weights.vector /= weights.vector.sum()   # keep normalised

    return weights
```

Updates are small (learning rate 0.005) and clipped to `[0, 1]` with renormalisation, preventing runaway weight values.

---

## Novelty Detection & Custom Cipher Learning

### Anomaly Detection on Input Fingerprints

The engine maintains a running model of "what typical CTF inputs look like" — a **Gaussian Mixture Model (GMM)** fitted to the stored fingerprint vectors of all past inputs.

When a new input arrives, its fingerprint is scored against the GMM. A low log-likelihood score flags the input as **anomalous** — structurally unlike anything seen before.

```python
def is_novel_input(fingerprint: np.ndarray, gmm: GaussianMixture) -> bool:
    log_likelihood = gmm.score_samples([fingerprint])[0]
    threshold = gmm.score_samples(gmm.means_).min() - 2.0  # 2 std below cluster centres
    return log_likelihood < threshold
```

When novelty is detected, the engine:
1. Logs a warning: `⚠ Input fingerprint is unlike any previously seen — brute-force depth increased to 5`.
2. Increases the brute-force search depth by 2 steps.
3. Tags the event as `novel=true` in the event log for later review.

The GMM is re-fitted incrementally every 50 new events using a fixed-memory streaming update.

### Custom Codec Inference

When a novel input is solved (either by brute-force or by the user manually), the engine attempts to infer a **custom transformation rule** from the input/output pair.

This is done by trying a set of parameterised transformation templates and finding parameters that explain the mapping:

**Template library (examples):**

| Template | Parameters to infer | Example |
|---|---|---|
| `CharSubstitution(table)` | 256-entry substitution map | Pigpen, custom alphabet |
| `XorWithKey(key)` | Key bytes | Single or repeating XOR |
| `ShiftWithOffset(n, charset)` | Shift amount, character set | ROT-N variant on custom alphabet |
| `ColumnTransposition(order)` | Column order permutation | Columnar transposition |
| `BitwiseTransform(op, mask)` | Bitwise op, mask value | NOT, AND, OR variants |

**Inference algorithm:**

```python
def infer_custom_codec(
    input_bytes: bytes,
    output_bytes: bytes,
    templates: list[TransformTemplate]
) -> CustomCodec | None:
    for template in templates:
        params = template.fit(input_bytes, output_bytes)
        if params is not None:
            candidate = template.instantiate(params)
            # Verify on a held-out portion of the byte mapping
            if candidate.verify(input_bytes, output_bytes):
                return CustomCodec(
                    name=f"custom_{template.name}_{hash(params):#06x}",
                    template=template,
                    params=params,
                    source_event=current_solve_id
                )
    return None
```

Successfully inferred custom codecs are added to the `DecoderRegistry` as **ephemeral plugins** for the remainder of the session, and saved to the knowledge base for future sessions. The user is notified and can give the codec a memorable name:

```
✓ Custom cipher inferred: CharSubstitution (custom_charsubst_0xa3f2)
  Rename? [Enter name or press Enter to skip]: l33tspeak_variant
```

---

## Knowledge Transfer Across Sessions

### Session Summarisation

At the end of each session, the engine writes a session summary to `memory.db`:

```python
@dataclass
class SessionSummary:
    session_id: str
    duration_seconds: float
    total_attempts: int
    confirmed_solves: int
    new_chain_templates: int          # templates added this session
    prior_updates: dict[str, float]   # codec -> delta in expected value
    novel_inputs_encountered: int
    custom_codecs_inferred: int
    platform: str | None
```

The summary is also printed to the terminal at session end when `adaptive.verbose = true`:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Session Summary — 14 solves, 47 min
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Top codecs this session: base64, xor, hex
 New chain templates added: 3
 Novel inputs: 1 (custom cipher inferred)
 Priors updated for: 8 codecs
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Knowledge Snapshots & Versioning

The knowledge base is snapshotted automatically:
- On the first run of each calendar month.
- Before any bulk re-fitting operation (GMM update, weight drift).
- When explicitly requested: `ctfdec memory snapshot`.

Snapshots are point-in-time copies of `memory.db` stored in `~/.ctf_decoder/snapshots/`. The knowledge base can be rolled back to any snapshot:

```bash
ctfdec memory rollback --snapshot 2025-06-01
```

All snapshots are retained for 12 months; older snapshots are pruned automatically.

### Community Knowledge Sync (Optional)

An opt-in feature allowing users to contribute anonymised solve statistics to a shared community knowledge base and receive aggregated priors in return. No raw input data or flag content is ever transmitted — only codec chain frequencies and fingerprint centroids are shared.

```toml
# config.toml — opt-in only, disabled by default
[adaptive.community]
enabled     = false
endpoint    = "https://community.ctfdecoder.example/api/sync"
share_chains = true
share_fingerprint_centroids = true
receive_platform_profiles   = true
```

When enabled, the sync runs at session end and merges community-aggregated chain templates into the local knowledge base with a weight discount of 0.5 (personal experience outweighs community data).

---

## Implementation Roadmap

| Phase | Features | Status |
|---|---|---|
| **Phase 1 — Foundation** | Memory schema, event logging, session context, explicit feedback | `planned` |
| **Phase 2 — Bayesian Priors** | Codec Beta priors, Thompson sampling, platform profiling | `planned` |
| **Phase 3 — Chain Learning** | FP-Growth chain mining, template injection into brute-force | `planned` |
| **Phase 4 — Fingerprinting** | 32-dim fingerprint, cosine similarity retrieval | `planned` |
| **Phase 5 — Weight Evolution** | Detection weight drift, scorer online gradient descent | `planned` |
| **Phase 6 — Novelty & Inference** | GMM anomaly detection, custom codec inference | `planned` |
| **Phase 7 — Community Sync** | Opt-in anonymised sync, community platform profiles | `planned` |

---

## Configuration Reference

All adaptive engine settings live under `[adaptive]` in `~/.ctf_decoder/config.toml`:

```toml
[adaptive]
enabled                    = true
verbose                    = false          # print session summary at end

[adaptive.memory]
db_path                    = "~/.ctf_decoder/memory.db"
event_log_path             = "~/.ctf_decoder/events.jsonl"
snapshot_dir               = "~/.ctf_decoder/snapshots"
max_snapshot_age_days      = 365

[adaptive.learning]
prior_blend_max            = 0.30           # max weight of learned prior vs structural score
prior_blend_sample_scale   = 20             # samples needed to reach half of blend_max
decay_half_life_days       = 90             # half-life for codec confidence decay
min_chain_frequency        = 5             # min solves before a chain becomes a template
min_chain_success_rate     = 0.70
weight_drift_interval_days = 7             # how often detection weights are re-fitted
scorer_learning_rate       = 0.005

[adaptive.novelty]
gmm_components             = 8             # number of Gaussian components
gmm_refit_interval         = 50            # events between GMM re-fits
novel_brute_depth_boost    = 2             # extra brute-force depth for novel inputs

[adaptive.community]
enabled                    = false
endpoint                   = ""
share_chains               = true
share_fingerprint_centroids = true
receive_platform_profiles  = true
community_weight_discount  = 0.50
```

---

## Data Privacy Considerations

The adaptive engine stores derived metadata about your decode sessions — never the raw input payloads or flag values themselves.

**What is stored:**
- SHA-256 hash of input (not reversible to the original).
- Input length, entropy, and structural statistics.
- The codec chain that worked.
- Timing information.
- Platform and flag format (if detected).

**What is never stored:**
- The raw input bytes.
- The decoded plaintext or flag content.
- Any personal information.

All data lives in `~/.ctf_decoder/` and never leaves your machine unless community sync is explicitly enabled. To delete all adaptive data:

```bash
ctfdec memory clear --confirm
```

This removes `memory.db`, `events.jsonl`, and all snapshots. The tool reverts to its initial static behaviour, as if installed fresh.

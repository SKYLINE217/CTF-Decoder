# Core Concepts & High-Level Decoding Algorithms

> CTF Decoder — Technical Deep Dive

---

## Table of Contents

- [Foundational Concepts](#foundational-concepts)
  - [Encoding vs Encryption vs Hashing](#encoding-vs-encryption-vs-hashing)
  - [The Decode Pipeline Model](#the-decode-pipeline-model)
  - [Chained Decoding](#chained-decoding)
- [Detection Algorithms](#detection-algorithms)
  - [Pattern Classification](#pattern-classification)
  - [Shannon Entropy Analysis](#shannon-entropy-analysis)
  - [Heuristic Scoring & Candidate Ranking](#heuristic-scoring--candidate-ranking)
- [Decoding Algorithms by Category](#decoding-algorithms-by-category)
  - [Binary Encodings](#binary-encodings)
  - [Classical Ciphers](#classical-ciphers)
  - [XOR & Bitwise Operations](#xor--bitwise-operations)
  - [Compression-Based Decoding](#compression-based-decoding)
  - [Web & Text Encodings](#web--text-encodings)
- [Brute-Force Mode](#brute-force-mode)
- [Plaintext Scoring](#plaintext-scoring)
- [Flag Detection](#flag-detection)
- [Plugin API](#plugin-api)

---

## Foundational Concepts

### Encoding vs Encryption vs Hashing

CTF challenges use these three transformations interchangeably in problem descriptions, but they are fundamentally different:

| Property | Encoding | Encryption | Hashing |
|---|---|---|---|
| **Reversible?** | Yes (always) | Yes (with key) | No (one-way) |
| **Key required?** | No | Yes | No |
| **Purpose** | Data representation | Confidentiality | Integrity / fingerprinting |
| **Examples** | Base64, Hex, ROT13 | AES, RSA, XOR | MD5, SHA-256 |
| **CTF Decoder handles?** | Fully | XOR / simple only | Identification only |

CTF Decoder focuses on **encodings and simple ciphers** — transformations that are deterministically reversible without a secret key (or with a key space small enough to brute-force). It identifies hashes but cannot reverse them.

---

### The Decode Pipeline Model

Every decode operation is modelled as a pure function:

```
decode : bytes → Result<bytes, DecodeError>
```

An input byte sequence enters the pipeline; a decoded byte sequence (or an error) exits. Side effects (logging, output formatting) are handled outside the decoder itself.

This purity has two benefits:

1. **Testability** — Decoders can be unit-tested with trivial input/output pairs.
2. **Composability** — The output of any decoder is valid input for any other, enabling chains.

---

### Chained Decoding

Many CTF challenges stack multiple encoding layers. A challenge author might Base64-encode a hex-encoded ROT13-encoded flag to obscure it. CTF Decoder handles this via **decoder chains**.

A chain is an ordered list of codec names. The pipeline applies them left to right:

```
input  ──►  decoder[0]  ──►  decoder[1]  ──►  ...  ──►  decoder[n]  ──►  output
```

The intermediate results between steps are preserved and included in the final output, making it easy to see what each step produced.

**Auto-chain detection** (brute-force mode) explores chains up to a configurable depth, pruning branches where intermediate output looks like noise (low plaintext score).

---

## Detection Algorithms

Accurately identifying an unknown encoding scheme is the hardest problem CTF Decoder solves. The detection engine runs three complementary analyses and combines their signals.

### Pattern Classification

The first pass is structural. Each encoding has characteristic syntactic properties that can be tested cheaply with regular expressions and length checks.

**Character Set Analysis**

| Encoding | Expected Character Set | Length Constraint |
|---|---|---|
| Base64 | `[A-Za-z0-9+/=]` | Length ≡ 0 (mod 4) |
| Base64url | `[A-Za-z0-9_-=]` | Length ≡ 0 (mod 4) |
| Base32 | `[A-Z2-7=]` | Length ≡ 0 (mod 8) |
| Hex | `[0-9a-fA-F]` | Even length |
| Binary | `[01 ]` | Length ≡ 0 (mod 8) (ignoring spaces) |
| Octal | `[0-7 ]` | — |
| ROT13 | `[A-Za-z]` (printable, high letter freq) | — |

For each candidate encoding, the classifier computes a **structural fitness score**:

```
fitness = (chars_in_expected_set / total_chars) * length_constraint_satisfied
```

Encodings with fitness below a threshold (default 0.95) are eliminated from consideration.

**Structural Markers**

Beyond character sets, certain encodings have distinctive structural markers:
- Base64 strings frequently end with one or two `=` padding characters.
- JWT tokens contain exactly two `.` separators and all three segments are Base64url.
- Hex strings for printable ASCII contain many occurrences of `3`, `4`, `5`, `6`, `7` as high nibbles.
- Morse code contains only `.`, `-`, and space/slash separators.

These markers contribute additional weight to the structural fitness score.

---

### Shannon Entropy Analysis

Shannon entropy measures the information density of a byte sequence. It is defined as:

```
H(X) = -Σ p(xᵢ) · log₂(p(xᵢ))
```

Where `p(xᵢ)` is the probability of byte value `xᵢ` occurring in the input.

The maximum entropy for a byte sequence is **8.0 bits/byte** (uniform distribution of all 256 byte values — characteristic of encrypted or compressed data). The minimum is **0.0** (all bytes identical).

Different encoding types produce characteristic entropy profiles:

| Encoding / Data Type | Typical Entropy Range |
|---|---|
| Random / encrypted | 7.5 – 8.0 |
| zlib / gzip compressed | 7.0 – 8.0 |
| Base64 of random data | 5.9 – 6.1 (64-symbol alphabet) |
| Hex-encoded data | 3.8 – 4.2 (16-symbol alphabet) |
| English plaintext | 3.5 – 4.5 |
| ROT13 / Caesar output | 3.5 – 4.5 (same as plaintext) |
| Binary (0s and 1s) | ~1.0 |
| Morse code | ~2.0 – 2.5 |

The entropy value is used to **rule out** impossible encodings and to **boost** likely ones. For example, an input with entropy 1.2 cannot be Base64-encoded ciphertext — it is almost certainly binary or Morse.

---

### Heuristic Scoring & Candidate Ranking

After pattern classification and entropy analysis, each candidate codec has a preliminary score in `[0, 1]`. The `HeuristicScorer` applies additional checks to refine these scores before producing the final ranked list.

**Additional heuristics (selected examples):**

- **Index of Coincidence (IoC)** — Used for classical cipher detection. Measures whether letter frequencies match a natural language distribution. High IoC (≈ 0.065 for English) suggests a monoalphabetic cipher; IoC near `1/26 ≈ 0.038` suggests polyalphabetic.

- **Bigram frequency correlation** — Measures how well the letter-pair frequencies in the input match expected English bigram frequencies. Strong correlation is evidence of a transposition cipher rather than a substitution cipher.

- **Byte value distribution peaks** — Certain encodings produce characteristic peaks in the byte frequency histogram. For example, hex-encoded ASCII has peaks at byte values `0x33`–`0x37` (digits 3–7) and `0x36`–`0x39` (digits 6–9).

- **Magic bytes / file headers** — If, after tentative Base64 or hex decoding, the result starts with a known file magic (`PK\x03\x04` for ZIP, `\x1f\x8b` for gzip, `%PDF` for PDF, `\x89PNG` for PNG), the score for that codec is substantially boosted.

The final ranked list is sorted by combined score. The top-ranked codec is used for single-pass auto-detect; all candidates are explored in brute-force mode.

---

## Decoding Algorithms by Category

### Binary Encodings

#### Base64

Base64 encodes 3 bytes (24 bits) of binary data as 4 ASCII characters, using an alphabet of 64 printable characters (`A-Z`, `a-z`, `0-9`, `+`, `/`) plus `=` for padding.

**High-level decode algorithm:**

1. Strip whitespace. Validate character set.
2. Add missing `=` padding if length is not a multiple of 4.
3. Map each character to its 6-bit value using the lookup table.
4. Concatenate the 6-bit groups into a bit stream.
5. Group the bit stream into bytes (8 bits each). Discard padding bits.

Variants handled: standard Base64, Base64url (`+`→`-`, `/`→`_`), MIME Base64 (line-wrapped at 76 chars).

#### Hexadecimal

Hex encodes each byte as two hexadecimal digits (`00`–`ff`).

**High-level decode algorithm:**

1. Strip separators (spaces, colons, `0x` prefixes).
2. Validate even length and hex character set.
3. Take pairs of characters, convert each pair from base-16 to a byte value.
4. Return the assembled byte array.

Common CTF variants: `\xNN` escape sequences, `%NN` URL encoding (handled separately), space-separated decimal bytes.

#### Binary / Octal

Groups of 8 binary digits (`0`/`1`) or 3 octal digits, each representing one byte. The algorithm mirrors hex decoding: parse groups, convert from base-2 or base-8, assemble bytes.

---

### Classical Ciphers

#### ROT13 / ROT-N (Caesar)

ROT-N shifts each letter of the alphabet by N positions (wrapping around). ROT13 is the special case where N=13 (self-inverse).

**High-level decode algorithm:**

```
for each character c in input:
    if c is uppercase letter:
        decoded[i] = chr((ord(c) - ord('A') - N) % 26 + ord('A'))
    elif c is lowercase letter:
        decoded[i] = chr((ord(c) - ord('a') - N) % 26 + ord('a'))
    else:
        decoded[i] = c  # non-alphabetic characters pass through
```

For unknown N, try all 25 non-trivial shifts and score each output for English plaintext likelihood.

#### Vigenère Cipher

A polyalphabetic substitution cipher. Each letter is shifted by the corresponding letter of a repeating key.

**High-level decode algorithm (known key):**

```
for i, c in enumerate(ciphertext):
    shift = ord(key[i % len(key)]) - ord('A')
    plaintext[i] = caesar_decode(c, shift)
```

**Key recovery (Kasiski / Index of Coincidence method) — brute-force mode:**

1. Find repeated substrings in the ciphertext. Their spacing is likely a multiple of the key length.
2. Compute the GCD of the spacings to estimate key length K.
3. Divide the ciphertext into K subsequences (every K-th character).
4. Each subsequence is a Caesar cipher — solve each independently using frequency analysis.
5. Combine the K recovered shift values to reconstruct the key.

#### Atbash

Substitutes each letter with its mirror in the alphabet (A↔Z, B↔Y, etc.). It is its own inverse.

```
decoded[i] = chr(ord('Z') - (ord(c) - ord('A')))  # for uppercase
```

#### Rail Fence Cipher

A transposition cipher that writes the plaintext in a zigzag pattern across N "rails" (rows), then reads off row by row.

**High-level decode algorithm:**

1. Given ciphertext length L and rail count N, compute how many characters fall on each rail.
2. Split the ciphertext into segments corresponding to each rail.
3. Reconstruct the zigzag index order (which position goes to which rail at which index).
4. Read characters from rail segments in zigzag order to recover the plaintext.

---

### XOR & Bitwise Operations

#### Single-Byte XOR

The ciphertext is produced by XOR-ing each byte of the plaintext with a single repeated key byte.

**High-level decode algorithm (key unknown — brute-force):**

```
for key in range(0, 256):
    candidate = bytes(b ^ key for b in ciphertext)
    score = plaintext_score(candidate)
    candidates.append((score, key, candidate))

return max(candidates, key=lambda x: x[0])
```

The `plaintext_score` function (see [Plaintext Scoring](#plaintext-scoring)) drives key selection.

#### Multi-Byte XOR (Repeating Key)

Generalises single-byte XOR to a key of length K.

**Key length recovery:**

1. Compute the **normalised Hamming distance** between consecutive K-byte blocks of the ciphertext for K from 2 to `min(40, len(ciphertext) // 4)`.
2. The key length with the smallest normalised Hamming distance is the most likely K.

```
hamming_distance(a, b) = popcount(a XOR b)  # count of differing bits
normalised = hamming_distance(block1, block2) / K
```

3. Once K is identified, split ciphertext into K subsequences and solve each as a single-byte XOR problem.

---

### Compression-Based Decoding

CTF challenges occasionally encode data by compressing it and then hex- or Base64-encoding the result.

**High-level decode algorithm:**

1. Decode the outer encoding layer (Base64 or hex) to obtain raw bytes.
2. Inspect magic bytes to identify compression format (`\x1f\x8b` = gzip, `\x78\x9c` / `\x78\x01` / `\x78\xda` = zlib deflate).
3. Decompress with the appropriate algorithm, enforcing the output size limit.
4. Return the decompressed bytes.

The detection engine checks for these magic bytes after tentative Base64/hex decoding, which is why it often correctly identifies these as `base64+gzip` rather than just `base64`.

---

### Web & Text Encodings

#### URL Percent-Encoding

`%XX` sequences where `XX` is a hex byte value. The algorithm iterates the input, replacing `%XX` sequences with the corresponding byte. `+` is decoded as a space in `application/x-www-form-urlencoded` mode.

#### HTML Entities

Named (`&amp;`, `&lt;`, `&gt;`, `&quot;`, `&apos;`) and numeric (`&#65;`, `&#x41;`) HTML entities are replaced with their Unicode code points using Python's `html.unescape`.

#### Morse Code

The input is split on word separators (`/` or double-space). Each symbol sequence (`.` and `-`) maps to a letter via a fixed lookup table. Unknown sequences are preserved as `?`.

---

## Brute-Force Mode

When no single decoder produces a convincing plaintext, brute-force mode performs an exhaustive search.

**Algorithm overview:**

```
function brute_force(input, max_depth, top_k):
    queue = PriorityQueue()
    queue.push((score(input), [], input))  # (score, chain_so_far, current_bytes)

    results = []

    while queue is not empty and explored < MAX_NODES:
        score, chain, current = queue.pop()

        for codec in registry.all_codecs():
            if codec in chain:
                continue  # avoid trivial cycles (e.g. ROT13 twice)
            try:
                next_bytes = codec.decode(current)
            except DecodeError:
                continue

            next_score = plaintext_score(next_bytes)
            next_chain = chain + [codec.name]

            if looks_like_flag(next_bytes):
                results.append((next_score, next_chain, next_bytes))

            if len(next_chain) < max_depth:
                queue.push((next_score, next_chain, next_bytes))

    return top_k_by_score(results)
```

This is essentially a **best-first search** over the space of decoder chains, guided by the plaintext score. The priority queue ensures that promising intermediate decodings are explored first.

**Pruning strategies:**

- Skip codec if its character set precondition fails on the current bytes (fast pre-check).
- Skip codec if it is the inverse of the last applied codec (e.g. do not apply ROT13 twice in a row — that is a no-op).
- Terminate a branch if the output entropy exceeds 7.5 (likely still encrypted/compressed, not a dead end but deprioritised).

---

## Plaintext Scoring

The plaintext scorer assigns a quality score to a byte sequence, estimating how likely it is to be meaningful output (English text, source code, a flag string).

**Scoring components (weighted sum):**

| Component | Weight | Description |
|---|---|---|
| Printable ASCII ratio | 0.30 | Fraction of bytes in printable ASCII range (0x20–0x7E) |
| English letter frequency | 0.25 | Pearson correlation with expected English letter frequencies (ETAOIN SHRDLU ordering) |
| Common bigram frequency | 0.15 | How many common English bigrams (TH, HE, IN, ER, AN …) appear |
| Word match ratio | 0.20 | Fraction of space-separated tokens found in a 10k English word list |
| Flag pattern match | +0.50 (additive bonus) | Hard boost if output matches a known flag regex |

The final score is normalised to `[0, 1]`. A score above 0.6 is considered "likely plaintext"; above 0.85 is "strong plaintext hit".

---

## Flag Detection

After decoding, the `FlagDetector` scans the output for strings matching known CTF flag formats:

```python
FLAG_PATTERNS = [
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"DUCTF\{[^}]+\}",
    r"[A-Z]{2,8}\{[A-Za-z0-9_\-!@#$%^&*]+\}",  # generic format
]
```

Matches are annotated in the output with their position and the matched string. The `--flag-pattern` CLI argument and the `FLAG_PATTERN` environment variable allow custom patterns to be added without modifying source code.

---

## Plugin API

To add a custom decoder, subclass `BaseDecoder` and register it via the entry-point mechanism described in [System Architecture](SYSTEM_ARCHITECTURE.md#5-plugin-system).

```python
from ctf_decoder.decoders.base import BaseDecoder, DecodeError

class PigLatinDecoder(BaseDecoder):
    name = "pig_latin"
    aliases = ["piglatin", "pig-latin"]
    description = "Reverses basic Pig Latin encoding"

    # Optional: hints to the detection engine
    entropy_range = (3.5, 5.0)
    charset_hint = r"[A-Za-z\s]"

    def decode(self, data: bytes) -> bytes:
        text = data.decode("utf-8")
        words = []
        for word in text.split():
            if word.endswith("ay") and len(word) > 2:
                # Naive reversal: move first consonant cluster back
                core = word[:-2]
                words.append(core[1:] + core[0])
            else:
                words.append(word)
        return " ".join(words).encode("utf-8")

    def can_decode(self, data: bytes) -> float:
        """Return a confidence score [0, 1] that this decoder applies."""
        text = data.decode("utf-8", errors="replace")
        ay_words = sum(1 for w in text.split() if w.lower().endswith("ay"))
        ratio = ay_words / max(len(text.split()), 1)
        return min(ratio * 2, 1.0)
```

The optional `can_decode` method integrates the plugin into the detection engine. It is called during the heuristic scoring phase and its return value contributes to the candidate score for this codec.

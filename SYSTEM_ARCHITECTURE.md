# System Architecture

> CTF Decoder — Technical Architecture Reference

---

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Component Map](#component-map)
- [Layer Breakdown](#layer-breakdown)
  - [Interface Layer](#1-interface-layer)
  - [Orchestration Layer](#2-orchestration-layer)
  - [Detection Engine](#3-detection-engine)
  - [Decoder Registry](#4-decoder-registry)
  - [Plugin System](#5-plugin-system)
  - [Output Layer](#6-output-layer)
- [Data Flow](#data-flow)
- [Module Structure](#module-structure)
- [Technology Stack](#technology-stack)
- [Scalability Considerations](#scalability-considerations)

---

## Architectural Overview

CTF Decoder follows a **layered pipeline architecture** with a clean separation between input handling, detection, decoding, and output formatting. The design is intentionally modular — each layer communicates through well-defined interfaces, making it straightforward to add new decoders, swap detection strategies, or extend the output layer without touching core logic.

```
┌─────────────────────────────────────────────────────────┐
│                     INTERFACE LAYER                     │
│           CLI (Click)    │    Web UI (FastAPI)          │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  ORCHESTRATION LAYER                    │
│        Pipeline Manager  │  Chain Resolver              │
└───────────────────────────┬─────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
┌─────────────────────┐     ┌─────────────────────────────┐
│   DETECTION ENGINE  │     │       DECODER REGISTRY      │
│  Pattern Classifier │     │  30+ built-in decoders +    │
│  Entropy Analyzer   │     │  Plugin loader              │
│  Heuristic Scorer   │     └─────────────────────────────┘
└─────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│                     OUTPUT LAYER                        │
│    Formatter   │   Flag Detector   │   Result Ranker    │
└─────────────────────────────────────────────────────────┘
```

---

## Component Map

| Component | Responsibility | Location |
|---|---|---|
| `CLI` | Entry point for terminal usage | `ctf_decoder/cli/` |
| `WebServer` | FastAPI app serving the UI and REST API | `ctf_decoder/web/` |
| `PipelineManager` | Orchestrates single and chained decode runs | `ctf_decoder/core/pipeline.py` |
| `ChainResolver` | Parses and validates decoder chain strings | `ctf_decoder/core/chain.py` |
| `DetectionEngine` | Identifies likely encodings from raw input | `ctf_decoder/detection/` |
| `DecoderRegistry` | Holds all registered decoders, built-in and plugin | `ctf_decoder/registry.py` |
| `BaseDecoder` | Abstract interface all decoders implement | `ctf_decoder/decoders/base.py` |
| `PluginLoader` | Discovers and loads third-party decoder plugins | `ctf_decoder/plugins/loader.py` |
| `FlagDetector` | Scans output for CTF flag patterns | `ctf_decoder/output/flag_detector.py` |
| `ResultRanker` | Scores and ranks candidate decodings | `ctf_decoder/output/ranker.py` |
| `OutputFormatter` | Serialises results to text, JSON, or HTML | `ctf_decoder/output/formatter.py` |

---

## Layer Breakdown

### 1. Interface Layer

The interface layer provides two entry points into the system. Both ultimately construct a `DecodeRequest` object and hand it to the `PipelineManager`.

**CLI (`ctf_decoder/cli/`)**

Built with [Click](https://click.palletsprojects.com/). Each subcommand (`decode`, `brute`, `chain`, `list`, etc.) maps to a thin wrapper that validates arguments and delegates to the orchestration layer. The CLI is fully testable — all side effects (printing, file I/O) are injected via dependency injection.

**Web Server (`ctf_decoder/web/`)**

A [FastAPI](https://fastapi.tiangolo.com/) application that exposes:
- `POST /api/decode` — single-shot decode
- `POST /api/chain` — chained decode
- `POST /api/brute` — brute-force decode
- `GET /api/codecs` — list available decoders
- `GET /` — serves the static web UI (Vue 3, built to `web/static/`)

The web server is stateless. No session state is stored server-side; the frontend maintains its own decode history in `localStorage`.

---

### 2. Orchestration Layer

**`PipelineManager`**

The central coordinator. Given a `DecodeRequest`, it:

1. Calls the `DetectionEngine` (unless a codec is explicitly specified).
2. Resolves the target decoder(s) from the `DecoderRegistry`.
3. Executes the decode pass (or chain of passes).
4. Passes results to the `OutputLayer`.

For chained decoding, the output of each decoder becomes the input of the next. If any step fails, the pipeline records the failure and (depending on `strict_mode`) either aborts or continues with the next candidate.

**`ChainResolver`**

Parses chain specification strings (e.g. `"base64,hex,rot13"`) into an ordered list of `BaseDecoder` instances. Validates that each named codec exists in the registry before execution begins, providing early and clear error messages.

---

### 3. Detection Engine

The detection engine is the most algorithmically interesting component. It is covered in depth in [Core Concepts & Decoding Algorithms](CORE_CONCEPTS.md), but structurally it consists of three cooperating sub-systems:

**`PatternClassifier`**

Runs a series of regular-expression and structural tests against the input (character set analysis, padding characters, length constraints). Produces a list of candidate codec names with initial confidence scores.

**`Machine Learning Ensemble (RF + ET)`**

Extracts a 276-dimensional numerical statistic vector and character-level bigram/trigram n-grams (via `TfidfVectorizer`). Trains a high-capacity custom ensemble composed of Random Forest and Extra Trees classifiers to accurately identify complex, nested encodings with flag signatures and noise embeddings.

**`Structural Fingerprint Generator`**

Computes a 32-dimensional float vector capturing Shannon entropy, byte-value histograms, character class ratios, bigram/trigram entropy, gap spacings, run length statistics, and presence flags for similarity-based retrieval.

**`EntropyAnalyzer`**

Computes the Shannon entropy of the input byte sequence and compares it against known entropy profiles for each encoding type. High entropy (close to 8.0 bits/byte) suggests encryption or compression; low entropy suggests human-readable or structured encoding.

**`HeuristicScorer`**

Combines pattern classifier output, entropy scores, ML ensemble predictions, and additional heuristics into a final ranked list of candidates.

---

### 3b. Autopilot Guided Search

The orchestration layer contains the `run_autopilot` function, which performs a depth-first search (DFS) over potential decode paths guided by high-confidence ML probabilities and heuristics. It automatically resolves recursive multi-layered ciphers and terminates immediately when a valid flag pattern is detected.

---

### 3c. Complex Challenge Solver

The `ChallengeSolver` in `ctf_decoder/core/solver.py` parses complex, noisy CTF inputs (such as files containing arbitrary logs, scripts, or garbage text) to isolate hidden encoded structures. It:
1. Employs regex patterns to detect potential Base64, Hex, binary, Morse, octal, or URL encoded blocks.
2. Extracts matching substrings and filters duplicates.
3. Automatically launches the autopilot depth-first guided search on each extracted candidate to resolve nested multi-layered ciphers.
4. Returns all successfully solved targets along with their full decode chains.

---

### 3d. Code Script Solver

The `CodeSolver` in `ctf_decoder/core/code_solver.py` processes pasted source scripts (Python, C, Java) to decode target flags. It operates in two modes:
1. **Static Analysis Mode**:
   - Parses code files to isolate string literals, character lists, hex sequences, comments, and variables.
   - De-duplicates the extracted constants and passes each of them to the `ChallengeSolver` for recursive decoding.
2. **Dynamic Execution Mode**:
   - Safely compiles (if C/Java and compilers are available) or runs (for Python) the script in a temporary isolated environment.
   - Captures the script's `stdout` and feeds the output stream to the `ChallengeSolver` to search for encoded flags.
   - Returns execution logs, compilation errors, and all resolved flags.

---

### 4. Decoder Registry

A singleton `DecoderRegistry` manages all available decoders. At startup it auto-discovers and instantiates all built-in decoder classes from `ctf_decoder/decoders/`. Plugins are loaded separately via the `PluginLoader` and registered into the same registry.

```python
# Registry lookup is O(1)
decoder = registry.get("base64")
result = decoder.decode(input_bytes)
```

Each decoder is keyed by a canonical name (e.g. `"base64"`) and optional aliases (e.g. `"b64"`, `"base-64"`). The registry resolves aliases transparently.

---

### 5. Plugin System

Third-party decoders are distributed as Python packages that declare an entry point in the `ctf_decoder.plugins` group:

```toml
# In the plugin's pyproject.toml
[project.entry-points."ctf_decoder.plugins"]
mycipher = "my_package.decoder:MyCipherDecoder"
```

At startup, `PluginLoader` iterates all registered entry points, loads each class, validates it against the `BaseDecoder` interface, and registers it in the `DecoderRegistry`. Plugin decoders are indistinguishable from built-in ones at runtime.

---

### 6. Output Layer

**`ResultRanker`**

After decoding, produces a `DecodeResult` containing one or more candidate plaintext strings. Each candidate is scored by the `ResultRanker`, which evaluates:
- Printable ASCII ratio
- English language bigram/trigram frequency (for cipher outputs)
- Flag pattern match (hard boost)
- Entropy of the output (lower is generally better for plaintext)

**`FlagDetector`**

Scans the ranked output for strings matching CTF flag patterns. Default patterns cover common formats; custom patterns can be provided via `--flag-pattern`.

**`OutputFormatter`**

Renders the final `DecodeResult` into the requested format: pretty-printed terminal text, JSON, or HTML (for the web UI).

---

## Data Flow

```
User Input (string / bytes)
        │
        ▼
  DecodeRequest (immutable dataclass)
        │
        ├──► DetectionEngine ──► CandidateList (ranked codec names)
        │
        ▼
  PipelineManager selects codec(s)
        │
        ▼
  Decoder.decode(input_bytes) ──► raw output bytes
        │
   [if chained, repeat for next decoder]
        │
        ▼
  ResultRanker ──► scored candidates
        │
        ▼
  FlagDetector ──► flag annotations
        │
        ▼
  OutputFormatter ──► final rendered output
        │
        ▼
  CLI stdout / HTTP JSON response / Web UI render
```

---

## Module Structure

```
ctf_decoder/
├── cli/
│   ├── __init__.py
│   ├── commands/
│   │   ├── decode.py
│   │   ├── brute.py
│   │   ├── chain.py
│   │   └── list.py
│   └── main.py
│
├── core/
│   ├── pipeline.py        # PipelineManager
│   ├── solver.py          # ChallengeSolver
│   ├── code_solver.py     # CodeSolver
│   ├── chain.py           # ChainResolver
│   ├── request.py         # DecodeRequest dataclass
│   └── exceptions.py
│
├── detection/
│   ├── engine.py          # DetectionEngine (orchestrates sub-systems)
│   ├── pattern.py         # PatternClassifier
│   ├── entropy.py         # EntropyAnalyzer
│   └── scorer.py          # HeuristicScorer
│
├── decoders/
│   ├── base.py            # BaseDecoder ABC
│   ├── binary/            # base64, hex, octal, binary, base32 …
│   ├── classical/         # rot13, caesar, vigenere, atbash …
│   ├── web/               # url, html_entities, unicode_escape …
│   ├── xor/               # single_byte_xor, multi_byte_xor …
│   └── compression/       # zlib, gzip …
│
├── plugins/
│   └── loader.py          # PluginLoader
│
├── output/
│   ├── ranker.py          # ResultRanker
│   ├── flag_detector.py   # FlagDetector
│   └── formatter.py       # OutputFormatter
│
├── registry.py            # DecoderRegistry singleton
│
└── web/
    ├── app.py             # FastAPI application
    ├── routes/
    └── static/            # Built Vue 3 frontend
```

---

## Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| CLI | Python 3.10+, Click | Ergonomic subcommand structure, testable |
| Web API | FastAPI | Async, auto-generated OpenAPI docs, fast |
| Web Frontend | Vue 3 + Vite | Lightweight, no build tooling lock-in |
| Detection | Pure Python (stdlib + `regex`) | Zero heavy dependencies for core logic |
| Language scoring | `nltk` (optional) | Bigram frequency tables for plaintext scoring |
| Testing | pytest + hypothesis | Property-based testing for decoder correctness |
| Packaging | pyproject.toml + Hatch | Modern Python packaging, entry-point plugins |
| Container | Docker (Alpine base) | Small image for CI/CTF server deployment |

---

## Scalability Considerations

CTF Decoder is primarily a local tool, but the web server mode has some considerations worth noting:

- **Stateless API** — Each request is independent. Horizontal scaling behind a load balancer requires no shared state.
- **Brute-force throttling** — Brute-force endpoints are CPU-intensive. In multi-user deployments, consider rate limiting via a reverse proxy (nginx, Caddy) or the built-in `--brute-workers` flag to limit parallelism.
- **Plugin isolation** — Plugins execute in the same process. A malicious or buggy plugin can crash the server. For untrusted plugins, consider running the decoder worker in a subprocess with resource limits.
- **Input size limits** — The web API enforces a configurable `MAX_INPUT_BYTES` limit (default 1 MB) to prevent DoS via large inputs in compression or brute-force modes.

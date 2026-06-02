<div align="center">

<!-- Logo / Banner -->
<img src="https://raw.githubusercontent.com/SKYLINE217/CTF-Decoder/main/docs/banner.png" alt="CTF Decoder" width="100%" onerror="this.style.display='none'">

<h1>
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=32&pause=1000&color=0A84FF&center=true&vCenter=true&width=600&lines=CTF+Decoder;Adaptive+Heuristic+Engine;Crack+Any+Flag." alt="CTF Decoder">
</h1>

<p align="center">
  <strong>A self-learning, modular decoding engine built for CTF competitors.<br>Detect, decode, and crack flags faster than ever before.</strong>
</p>

<br/>

<!-- Badges -->
<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-0.104%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/Deployed%20on-Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Version-0.1.0-orange?style=for-the-badge" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Decoders-30%2B-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/Adaptive-Beta--Binomial%20Engine-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/UI-macOS%20Sequoia%20Style-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/Solver-Python%20%7C%20C%20%7C%20Java-orange?style=flat-square" />
</p>

</div>

---

## ⚡ What Is CTF Decoder?

**CTF Decoder** is a professional-grade, self-learning decoding suite designed for Capture The Flag competitions and security research. It goes beyond a simple decoder: it studies your solving patterns, adapts its confidence models over time, and gives you a beautiful macOS-style web interface to operate from.

> Drop in any encoded payload — Base64, Hex, XOR, Gzip, Morse, or a multi-layered chain — and the engine tells you exactly what it is, decodes it, and flags any CTF patterns it finds.

---

## 🗺️ Table of Contents

- [Features at a Glance](#-features-at-a-glance)
- [Project Architecture](#-project-architecture)
- [Adaptive Heuristic Engine](#-adaptive-heuristic-engine)
- [Supported Codecs](#-supported-codecs)
- [Code Script Solver](#-code-script-solver)
- [REST API Reference](#-rest-api-reference)
- [Web Interface](#-web-interface)
- [Local Development Setup](#-local-development-setup)
- [Vercel Deployment](#-vercel-deployment)
- [Running Tests](#-running-tests)
- [Tech Stack](#-tech-stack)

---

## 🔥 Features at a Glance

| Feature | Details |
|---|---|
| 🧠 **Adaptive Detection** | Beta-Binomial Bayesian priors update after every solve |
| 🔗 **Chained Decoding** | Multi-layer chains automatically explored and scored |
| 💥 **Brute Force Mode** | Best-first exhaustive search across all codec combinations |
| 🖥️ **Code Script Solver** | Solves Python, C, and Java scripts via static + dynamic analysis |
| 🚩 **Flag Detection** | Auto-matches `FLAG{}`, `CTF{}`, `picoCTF{}` and custom patterns |
| 📊 **Plaintext Scoring** | Ranks candidates by ASCII ratio, bigrams, and English word frequency |
| 🔄 **Live Detection** | Real-time codec probability hints as you type |
| 💾 **Memory Store** | Session-persistent prior database with SQLite + JSONL event log |
| 🎨 **macOS UI** | Glassmorphic Sequoia/Sonoma-style desktop workspace |
| ☁️ **Serverless** | Vercel-ready with read-only FS failover and lazy ML imports |

---

## 🏗️ Project Architecture

```
ctf-decoder/
├── api/                        # Vercel serverless entrypoint
│   └── index.py
├── ctf_decoder/
│   ├── adaptive/
│   │   └── memory.py           # Beta-Binomial adaptive memory (SQLite + JSONL)
│   ├── cli/
│   │   └── main.py             # Click-based CLI
│   ├── core/
│   │   ├── bruteforce.py       # Best-first brute-force search
│   │   ├── chain.py            # Decoder chain management
│   │   ├── code_solver.py      # Python / C / Java script solver
│   │   ├── pipeline.py         # Orchestration layer
│   │   └── solver.py           # Challenge pattern matcher & solver
│   ├── decoders/
│   │   ├── binary/             # Base64, Hex, Binary, Octal
│   │   ├── classical/          # ROT13, Atbash, Morse, AlphaHex
│   │   ├── crypto/             # XOR (single & multi-byte)
│   │   ├── archive/            # Gzip, Zlib, Bzip2
│   │   └── web/                # URL percent-encoding
│   ├── detection/
│   │   ├── engine.py           # Heuristic detection orchestrator
│   │   └── ml_model.py         # Probabilistic + ML scoring model
│   ├── output/
│   │   ├── flag_detector.py    # Regex flag pattern matcher
│   │   ├── formatter.py        # Rich text / JSON output formatter
│   │   └── ranker.py           # Plaintext quality ranker
│   ├── plugins/                # Custom decoder plugin directory
│   ├── registry.py             # Codec registry & loader
│   └── web/
│       ├── app.py              # FastAPI application & REST routes
│       └── static/
│           ├── index.html      # Vue 3 single-page application
│           └── style.css       # macOS Sequoia glass design system
├── pyproject.toml
├── requirements.txt
├── vercel.json
└── tests/
```

---

## 🧠 Adaptive Heuristic Engine

The detection engine is built on two complementary layers:

### 1. Structural Heuristics
Each decoder registers its own fingerprinting rule set:
- **Entropy analysis** — Shannon entropy windows over 4-byte sliding blocks
- **Character set constraints** — valid alphabet checks (e.g., Base64 charset, hex pairs)
- **Byte-range validation** — null byte detection, printable ASCII ratios, BOM markers
- **Length constraints** — padding alignment checks for Base64, modular hex length

### 2. Beta-Binomial Adaptive Priors
After every successful or failed decode, the memory store updates a **Beta distribution** per codec:

```
α_new = α_old + 1   (on success)
β_new = β_old + 1   (on failure)

E[θ] = α / (α + β)  → expected success probability
```

This means the engine learns from your CTF session history. Codecs you've successfully used more often get ranked higher in future detection runs. Priors decay over time to prevent overfitting to stale history.

### 3. Plaintext Validation
After decoding, output is scored on four metrics:

| Metric | Weight | Description |
|---|---|---|
| `printable_ascii` | 35% | Ratio of printable ASCII characters in output |
| `english_freq` | 30% | Letter frequency deviation from English distribution |
| `bigram_freq` | 20% | Common English bigram match rate |
| `word_match` | 15% | Hit rate against a common English word dictionary |

Candidates scoring above **0.85** are marked green; between **0.60–0.85** as orange; below as red.

---

## 📡 Supported Codecs

| Category | Codecs |
|---|---|
| **Binary Encoding** | Base64, Base64-URL, Base32, Base85, Base16 (Hex), Binary, Octal |
| **Classical Ciphers** | ROT13, ROT-N (all rotations), Atbash, Morse Code, AlphaHex |
| **Crypto / XOR** | XOR single-byte (auto key-search), XOR multi-byte |
| **Compression** | Gzip (detect + decompress), Zlib / Deflate, Bzip2 |
| **Web Encoding** | URL percent-encoding, HTML entities |
| **Flag Patterns** | `FLAG{}`, `CTF{}`, `picoCTF{}`, `HTB{}`, `DUCTF{}`, `TMUCTF{}`, Custom regex |

---

## 🖥️ Code Script Solver

The **Code Script Solver** handles CTF challenges where the flag is hidden inside source code rather than a raw encoded string.

### How It Works

```
Input Script (Python / C / Java)
        │
        ├── Static Analysis
        │     ├── Extract quoted string literals
        │     ├── Parse hex constants (0xAB1234...)
        │     ├── Extract byte arrays and char arrays
        │     └── Scan inline comments for embedded values
        │
        └── Dynamic Execution (optional)
              ├── Run in isolated subprocess (5s timeout)
              ├── Capture stdout + stderr
              └── Feed output → Adaptive Decoder Engine
                        │
                        └── → Flag Match → Report
```

### Supported Languages

| Language | Static Extraction | Dynamic Execution | Compiler Required |
|---|---|---|---|
| **Python** | ✅ | ✅ | None (uses `sys.executable`) |
| **C / C++** | ✅ | ✅ | `gcc` or `clang` |
| **Java** | ✅ | ✅ | `javac` + `java` JDK |

---

## 🔌 REST API Reference

All endpoints are hosted at `/api/`. The API is rate-limited via `slowapi`.

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/decode` | Decode payload — auto-detect or specify codec |
| `POST` | `/api/brute` | Best-first brute-force across all codec chains |
| `POST` | `/api/detect` | Return ranked codec candidates without decoding |
| `POST` | `/api/solve_code` | Solve an embedded script (Python, C, Java) |
| `GET` | `/api/codecs` | List all registered decoder codec IDs |
| `GET` | `/api/memory` | Return full adaptive memory snapshot |
| `POST` | `/api/feedback` | Submit explicit feedback to update priors |
| `POST` | `/api/memory/decay` | Apply time-based confidence decay to all priors |
| `POST` | `/api/memory/clear` | Wipe all learned prior data |

### Example — Auto Decode

```bash
curl -X POST http://localhost:8000/api/decode \
  -H "Content-Type: application/json" \
  -d '{"data_b64": "SGVsbG8gV29ybGQ=", "mode": "auto"}'
```

```json
{
  "success": true,
  "codec": "base64",
  "final_output_str": "Hello World",
  "score": { "total": 0.97, "printable_ascii": 1.0, "english_freq": 0.91 },
  "flags": [],
  "steps": [{ "codec": "base64", "output_str": "Hello World" }],
  "elapsed": 0.003
}
```

---

## 🎨 Web Interface

The web workspace is a fully self-contained Vue 3 SPA with a macOS Sequoia-style glassmorphic design.

### Panels

**① Auto / Manual Decoders**
- Paste raw bytes into the editor and get live codec probability hints as you type
- Choose between **Auto**, **Manual** (select codec), or **Brute Force** mode
- Results show the decoded plaintext, full decode chain, plaintext quality score breakdown, and any detected flags
- Send thumbs-up / thumbs-down feedback to update adaptive priors in real time

**② Code Script Solver**
- Paste Python, C, or Java source code
- Toggle **Execute Code** to run it dynamically in a sandboxed subprocess
- Define a custom flag pattern regex for proprietary CTF flag formats
- Results display resolved flags, execution logs, and all statically extracted string literals

**③ Adaptive Memory Store**
- View the full Beta-Binomial prior table with alpha/beta values and last-updated timestamps
- See session statistics: solve count, session ID, platform guess
- Inspect learned codec chain templates sorted by frequency and success rate
- Apply **time decay** or **wipe the memory store** to reset learning state

### Desktop Widgets
Two macOS Sequoia-style widgets appear on the desktop behind the main window:
- **🕐 Clock Widget** — Live time, AM/PM, weekday and date
- **⚡ Engine Widget** — Real-time learned prior count and detected platform hint

---

## 🚀 Local Development Setup

### Prerequisites

- Python **3.10+**
- pip

### Install

```bash
git clone https://github.com/SKYLINE217/CTF-Decoder.git
cd CTF-Decoder
pip install -r requirements.txt
```

### Run the Dev Server

```bash
python -m uvicorn ctf_decoder.web.app:app --port 8000 --host 127.0.0.1 --reload
```

Open **http://127.0.0.1:8000** in your browser.

### Install with Full Dev Tooling

```bash
pip install -e ".[dev]"
```

---

## ☁️ Vercel Deployment

The project is pre-configured for serverless deployment on Vercel.

### Configuration (`vercel.json`)

```json
{
  "rewrites": [{ "source": "/(.*)", "destination": "/api/index" }]
}
```

### Serverless Optimizations Applied

| Problem | Solution |
|---|---|
| Read-only filesystem | `memory.py` falls back to `:memory:` SQLite automatically |
| Cold-start latency | Heavy ML packages (`numpy`, `scipy`) loaded lazily on first use |
| Static file serving | CSS/JS MIME types explicitly registered via `mimetypes` module |
| Entrypoint detection | `api/index.py` exports the FastAPI `app` at the root level |

### Deploy

Push to `main` — Vercel auto-deploys from GitHub:

```bash
git push origin main
```

---

## 🧪 Running Tests

```bash
# Decoder unit tests (Base64, Hex, ROT13, XOR, Gzip, etc.)
python test_decoders.py

# Code solver tests (static extraction + dynamic execution)
python test_solver.py

# API endpoint integration tests
python test_api.py

# Code solver edge cases
python test_code_solver.py
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.10+, FastAPI, Uvicorn, SlowAPI |
| **Frontend** | Vue 3 (CDN), Vanilla CSS, Google Fonts (Inter + Fira Code) |
| **Database** | SQLite (persistent) → in-memory fallback on serverless |
| **Validation** | Pydantic v2 |
| **Rate Limiting** | SlowAPI |
| **Build / Package** | Hatchling, pyproject.toml |
| **Deployment** | Vercel Serverless Functions (Python runtime) |
| **Dev Tooling** | Ruff, MyPy, Pytest, Bandit, Hypothesis |

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for full text.

---

<div align="center">

**Built for the CTF community.**  
*Crack the flags. Learn the techniques. Ship it anywhere.*

<br/>

[![GitHub Stars](https://img.shields.io/github/stars/SKYLINE217/CTF-Decoder?style=social)](https://github.com/SKYLINE217/CTF-Decoder)
&nbsp;&nbsp;
[![GitHub Forks](https://img.shields.io/github/forks/SKYLINE217/CTF-Decoder?style=social)](https://github.com/SKYLINE217/CTF-Decoder/fork)

</div>

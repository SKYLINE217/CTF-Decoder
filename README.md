# 🚩 CTF Decoder — Capture The Flag Toolkit

> A modular, extensible decoding suite built for competitive Capture The Flag challenges. Supports 30+ encoding schemes, chained transformations, and automated cipher detection.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Supported Encodings & Ciphers](#supported-encodings--ciphers)
- [CLI Reference](#cli-reference)
- [Web Interface](#web-interface)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

CTF Decoder is a purpose-built tool for security researchers and CTF competitors who need to rapidly identify, decode, and transform encoded payloads encountered during challenges. Whether you're dealing with a simple Base64-encoded flag or a multi-layered combination of XOR, ROT13, and hex encoding, CTF Decoder automates detection and handles chained transformations in a single pass.

The application is designed around three core principles:

- **Speed** — Identify the encoding scheme in milliseconds, not minutes.
- **Breadth** — Cover the full spectrum of encodings seen in real CTF competitions.
- **Composability** — Chain multiple decoders together in a Unix-style pipeline.

---

## Features

- **Auto-detection engine** — Probabilistic classifier identifies encoding type from raw input.
- **30+ decoders** — From classic ciphers to modern encoding standards.
- **Chained decoding** — Apply multiple transformations in sequence (`base64 | hex | rot13`).
- **Brute-force mode** — Exhaustively tries combinations when encoding is unknown.
- **Scoring & ranking** — Outputs candidate decodings ranked by plaintext likelihood.
- **CLI & Web UI** — Use interactively or integrate into scripts and pipelines.
- **Plugin API** — Register custom decoders without modifying core code.
- **CTF flag pattern matching** — Auto-highlights strings matching common flag formats (`FLAG{}`, `CTF{}`, `picoCTF{}`, etc.).

---

## Quick Start

```bash
# Install
pip install ctf-decoder

# Decode a single string (auto-detect mode)
ctfdec decode "SGVsbG8gV29ybGQ="

# Output:
# [✓] Base64 detected (confidence: 98.3%)
# Decoded: Hello World
```

---

## Installation

### Requirements

- Python 3.10+
- pip or pipx

### From PyPI

```bash
pip install ctf-decoder
```

### From Source

```bash
git clone https://github.com/your-org/ctf-decoder.git
cd ctf-decoder
pip install -e ".[dev]"
```

### Docker

```bash
docker pull yourorg/ctf-decoder:latest
docker run -it yourorg/ctf-decoder decode "NzQgNjUgNzMgNzQ="
```

---

## Usage

### Auto-Detect Mode

```bash
ctfdec decode "<encoded_string>"
```

### Specify Decoder Explicitly

```bash
ctfdec decode --codec base64 "SGVsbG8="
ctfdec decode --codec hex "48656c6c6f"
ctfdec decode --codec rot13 "Uryyb"
```

### Chained Decoding

```bash
# Pipe decoders in sequence
ctfdec decode --chain "base64,hex,rot13" "U0c5c2JHOD0="

# Or use the interactive chain builder
ctfdec chain
```

### Brute-Force Mode

```bash
ctfdec brute "U2FsdGVkX1..."
```

### Read from File

```bash
ctfdec decode --file encoded.txt
cat encoded.txt | ctfdec decode -
```

---

## Supported Encodings & Ciphers

| Category | Supported Schemes |
|---|---|
| **Binary Encoding** | Base64, Base32, Base58, Base85, Base16 (Hex), Binary, Octal |
| **Classic Ciphers** | ROT13, ROT-N (all), Caesar, Vigenère, Atbash, Rail Fence, Columnar Transposition |
| **Hash / Checksums** | MD5, SHA-1, SHA-256, CRC32 (identify only) |
| **URL / Web** | URL Encoding (percent-encode), HTML Entities, Unicode escapes |
| **Text Encoding** | ASCII, Morse Code, NATO Phonetic Alphabet, Braille |
| **Substitution** | Bacon's Cipher, Pigpen, T9/Phone keypad |
| **XOR / Bitwise** | XOR (single-byte & multi-byte), NOT, bit rotation |
| **Compression** | zlib (deflate), gzip (detect + decompress) |
| **Modern** | JWT (decode payload), Base64url, MIME quoted-printable |

---

## CLI Reference

```
ctfdec [COMMAND] [OPTIONS] [INPUT]

Commands:
  decode      Decode an encoded string (auto-detect or specify codec)
  encode      Encode a string using a specified codec
  brute       Brute-force unknown encoding
  chain       Interactively build a decoder chain
  list        List all available codecs
  detect      Run detection only (no decoding)
  plugin      Manage custom decoder plugins

Options:
  -c, --codec TEXT     Encoding scheme to use
  --chain TEXT         Comma-separated list of codecs to apply in order
  -f, --file PATH      Read input from file
  -o, --output PATH    Write output to file
  --json               Output results as JSON
  --flag-pattern TEXT  Custom regex pattern for flag detection
  -v, --verbose        Show detection scores and debug info
  -h, --help           Show this message and exit
```

---

## Web Interface

Start the local web server:

```bash
ctfdec serve --port 8080
```

Then open `http://localhost:8080` in your browser. The web UI provides:

- Paste-and-decode input panel
- Visual decoder chain builder (drag-and-drop)
- Side-by-side input/output view
- History of decoded strings in the current session
- Export results as JSON or plain text

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

To add a new decoder, implement the `BaseDecoder` interface and register it as a plugin — see [Core Concepts](CORE_CONCEPTS.md#plugin-api) for details.

```bash
# Run the test suite
pytest tests/

# Run linting
ruff check . && mypy .
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built for the CTF community. Crack the flags, learn the techniques. Deployable on Vercel.*


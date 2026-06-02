# Security

> CTF Decoder — Security Model, Threat Analysis & Hardening Guide

---

## Table of Contents

- [Security Philosophy](#security-philosophy)
- [Threat Model](#threat-model)
- [Attack Surface Analysis](#attack-surface-analysis)
- [Input Validation & Sanitisation](#input-validation--sanitisation)
- [Plugin Security](#plugin-security)
- [Web Server Hardening](#web-server-hardening)
- [CLI Security Considerations](#cli-security-considerations)
- [Secrets & Sensitive Data Handling](#secrets--sensitive-data-handling)
- [Dependency Security](#dependency-security)
- [Security Configuration Reference](#security-configuration-reference)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Security Philosophy

CTF Decoder is a local-first tool. In its default configuration (CLI, no server), it has minimal attack surface — it processes user-supplied text and writes output to stdout. The expanded attack surface introduced by `ctfdec serve` (the web server mode) demands a higher level of scrutiny, particularly when deployed on a shared or Internet-facing host.

The security model is built on three principles:

1. **Never trust input.** All user-supplied data is treated as potentially hostile before being passed to any decoder.
2. **Principle of least privilege.** The application requests no permissions it does not need. Plugins are declared explicitly and loaded intentionally.
3. **Fail securely.** When a decoder errors or a validation check fails, the system returns a controlled error — it never surfaces raw exception tracebacks to the end user in production mode.

---

## Threat Model

### Assets to Protect

| Asset | Sensitivity | Notes |
|---|---|---|
| Host filesystem | High | Decode inputs must not be used as file paths |
| Host memory / CPU | Medium | Brute-force and compression bombs can exhaust resources |
| Decode history (web UI) | Low | Stored client-side only; no server-side persistence by default |
| Plugin code | High | Arbitrary Python executed in-process |

### Actors

| Actor | Trust Level | Description |
|---|---|---|
| Local user (CLI) | Trusted | Running the tool for their own CTF work |
| Web UI user (local) | Trusted | Single-user local server instance |
| Web UI user (shared server) | Semi-trusted | Multi-user CTF team deployment |
| Anonymous Internet user | Untrusted | Internet-facing deployment (not recommended without auth) |
| Plugin author | Untrusted by default | Third-party plugins must be reviewed before installation |

### Out of Scope

- Cryptographic key recovery (the tool decodes encodings; it does not break encryption keys).
- Compliance with any regulatory framework (this is a CTF tool, not a production security product).

---

## Attack Surface Analysis

### 1. Arbitrary Code Execution via Decoder Logic

**Risk:** A decoder processes attacker-controlled bytes. A vulnerable decoder (e.g. one using `eval`, `exec`, `pickle.loads`, or `yaml.load` on the input) could allow arbitrary code execution.

**Mitigation:**
- All built-in decoders are reviewed to ensure they never call `eval`, `exec`, `compile`, `pickle`, or `yaml.unsafe_load` on user input.
- Static analysis (`bandit`) is run in CI on all decoder code.
- Code review checklist explicitly flags any use of dynamic evaluation functions.

---

### 2. Compression Bomb / Decompression DoS

**Risk:** A zlib or gzip-compressed input may expand to gigabytes of data, exhausting memory and crashing the process.

**Mitigation:**
- All decompression operations apply a hard output size limit (`MAX_DECOMPRESS_BYTES`, default 10 MB).
- Streaming decompression is used where possible; the byte counter is checked incrementally.
- If the limit is exceeded, a `DecompressionLimitError` is raised and the decode attempt is aborted.

```python
# Enforced in ctf_decoder/decoders/compression/zlib_decoder.py
MAX_DECOMPRESS_BYTES = 10 * 1024 * 1024  # 10 MB

def decode(self, data: bytes) -> bytes:
    result = bytearray()
    decompressor = zlib.decompressobj()
    for chunk in _chunked(data, 65536):
        result.extend(decompressor.decompress(chunk))
        if len(result) > MAX_DECOMPRESS_BYTES:
            raise DecompressionLimitError(
                f"Decompressed output exceeded {MAX_DECOMPRESS_BYTES} bytes"
            )
    return bytes(result)
```

---

### 3. ReDoS (Regular Expression Denial of Service)

**Risk:** The detection engine uses regular expressions against user input. Pathological inputs could cause catastrophic backtracking.

**Mitigation:**
- All detection regexes are reviewed to avoid nested quantifiers and catastrophic backtracking patterns.
- The `regex` library (instead of `re`) is used where needed; it supports atomic groups and possessive quantifiers.
- A per-detection timeout of 500 ms is enforced via `signal.alarm` (POSIX) or a thread-based watchdog (Windows/macOS).
- Fuzzing with `hypothesis` and `atheris` targets the detection engine in CI.

---

### 4. Path Traversal (CLI `--file` flag)

**Risk:** A malicious or accidentally constructed file path could read arbitrary files from the system.

**Mitigation:**
- The `--file` argument is resolved to an absolute path before opening.
- Symbolic links are not followed by default (configurable with `--follow-symlinks`).
- In web server mode, the file upload API only accepts file content (not file paths on the server's filesystem). The server never reads from its own filesystem based on user-supplied paths.

---

### 5. Cross-Site Scripting (Web UI)

**Risk:** Decoded output rendered in the browser could contain malicious HTML or JavaScript, leading to XSS.

**Mitigation:**
- All decoded output is HTML-escaped before insertion into the DOM. The Vue 3 frontend uses template bindings (`{{ value }}`) rather than `v-html` for all user-controlled data.
- A strict Content Security Policy (CSP) is set by the FastAPI server:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none';
```

- `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY` headers are also set on all responses.

---

### 6. Server-Side Request Forgery (SSRF)

**Risk:** Not currently applicable. CTF Decoder does not make outbound network requests as part of decoding.

**Note:** If a future decoder requires network access (e.g. a DNS-based encoder), it must be gated behind an explicit `--allow-network` flag and must validate and restrict target URLs.

---

### 7. Plugin Code Execution

See the [Plugin Security](#plugin-security) section.

---

## Input Validation & Sanitisation

All inputs pass through a `RequestValidator` before reaching any decoder. The validator enforces:

| Check | Limit | Configurable |
|---|---|---|
| Input byte length | 1 MB (CLI), 1 MB (API) | `MAX_INPUT_BYTES` |
| Codec name format | `^[a-z0-9_-]{1,64}$` | No |
| Chain length | 20 steps maximum | `MAX_CHAIN_DEPTH` |
| File upload size (web) | 5 MB | `MAX_UPLOAD_BYTES` |
| Allowed MIME types (web upload) | `text/plain`, `application/octet-stream` | `ALLOWED_MIME_TYPES` |

Validation errors are returned as structured JSON error responses with a `4xx` status code. Raw Python exceptions are never surfaced to the client in production mode (`DEBUG=false`).

---

## Plugin Security

Plugins are third-party Python packages installed into the same environment as CTF Decoder. They execute with the same operating system permissions as the main process. This is a significant trust boundary.

### Risks

- A malicious plugin could exfiltrate data, execute arbitrary system commands, or modify the decoder registry.
- A buggy plugin could crash the process or exhaust resources.

### Mitigations

**Review before install.** There is no automated sandbox. Treat plugin installation with the same scrutiny as installing any Python package. Review the source code, check the maintainer's reputation, and pin to a specific version.

**Plugin allowlist.** In production/shared deployments, the `PLUGIN_ALLOWLIST` configuration option restricts which entry-point names are loaded:

```toml
# config.toml
[plugins]
allowlist = ["my_verified_plugin", "another_trusted_one"]
```

If `allowlist` is set, only plugins whose entry-point key matches an entry in the list are loaded. All others are silently skipped with a log warning.

**Resource limits.** When running the web server, consider wrapping the process in a systemd unit with `MemoryMax` and `CPUQuota` to limit the blast radius of a buggy plugin.

**Future work.** A subprocess-based plugin sandbox (using `multiprocessing` with resource limits and a restricted namespace) is on the roadmap.

---

## Web Server Hardening

### Do Not Expose to the Internet Without Authentication

The web server has no built-in authentication. It is designed for single-user local use or trusted-network team deployments. If you need to expose it externally:

1. Place it behind a reverse proxy (nginx, Caddy, Traefik).
2. Enable HTTP Basic Auth or OAuth2 at the proxy layer.
3. Use TLS (the application does not handle TLS termination itself).

### Recommended nginx Config Snippet

```nginx
server {
    listen 443 ssl;
    server_name ctfdec.internal;

    ssl_certificate     /etc/ssl/certs/ctfdec.crt;
    ssl_certificate_key /etc/ssl/private/ctfdec.key;

    auth_basic           "CTF Decoder";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Rate Limiting

The FastAPI app uses `slowapi` for rate limiting. Default limits:

| Endpoint | Rate Limit |
|---|---|
| `POST /api/decode` | 60 req/min per IP |
| `POST /api/brute` | 5 req/min per IP |
| `POST /api/chain` | 30 req/min per IP |

Adjust in `config.toml` under `[ratelimit]`.

### CORS

CORS is set to `allow_origins = ["http://localhost:*"]` by default. For shared deployments, update `CORS_ORIGINS` in `config.toml` to your specific origin. Never set `allow_origins = ["*"]` on an externally reachable instance.

---

## CLI Security Considerations

The CLI is a local tool. The main security considerations are:

- **Shell injection** — Do not construct `ctfdec` commands by interpolating untrusted strings into shell invocations. Use the Python API directly, or pass inputs via `--file` rather than positional arguments, to avoid shell word-splitting issues.
- **Output redirection** — Decoded output may contain binary data or control characters. Pipe through `cat -v` or use `--json` mode if you need to inspect output safely in a terminal.
- **Temporary files** — CTF Decoder does not write temporary files containing decode input or output. If you redirect output to a file, ensure appropriate filesystem permissions.

---

## Secrets & Sensitive Data Handling

CTF Decoder does not collect, log, or transmit any user data. Specifically:

- No telemetry or analytics.
- No network calls during decode operations.
- Decode history in the web UI is stored in the browser's `localStorage` only — it never leaves the client.
- Log output (when `--verbose` is used) is written to stdout/stderr only. Log files, if configured, should be treated with the same sensitivity as the input data.

If a decoded payload contains sensitive data (credentials, keys, PII encountered during a CTF challenge), handle it with appropriate care — clear your terminal history and browser localStorage after the session.

---

## Dependency Security

All dependencies are pinned in `requirements.lock`. A Dependabot configuration is included to open PRs for security updates automatically.

Run a dependency audit manually:

```bash
pip-audit
```

Known safe-to-ignore advisories (if any) are documented in `.pip-audit-ignore`.

---

## Security Configuration Reference

All security-relevant settings live in `config.toml` (or environment variables with the `CTFDEC_` prefix):

```toml
[security]
max_input_bytes      = 1048576   # 1 MB
max_decompress_bytes = 10485760  # 10 MB
max_chain_depth      = 20
detection_timeout_ms = 500
debug                = false     # Never enable in multi-user deployments

[plugins]
allowlist = []                   # Empty = load all installed plugins

[ratelimit]
decode_per_minute = 60
brute_per_minute  = 5
chain_per_minute  = 30

[cors]
origins = ["http://localhost:8080"]
```

---

## Reporting Vulnerabilities

If you discover a security vulnerability in CTF Decoder, please report it responsibly:

1. **Do not open a public GitHub issue.**
2. Email the maintainers at `security@your-org.example` with the subject line `[CTF Decoder] Security Vulnerability`.
3. Include a description of the issue, reproduction steps, and your assessment of impact.
4. We aim to acknowledge reports within 48 hours and provide a fix within 14 days for critical issues.

We follow a coordinated disclosure policy. Credit will be given in the release notes unless you prefer to remain anonymous.

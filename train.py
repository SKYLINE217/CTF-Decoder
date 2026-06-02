"""
CTF Decoder — Industrial Training Suite
========================================
Trains the adaptive engine at industrial scale:
  • Every decoder (single-step)
  • Every decoder (base64-wrapped)
  • Multi-layer chained scenarios
  • 4 platform profiles (picoCTF, HackTheBox, TryHackMe, DownUnderCTF)
  • Compression with raw binary AND base64-encoded blobs

Run:
    python train.py                # incremental
    python train.py --reset        # wipe memory and retrain from scratch
    python train.py --verbose      # show per-codec prior updates
"""

import os, sys, gzip, zlib, bz2, base64, urllib.parse, codecs, argparse
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from ctf_decoder.core.pipeline import PipelineManager, DecodeRequest
from ctf_decoder.adaptive.memory import memory_db, session
from ctf_decoder.output.flag_detector import FlagDetector


# ─────────────────────────────────────────────────────────────────────────────
# Encoding helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64(s: bytes) -> bytes:    return base64.b64encode(s)
def _hex(s: bytes) -> bytes:    return s.hex().encode()
def _hex_spaced(s: bytes) -> bytes: return b' '.join(s.hex()[i:i+2].encode() for i in range(0,len(s.hex()),2))
def _hex_0x(s: bytes) -> bytes: return b' '.join(f'0x{b:02x}'.encode() for b in s)
def _rot13(s: bytes) -> bytes:  return codecs.encode(s.decode(), 'rot_13').encode()
def _xor(s: bytes, k: int) -> bytes: return bytes([b ^ k for b in s])
def _url(s: bytes) -> bytes:    return urllib.parse.quote(s.decode()).encode()
def _oct(s: bytes) -> bytes:    return b' '.join(format(b, '03o').encode() for b in s)
def _bin8(s: bytes) -> bytes:   return b' '.join(format(b, '08b').encode() for b in s)
def _atbash(s: bytes) -> bytes:
    out = []
    for c in s.decode():
        if 'A' <= c <= 'Z': out.append(chr(ord('Z') - (ord(c)-ord('A'))))
        elif 'a' <= c <= 'z': out.append(chr(ord('z') - (ord(c)-ord('a'))))
        else: out.append(c)
    return ''.join(out).encode()
def _alphahex(s: bytes) -> bytes:
    return s.hex().translate(str.maketrans('abcdef','hijklm')).encode()


# ─────────────────────────────────────────────────────────────────────────────
# Industrial dataset — 60+ samples
# ─────────────────────────────────────────────────────────────────────────────

def build_dataset():
    D = []

    # ── Base64 variants ──────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{Base64_is_fun}", 4.0),
        (b"picoCTF{b4s3_64_m4st3r}", 3.0),
        (b"HTB{h4ck_th3_b0x}", 3.0),
        (b"THM{try_hack_me_b64}", 3.0),
        (b"DUCTF{down_under_b64}", 3.0),
        (b"CTF{decode_me_now_1234}", 2.5),
    ]:
        D.append({"name": f"[Base64] {flag.decode()}", "data": _b64(flag),
                  "codec": "base64", "expected": flag.decode(), "boost": boost})

    # ── Hex variants ─────────────────────────────────────────────────────────
    for flag, enc_fn, label, boost in [
        (b"CTF{Hex_Is_Nice}", _hex, "compact", 4.0),
        (b"CTF{spaced_hex}", _hex_spaced, "spaced", 3.0),
        (b"CTF{0xNN_format}", _hex_0x, "0xNN", 3.0),
        (b"picoCTF{hex_pico}", _hex, "picoCTF", 2.5),
        (b"HTB{hex_htb}", _hex_spaced, "HTB spaced", 2.5),
    ]:
        D.append({"name": f"[Hex] {label}", "data": enc_fn(flag),
                  "codec": "hex", "expected": flag.decode(), "boost": boost})

    # ── ROT13 ────────────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{caesar_is_easy}", 4.0),
        (b"picoCTF{r0t_13_ftw}", 3.0),
        (b"HTB{rot13_magic}", 2.5),
        (b"THM{thirteen_shifts}", 2.5),
    ]:
        D.append({"name": f"[ROT13] {flag.decode()}", "data": _rot13(flag),
                  "codec": "rot13", "expected": flag.decode(), "boost": boost})

    # ── Binary ───────────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{bin}", 4.0),
        (b"CTF{01_is_code}", 3.0),
        (b"picoCTF{binary_pico}", 2.5),
    ]:
        D.append({"name": f"[Binary] {flag.decode()}", "data": _bin8(flag),
                  "codec": "binary", "expected": flag.decode(), "boost": boost})
    # Compact (no spaces)
    D.append({"name": "[Binary] compact no spaces",
              "data": _bin8(b"CTF{compact}").replace(b" ", b""),
              "codec": "binary", "expected": "CTF{compact}", "boost": 2.5})

    # ── Octal ────────────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{octal_decoded}", 4.0),
        (b"CTF{oct_master}", 3.0),
        (b"picoCTF{8_based}", 2.5),
    ]:
        D.append({"name": f"[Octal] {flag.decode()}", "data": _oct(flag),
                  "codec": "octal", "expected": flag.decode(), "boost": boost})
    # Compact (no spaces)
    D.append({"name": "[Octal] compact no spaces",
              "data": _oct(b"CTF{oct}").replace(b" ", b""),
              "codec": "octal", "expected": "CTF{oct}", "boost": 2.5})

    # ── URL Encoding ─────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{url_d3coded}", 4.0),
        (b"picoCTF{p3rc3nt_enc}", 3.0),
        (b"CTF{%url%enc%}", 3.0),
    ]:
        D.append({"name": f"[URL] {flag.decode()}", "data": _url(flag),
                  "codec": "url", "expected": flag.decode(), "boost": boost})

    # ── Atbash ───────────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{atbash_decoded}", 4.0),
        (b"CTF{mirror_me}", 3.0),
    ]:
        D.append({"name": f"[Atbash] {flag.decode()}", "data": _atbash(flag),
                  "codec": "atbash", "expected": flag.decode(), "boost": boost})

    # ── AlphaHex ─────────────────────────────────────────────────────────────
    D.append({"name": "[AlphaHex] Z0mb1e challenge",
              "data": b"5h306k6231657i315m637234636i33445m3768335m33617452595m473437337k",
              "codec": "alphahex", "expected": "Z0mb1e{1_cr4ck3D_7h3_3atRY_G473}", "boost": 4.0})
    for flag, boost in [
        (b"CTF{alphahex}", 3.0),
        (b"picoCTF{alpha_hex_magic}", 2.5),
    ]:
        D.append({"name": f"[AlphaHex] {flag.decode()}", "data": _alphahex(flag),
                  "codec": "alphahex", "expected": flag.decode(), "boost": boost})

    # ── Morse ────────────────────────────────────────────────────────────────
    D.append({"name": "[Morse] HELLOWORLD",
              "data": b".... . .-.. .-.. --- .-- --- .-. .-.. -..",
              "codec": "morse", "expected": "HELLOWORLD", "boost": 4.0})
    D.append({"name": "[Morse] CTF SOS",
              "data": b"-.-. - ..-.   ... --- ...",
              "codec": "morse", "expected": "CTF SOS", "boost": 3.0})

    # ── XOR (raw binary — decoder auto-brute-forces the key) ─────────────────
    for flag, key, boost in [
        (b"CTF{xor_key_42}",   42,   4.0),
        (b"CTF{XOR_DECODED}",  0xAA, 3.5),
        (b"picoCTF{xor_55}",   0x55, 3.0),
        (b"HTB{xor_htb_key}",  0x37, 2.5),
    ]:
        D.append({"name": f"[XOR] key=0x{key:02x}",
                  "data": _xor(flag, key),
                  "codec": "xor", "expected": flag.decode(), "boost": boost})

    # ── Gzip — RAW binary ────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{gzip_compress}", 4.0),
        (b"picoCTF{gzip_ftw}",  3.0),
        (b"HTB{gzip_htb}",      2.5),
    ]:
        D.append({"name": f"[Gzip raw] {flag.decode()}",
                  "data": gzip.compress(flag),
                  "codec": "gzip", "expected": flag.decode(), "boost": boost})

    # ── Gzip — BASE64-WRAPPED (the common CTF workflow) ──────────────────────
    for flag, boost in [
        (b"CTF{gzip_b64_wrapped}",   4.0),
        (b"picoCTF{gzip_b64_pico}",  3.0),
    ]:
        D.append({"name": f"[Gzip b64] {flag.decode()}",
                  "data": _b64(gzip.compress(flag)),
                  "codec": "gzip", "expected": flag.decode(), "boost": boost})

    # ── Zlib — RAW ───────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{zlib_deflate}", 4.0),
        (b"picoCTF{zlib_pico}", 3.0),
    ]:
        D.append({"name": f"[Zlib raw] {flag.decode()}",
                  "data": zlib.compress(flag),
                  "codec": "zlib", "expected": flag.decode(), "boost": boost})

    # ── Zlib — BASE64-WRAPPED ─────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{zlib_b64_wrapped}", 4.0),
        (b"picoCTF{zlib_b64}",     3.0),
    ]:
        D.append({"name": f"[Zlib b64] {flag.decode()}",
                  "data": _b64(zlib.compress(flag)),
                  "codec": "zlib", "expected": flag.decode(), "boost": boost})

    # ── Bzip2 — RAW ──────────────────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{bzip2_cracked}",  4.0),
        (b"picoCTF{bzip2_pico}", 3.0),
    ]:
        D.append({"name": f"[Bzip2 raw] {flag.decode()}",
                  "data": bz2.compress(flag),
                  "codec": "bzip2", "expected": flag.decode(), "boost": boost})

    # ── Bzip2 — BASE64-WRAPPED ───────────────────────────────────────────────
    for flag, boost in [
        (b"CTF{bzip2_b64_wrapped}", 4.0),
        (b"picoCTF{bzip2_b64}",     3.0),
    ]:
        D.append({"name": f"[Bzip2 b64] {flag.decode()}",
                  "data": _b64(bz2.compress(flag)),
                  "codec": "bzip2", "expected": flag.decode(), "boost": boost})

    # ── Chains ───────────────────────────────────────────────────────────────
    chains = [
        ("[Chain] B64→ROT13",   _rot13(_b64(b"CTF{chain_b64_rot}")),     ["rot13","base64"],  "CTF{chain_b64_rot}",   3.0),
        ("[Chain] Hex→XOR",     _hex_0x(_xor(b"CTF{XOR_DECODED}",0xAA)), ["hex","xor"],       "CTF{XOR_DECODED}",     3.0),
        ("[Chain] Double B64",  _b64(_b64(b"CTF{double_base64}")),         ["base64","base64"], "CTF{double_base64}",   3.0),
        ("[Chain] B64→Gzip",    _b64(gzip.compress(b"CTF{gzip_b64_chain}")), ["base64","gzip"], "CTF{gzip_b64_chain}", 3.0),
        ("[Chain] B64→Zlib",    _b64(zlib.compress(b"CTF{zlib_b64_chain}")), ["base64","zlib"], "CTF{zlib_b64_chain}", 3.0),
        ("[Chain] B64→Bzip2",   _b64(bz2.compress(b"CTF{bzip2_b64_chain}")), ["base64","bzip2"], "CTF{bzip2_b64_chain}", 3.0),
        ("[Chain] Hex→Base64",  _hex(_b64(b"CTF{hex_b64}")),               ["hex","base64"],    "CTF{hex_b64}",        2.5),
        ("[Chain] URL→Hex",     _url(_hex(b"CTF{hex_url}")),                ["url","hex"],       "CTF{hex_url}",        2.5),
        ("[Chain] ROT13→Hex",   _rot13(_hex(b"CTF{rot_hex}")),              ["rot13","hex"],     "CTF{rot_hex}",        2.5),
        ("[Chain] Triple B64",  _b64(_b64(_b64(b"CTF{triple}"))),           ["base64","base64","base64"], "CTF{triple}", 2.0),
    ]
    for name, data, chain, expected, boost in chains:
        D.append({"name": name, "data": data, "chain": chain,
                  "expected": expected, "boost": boost})

    return D


# ─────────────────────────────────────────────────────────────────────────────
# Platform profiles
# ─────────────────────────────────────────────────────────────────────────────

PLATFORM_CHAINS = {
    "picoCTF":      [["base64"], ["rot13"], ["hex"], ["binary"], ["base64","rot13"], ["hex","xor"]],
    "HackTheBox":   [["base64"], ["xor"], ["gzip"], ["base64","gzip"], ["hex","xor"]],
    "TryHackMe":    [["rot13"], ["base64"], ["url"], ["rot13","base64"]],
    "DownUnderCTF": [["base64"], ["hex"], ["zlib"], ["base64","zlib"]],
}


# ─────────────────────────────────────────────────────────────────────────────
# Training engine
# ─────────────────────────────────────────────────────────────────────────────

def train_engine(verbose: bool = False):
    pipeline = PipelineManager()
    dataset  = build_dataset()

    print("\n" + "═" * 62)
    print("  CTF DECODER — INDUSTRIAL TRAINING SUITE")
    print("═" * 62)
    print(f"  Total samples    : {len(dataset)}")
    print(f"  Platform profiles: {len(PLATFORM_CHAINS)}")
    print("═" * 62 + "\n")

    passed = failed = 0

    for item in dataset:
        name     = item["name"]
        expected = item.get("expected", "")
        boost    = item.get("boost", 2.0)

        try:
            if "chain" in item:
                req    = DecodeRequest(input_bytes=item["data"], chain=item["chain"])
                result = pipeline.run_chain(req)
            else:
                req    = DecodeRequest(input_bytes=item["data"], target_codec=item["codec"])
                result = pipeline.run_single(req)
        except Exception as e:
            print(f"  ✖ EXCEPTION  {name}\n     {e}")
            failed += 1
            continue

        if not result.success:
            print(f"  ✖ DECODE ERR {name}\n     {result.error}")
            failed += 1
            continue

        output_str = result.final_output.decode("utf-8", errors="ignore")
        if expected and expected not in output_str:
            print(f"  ✖ WRONG OUT  {name}\n     got: {repr(output_str[:80])}")
            failed += 1
            continue

        # ── Memory boost ──────────────────────────────────────────────────
        codecs_used = item.get("chain", [item.get("codec", "")])
        codecs_used = [c for c in codecs_used if c]
        for c in codecs_used:
            p = memory_db.get_prior(c)
            memory_db.set_prior(c, p.alpha + boost, p.beta)
        if codecs_used:
            memory_db.upsert_chain_template(codecs_used)

        rate = memory_db.get_prior(codecs_used[-1]).expected_value if codecs_used else 0
        if verbose:
            print(f"  ✔ {name}")
            for c in codecs_used:
                pr = memory_db.get_prior(c)
                print(f"      {c}: α={pr.alpha:.1f}  p={pr.expected_value:.2f}")
        else:
            print(f"  ✔ {name:<48} p={rate:.2f}")
        passed += 1

    # ── Platform profile seeding ─────────────────────────────────────────
    print("\n" + "─" * 62)
    print("  Seeding platform chain profiles…")
    for platform, chains in PLATFORM_CHAINS.items():
        for chain in chains:
            memory_db.upsert_chain_template(chain, platform=platform)
            for c in chain:
                p = memory_db.get_prior(c)
                memory_db.set_prior(c, p.alpha + 0.5, p.beta)
        print(f"  ✔ {platform}: {len(chains)} chain templates")

    # ── Final summary ────────────────────────────────────────────────────
    print("\n" + "═" * 62)
    print(f"  RESULTS  {passed}/{passed+failed} passed  |  {failed} failed")
    print()
    print("  CALIBRATED PRIORS (top 13):")
    priors = memory_db.get_all_priors()
    for codec, prior in sorted(priors, key=lambda x: -x[1].expected_value)[:13]:
        bar  = "█" * int(prior.expected_value * 24)
        pct  = f"{prior.expected_value:.0%}"
        obs  = int(prior.alpha + prior.beta - 2)
        print(f"    {codec:<12} {bar:<24} {pct}  ({obs} obs)")
    print("═" * 62)
    print("\n  [✔] Industrial training complete. Engine fully calibrated.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset",   action="store_true", help="Wipe memory before training")
    parser.add_argument("--verbose", action="store_true", help="Show per-codec prior updates")
    args = parser.parse_args()

    if args.reset:
        print("[!] Resetting adaptive memory…")
        memory_db.clear()

    train_engine(verbose=args.verbose)

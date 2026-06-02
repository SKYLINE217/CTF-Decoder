import random
import gzip
import zlib
import bz2
import base64
import urllib.parse
import codecs
from typing import List, Tuple, Dict

# Standard Morse code dict (reversed for encoding)
MORSE_DICT = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
    '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
    '9': '----.', '0': '-----', ',': '--..--', '.': '.-.-.-', '?': '..--..',
    '/': '-..-.', '(': '-.--.', ')': '-.--.-'
}

NOUNS = ["flag", "secret", "cipher", "hacker", "network", "system", "database", "server", "password", "token", "session", "admin", "root", "kernel", "packet", "payload", "exploit", "vulnerability", "encryption", "hash", "key", "iv", "signature", "certificate", "protocol", "port", "socket", "cookie", "request", "response"]
VERBS = ["hack", "decrypt", "encrypt", "bypass", "exploit", "secure", "monitor", "breach", "intercept", "sniff", "inject", "detect", "analyze", "obfuscate", "decode", "encode", "transmit", "receive", "crack", "leak"]
ADJECTIVES = ["secure", "hidden", "encrypted", "encoded", "random", "obfuscated", "malicious", "valid", "invalid", "broken", "vulnerable", "remote", "local", "internal", "external", "critical", "sensitive", "private", "public", "anonymous"]
CTF_PLATFORMS = ["picoCTF", "HTB", "THM", "DUCTF", "SECCON", "DEFCON", "ASIS", "GoogleCTF", "AngstromCTF", "HackTheBox", "TryHackMe", "DownUnderCTF"]
SPECIAL_CHARS = ["!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "_", "+", "-", "=", "[", "]", "{", "}", ";", ":", ",", ".", "/", "?", "~"]

def generate_random_word() -> str:
    parts = [random.choice(NOUNS), random.choice(VERBS), random.choice(ADJECTIVES)]
    word = random.choice(parts)
    if random.random() < 0.3:
        word = word.replace('e', '3').replace('a', '4').replace('o', '0').replace('i', '1').replace('s', '5').replace('t', '7')
    return word

def generate_random_sentence(min_words=3, max_words=12) -> str:
    num_words = random.randint(min_words, max_words)
    words = []
    for _ in range(num_words):
        if random.random() < 0.1:
            words.append(str(random.randint(0, 999999)))
        else:
            words.append(generate_random_word())
    return " ".join(words)

def generate_random_flag() -> str:
    platform = random.choice(CTF_PLATFORMS)
    inner_parts = []
    for _ in range(random.randint(1, 4)):
        inner_parts.append(generate_random_word())
    if random.random() < 0.5:
        inner_parts.append(str(random.randint(0, 99999)))
    
    separator = random.choice(["_", "-", ""])
    inner = separator.join(inner_parts)
    
    if platform == "HTB" or platform == "HackTheBox":
        return f"HTB{{{inner}}}"
    elif platform == "picoCTF":
        return f"picoCTF{{{inner}}}"
    elif platform == "THM" or platform == "TryHackMe":
        return f"THM{{{inner}}}"
    elif platform == "DUCTF" or platform == "DownUnderCTF":
        return f"DUCTF{{{inner}}}"
    else:
        return f"FLAG{{{inner}}}"

def generate_raw_plaintext() -> bytes:
    choice = random.random()
    if choice < 0.4:
        # Standard clean flag
        return generate_random_flag().encode('utf-8')
    elif choice < 0.6:
        # Flag mixed with garbage text (simulating real CTF capture outputs)
        flag = generate_random_flag()
        pre = generate_random_sentence(1, 5)
        post = generate_random_sentence(1, 5)
        templates = [
            f"{pre} {flag} {post}",
            f"Here is your target flag: {flag}",
            f"Flag hidden in payload: {flag} (verify carefully)",
            f"{flag}"
        ]
        return random.choice(templates).encode('utf-8')
    elif choice < 0.8:
        # Sentence
        return generate_random_sentence().encode('utf-8')
    else:
        # Pure random characters/noise
        length = random.randint(10, 150)
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" + " ".join(SPECIAL_CHARS)
        return "".join(random.choice(chars) for _ in range(length)).encode('utf-8')

# Encoder helper functions
def encode_base64(s: bytes) -> bytes:
    if random.random() < 0.3:
        return base64.urlsafe_b64encode(s)
    elif random.random() < 0.3:
        b = base64.b64encode(s)
        return b'\n'.join(b[i:i+64] for i in range(0, len(b), 64))
    else:
        return base64.b64encode(s)

def encode_hex(s: bytes) -> bytes:
    r = random.random()
    if r < 0.3:
        return b' '.join(s.hex()[i:i+2].encode() for i in range(0, len(s.hex()), 2))
    elif r < 0.5:
        return b' '.join(f'0x{b:02x}'.encode() for b in s)
    elif r < 0.7:
        return b''.join(f'\\x{b:02x}'.encode() for b in s)
    else:
        return s.hex().encode()

def encode_binary(s: bytes) -> bytes:
    if random.random() < 0.5:
        return b' '.join(format(b, '08b').encode() for b in s)
    else:
        return b''.join(format(b, '08b').encode() for b in s)

def encode_octal(s: bytes) -> bytes:
    if random.random() < 0.5:
        return b' '.join(format(b, '03o').encode() for b in s)
    else:
        return b''.join(format(b, '03o').encode() for b in s)

def encode_rot13(s: bytes) -> bytes:
    text = s.decode('latin-1')
    return codecs.encode(text, 'rot_13').encode('latin-1')

def encode_atbash(s: bytes) -> bytes:
    text = s.decode('latin-1')
    out = []
    for c in text:
        if 'A' <= c <= 'Z': out.append(chr(ord('Z') - (ord(c)-ord('A'))))
        elif 'a' <= c <= 'z': out.append(chr(ord('z') - (ord(c)-ord('a'))))
        else: out.append(c)
    return ''.join(out).encode('latin-1')

def encode_url(s: bytes) -> bytes:
    # Double url encoding occasionally
    if random.random() < 0.3:
        first = urllib.parse.quote_from_bytes(s).encode('ascii')
        return urllib.parse.quote_from_bytes(first).encode('ascii')
    return urllib.parse.quote_from_bytes(s).encode('ascii')

def encode_xor(s: bytes) -> bytes:
    key = random.randint(1, 255)
    return bytes([b ^ key for b in s])

def encode_gzip(s: bytes) -> bytes:
    return gzip.compress(s)

def encode_zlib(s: bytes) -> bytes:
    return zlib.compress(s)

def encode_bzip2(s: bytes) -> bytes:
    return bz2.compress(s)

def encode_alphahex(s: bytes) -> bytes:
    return s.hex().translate(str.maketrans('abcdef','hijklm')).encode()

def encode_morse(s: bytes) -> bytes:
    try:
        text = s.decode('utf-8').upper()
    except UnicodeDecodeError:
        text = s.decode('latin-1').upper()
    words = text.split()
    encoded_words = []
    for w in words:
        chars = [MORSE_DICT[c] for c in w if c in MORSE_DICT]
        if chars:
            encoded_words.append(" ".join(chars))
    return "   ".join(encoded_words).encode('ascii')

ENCODERS = {
    "base64": encode_base64,
    "hex": encode_hex,
    "binary": encode_binary,
    "octal": encode_octal,
    "rot13": encode_rot13,
    "atbash": encode_atbash,
    "url": encode_url,
    "xor": encode_xor,
    "gzip": encode_gzip,
    "zlib": encode_zlib,
    "bzip2": encode_bzip2,
    "alphahex": encode_alphahex,
    "morse": encode_morse
}

def generate_dataset(num_samples: int = 50000) -> List[Tuple[bytes, str]]:
    """
    Generates a high-quality dataset of `num_samples` entries.
    Supports complex nested chains and mixed noise patterns.
    """
    random.seed(42)
    dataset = []
    
    # 1. Plaintext / flags / none class (15%)
    num_none = int(num_samples * 0.15)
    for _ in range(num_none):
        if random.random() < 0.6:
            dataset.append((generate_raw_plaintext(), "none"))
        else:
            length = random.randint(10, 600)
            noise = bytes(random.randint(0, 255) for _ in range(length))
            dataset.append((noise, "none"))
            
    # 2. Single encoded samples (50%)
    num_single = int(num_samples * 0.50)
    codecs_list = list(ENCODERS.keys())
    samples_per_codec = num_single // len(codecs_list)
    
    for codec in codecs_list:
        encoder_func = ENCODERS[codec]
        for _ in range(samples_per_codec):
            plaintext = generate_raw_plaintext()
            try:
                encoded = encoder_func(plaintext)
                if encoded:
                    dataset.append((encoded, codec))
            except Exception:
                continue

    # 3. Chained encoded samples (35%)
    num_chained = num_samples - len(dataset)
    
    common_chains = [
        # (inner, outer) -> label is outer
        ("rot13", "base64"),
        ("hex", "base64"),
        ("xor", "base64"),
        ("gzip", "base64"),
        ("zlib", "base64"),
        ("bzip2", "base64"),
        ("base64", "base64"),
        ("xor", "hex"),
        ("rot13", "hex"),
        ("base64", "hex"),
        ("hex", "xor"),
        ("rot13", "xor"),
        ("base64", "rot13"),
        ("hex", "url"),
        ("rot13", "url"),
        ("base64", "url"),
        # Triple chains:
        ("rot13", "hex", "base64"),
        ("xor", "base64", "rot13"),
        ("gzip", "base64", "url"),
        ("zlib", "base64", "rot13"),
        ("bzip2", "base64", "rot13"),
        ("xor", "hex", "base64"),
        ("rot13", "xor", "base64"),
        ("atbash", "rot13", "base64"),
        # Quadruple chains:
        ("gzip", "rot13", "base64", "url"),
        ("xor", "base64", "rot13", "hex"),
        ("zlib", "hex", "base64", "url")
    ]
    
    for _ in range(num_chained):
        chain = random.choice(common_chains)
        plaintext = generate_raw_plaintext()
        
        current = plaintext
        try:
            for codec in chain:
                current = ENCODERS[codec](current)
            
            label = chain[-1]
            if current:
                dataset.append((current, label))
        except Exception:
            continue
            
    random.shuffle(dataset)
    return dataset

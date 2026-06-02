import re
from typing import Dict

def check_base64(data: bytes) -> float:
    try:
        s = data.decode('ascii').translate(str.maketrans("", "", " \t\r\n"))
    except UnicodeDecodeError:
        return 0.0
        
    if not s:
        return 0.0
        
    valid_chars = sum(1 for c in s if c.isalnum() or c in "+/=-_")
    ratio = valid_chars / len(s)
    
    if ratio < 0.95:
        return 0.0
        
    if len(s) % 4 == 0 or s.endswith("="):
        return ratio
        
    return ratio * 0.8 # Penalty for missing padding

def check_hex(data: bytes) -> float:
    try:
        s = data.decode('ascii')
    except UnicodeDecodeError:
        return 0.0
        
    s = re.sub(r'(?:0x|\\x|%|:| )', '', s, flags=re.IGNORECASE).strip()
    if not s:
        return 0.0
        
    valid_chars = sum(1 for c in s if c in "0123456789abcdefABCDEF")
    ratio = valid_chars / len(s)
    
    if ratio < 0.95:
        return 0.0
        
    if len(s) % 2 == 0:
        return ratio
        
    return 0.0 # Strict on hex length
    
def check_binary(data: bytes) -> float:
    try:
        s = data.decode('ascii').replace(" ", "").replace("\n", "").replace("\r", "")
    except UnicodeDecodeError:
        return 0.0
        
    if not s:
        return 0.0
        
    valid_chars = sum(1 for c in s if c in "01")
    ratio = valid_chars / len(s)
    
    if ratio < 0.99:
        return 0.0
        
    if len(s) % 8 == 0 or len(s) % 7 == 0:
        return ratio
        
    return ratio * 0.5
    
def check_url(data: bytes) -> float:
    try:
        s = data.decode('ascii')
    except UnicodeDecodeError:
        return 0.0
    
    matches = len(re.findall(r'%[0-9a-fA-F]{2}', s))
    if matches > 0:
        return min(1.0, 0.5 + (matches * 0.1))
    return 0.0

CLASSIFIERS = {
    "base64": check_base64,
    "hex": check_hex,
    "binary": check_binary,
    "url": check_url
}

def analyze_patterns(data: bytes) -> Dict[str, float]:
    scores = {}
    for name, func in CLASSIFIERS.items():
        scores[name] = func(data)
    return scores

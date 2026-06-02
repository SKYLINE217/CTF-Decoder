import math
from collections import Counter

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy

def entropy_confidence(entropy: float, expected_min: float, expected_max: float) -> float:
    """Return a confidence score [0, 1] based on how well the entropy matches expected range."""
    if expected_min <= entropy <= expected_max:
        return 1.0
        
    # Penalty drops off linearly up to a distance of 1.0 outside the range
    if entropy < expected_min:
        distance = expected_min - entropy
    else:
        distance = entropy - expected_max
        
    return max(0.0, 1.0 - distance)

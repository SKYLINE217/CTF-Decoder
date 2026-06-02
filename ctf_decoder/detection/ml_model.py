import os
import math
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

MODEL_PATH = Path(__file__).parent / "model.joblib"

# Ordered list of classes (including "none")
CLASSES = [
    "alphahex",
    "atbash",
    "base64",
    "binary",
    "bzip2",
    "gzip",
    "hex",
    "morse",
    "octal",
    "rot13",
    "url",
    "xor",
    "zlib",
    "none"
]

def get_string_rep(data: bytes) -> str:
    """Safely decode bytes to latin-1 to preserve exact byte patterns as a string."""
    return data.decode('latin-1')

def extract_features(data: bytes) -> List[float]:
    """
    Extracts 276 statistical, structural, and frequency-based features from raw bytes.
    Features:
      - 256 normalized byte frequencies
      - 20 statistical/structural metrics (entropy, length, character ratio classes, magic bytes)
    """
    if not data:
        return [0.0] * 276
    
    length = len(data)
    
    # 1. Byte frequencies (256 features)
    freqs = [0.0] * 256
    for b in data:
        freqs[b] += 1.0
    for i in range(256):
        freqs[i] /= length
        
    # 2. Shannon Entropy
    entropy = 0.0
    for f in freqs:
        if f > 0.0:
            entropy -= f * math.log2(f)
            
    # 3. Specific character classes ratios
    printable = 0.0
    digits = 0.0
    lowercase = 0.0
    uppercase = 0.0
    whitespace = 0.0
    binary_digits = 0.0
    octal_digits = 0.0
    hex_letters = 0.0
    b64_symbols = 0.0
    pct_symbols = 0.0
    morse_symbols = 0.0
    
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            printable += 1
        if 48 <= b <= 57:
            digits += 1
            if b in (48, 49):
                binary_digits += 1
            if 48 <= b <= 55:
                octal_digits += 1
        if 97 <= b <= 122:
            lowercase += 1
            if 97 <= b <= 102:
                hex_letters += 1
        if 65 <= b <= 90:
            uppercase += 1
            if 65 <= b <= 70:
                hex_letters += 1
        if b in (9, 10, 13, 32):
            whitespace += 1
        if b in (43, 47, 61):
            b64_symbols += 1
        if b == 37:
            pct_symbols += 1
        if b in (45, 46, 47, 32):
            morse_symbols += 1
            
    r_printable = printable / length
    r_digits = digits / length
    r_lowercase = lowercase / length
    r_uppercase = uppercase / length
    r_whitespace = whitespace / length
    r_binary_digits = binary_digits / length
    r_octal_digits = octal_digits / length
    r_hex_letters = hex_letters / length
    r_b64_symbols = b64_symbols / length
    r_pct_symbols = pct_symbols / length
    r_morse_symbols = morse_symbols / length
    
    # 4. Length-related indicators
    is_even = 1.0 if length % 2 == 0 else 0.0
    is_mod4 = 1.0 if length % 4 == 0 else 0.0
    is_mod8 = 1.0 if length % 8 == 0 else 0.0
    
    # 5. Magic headers (binary checks)
    has_gzip = 1.0 if data.startswith(b'\x1f\x8b') else 0.0
    has_zlib = 1.0 if (data.startswith(b'\x78\x01') or data.startswith(b'\x78\x9c') or data.startswith(b'\x78\xda')) else 0.0
    has_bzip2 = 1.0 if data.startswith(b'BZh') else 0.0
    
    # 6. Flag presence indicators (checks for common flag start bytes)
    has_flag_prefix = 0.0
    if len(data) >= 4:
        for prefix in (b'CTF{', b'pico', b'HTB{', b'THM{', b'DUCT', b'flag'):
            if prefix in data:
                has_flag_prefix = 1.0
                break
                
    features = [
        entropy,
        float(length),
        r_printable,
        r_digits,
        r_lowercase,
        r_uppercase,
        r_whitespace,
        r_binary_digits,
        r_octal_digits,
        r_hex_letters,
        r_b64_symbols,
        r_pct_symbols,
        r_morse_symbols,
        is_even,
        is_mod4,
        is_mod8,
        has_gzip,
        has_zlib,
        has_bzip2,
        has_flag_prefix
    ]
    
    return freqs + features

class MLModelManager:
    """Manages training, loading, saving, and inference for the upgraded ML detection model."""
    
    _model = None
    
    @classmethod
    def load_model(cls) -> bool:
        """Loads the trained model components from disk if it exists."""
        if cls._model is not None:
            return True
        try:
            import joblib
        except ImportError:
            return False
        if MODEL_PATH.exists():
            try:
                cls._model = joblib.load(MODEL_PATH)
                return True
            except Exception as e:
                print(f"[-] Failed to load ML model from {MODEL_PATH}: {e}")
        return False
        
    @classmethod
    def train_and_save(cls, X_num: List[List[float]], X_str: List[str], y: List[str], estimators: int = 300) -> Dict[str, Any]:
        """
        Trains a heavy ensemble model (RandomForest + ExtraTrees) combined with
        character n-gram TF-IDF vectorization and saves it to disk.
        """
        import joblib
        import numpy as np
        import scipy.sparse as sp
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report, accuracy_score
        
        # Split original data indices
        indices = np.arange(len(y))
        train_idx, test_idx = train_test_split(
            indices, test_size=0.15, random_state=42, stratify=y
        )
        
        print("[*] Fitting TfidfVectorizer on character n-grams...")
        vectorizer = TfidfVectorizer(analyzer='char_wb', ngram_range=(1, 3), max_features=500)
        
        # Fit vectorizer only on training strings to prevent leakage
        train_strs = [X_str[i] for i in train_idx]
        vectorizer.fit(train_strs)
        
        # Vectorize and stack features
        print("[*] Vectorizing features and combining tables...")
        X_num_arr = np.array(X_num, dtype=np.float32)
        X_str_tfidf = vectorizer.transform(X_str)
        
        # Stack numerical stats and sparse TF-IDF together
        X_combined = sp.hstack([sp.csr_matrix(X_num_arr), X_str_tfidf], format='csr')
        
        X_train = X_combined[train_idx]
        X_test = X_combined[test_idx]
        
        y_arr = np.array(y)
        y_train = y_arr[train_idx]
        y_test = y_arr[test_idx]
        
        print(f"[*] Training RandomForestClassifier ({estimators} estimators)...")
        rf = RandomForestClassifier(
            n_estimators=estimators,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            n_jobs=-1
        )
        rf.fit(X_train, y_train)
        
        print(f"[*] Training ExtraTreesClassifier ({estimators} estimators)...")
        et = ExtraTreesClassifier(
            n_estimators=estimators,
            max_depth=None,
            min_samples_split=2,
            random_state=42,
            n_jobs=-1
        )
        et.fit(X_train, y_train)
        
        # Evaluate ensemble average
        p_rf = rf.predict_proba(X_test)
        p_et = et.predict_proba(X_test)
        ensemble_probs = (p_rf + p_et) / 2.0
        
        classes = rf.classes_
        preds = classes[np.argmax(ensemble_probs, axis=1)]
        
        acc = accuracy_score(y_test, preds)
        report = classification_report(y_test, preds, output_dict=True)
        
        print(f"[+] Custom ensemble validation accuracy: {acc:.2%}")
        
        # Save model dict
        model_data = {
            "vectorizer": vectorizer,
            "rf": rf,
            "et": et
        }
        
        os.makedirs(MODEL_PATH.parent, exist_ok=True)
        joblib.dump(model_data, MODEL_PATH)
        cls._model = model_data
        print(f"[+] Model successfully saved to {MODEL_PATH}")
        
        return {
            "accuracy": acc,
            "report": report
        }

    @classmethod
    def predict_codec_probs(cls, data: bytes) -> List[Tuple[float, str]]:
        """
        Predicts the probabilities of each codec class for the given input data.
        Returns a sorted list of (probability, codec_name).
        """
        if not cls.load_model():
            return []
            
        import numpy as np
        import scipy.sparse as sp
        
        num_feats = extract_features(data)
        text_rep = get_string_rep(data)
        
        vectorizer = cls._model["vectorizer"]
        rf = cls._model["rf"]
        et = cls._model["et"]
        
        # Transform
        text_tfidf = vectorizer.transform([text_rep])
        num_arr = np.array([num_feats], dtype=np.float32)
        combined = sp.hstack([sp.csr_matrix(num_arr), text_tfidf], format='csr')
        
        # Average probability of custom ensemble
        p_rf = rf.predict_proba(combined)[0]
        p_et = et.predict_proba(combined)[0]
        probs = (p_rf + p_et) / 2.0
        classes = rf.classes_
        
        results = []
        for prob, name in zip(probs, classes):
            if name == "none":
                continue
            if prob > 0.01:
                results.append((float(prob), str(name)))
                
        # Sort by probability descending
        results.sort(key=lambda x: x[0], reverse=True)
        return results

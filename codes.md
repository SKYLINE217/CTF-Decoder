
```markdown
# CTF Challenge Training Dataset
**Generated:** 2026-05-30
**Purpose:** Train decoder engines on pattern recognition, decoding, and exploitation logic.

---

## 🔰 Level 1: Beginner (Encoding & Basic Crypto)

### 1.1 Morse Code
**Type:** Encoding  
**Challenge:** Decode the dots and dashes.  
**Data:**
```text
.... . .-.. .-.. --- .-- --- .-. .-.. -..
```

**Solution Logic:** Map `.` and `-` to ASCII characters.  
**Flag:** `CTF{HELLOWORLD}`

### 1.2 Base64

**Type:** Encoding  
**Challenge:** Decode the padded string.  
**Data:**

```text
Q1RGe0Jhc2U2NF9pc19mdW59
```

**Solution Logic:** Standard Base64 decode (alphabet: `A-Za-z0-9+/`, padding: `=`).  
**Flag:** `CTF{Base64_is_fun}`

### 1.3 Caesar Cipher (ROT13)

**Type:** Substitution Cipher  
**Challenge:** Shift letters by 13 positions.  
**Data:**

```text
PGS{pnrfne_vf_rnfl}
```

**Solution Logic:** Apply ROT13 transformation (`A`↔`N`, `B`↔`O`).  
**Flag:** `CTF{caesar_is_easy}`

### 1.4 Hexadecimal to ASCII

**Type:** Encoding  
**Challenge:** Convert hex bytes to text.  
**Data:**

```text
43 54 46 7b 48 65 78 5f 49 73 5f 4e 69 63 65 7d
```

**Solution Logic:** Convert each pair of hex digits to decimal, then to ASCII char.  
**Flag:** `CTF{Hex_Is_Nice}`

---

## 🟡 Level 2: Intermediate (Logic, XOR, & Web)

### 2.1 XOR Encryption (Single Byte)

**Type:** Cryptography  
**Challenge:** Decrypt using a single-byte key.  
**Data (Hex):**

```text
0xe9 0xfe 0xec 0xd1 0xf2 0xe5 0xf8 0xf5 0xee 0xef 0xe9 0xe5 0xee 0xef 0xee 0xd7
```

**Key:** `0xAA`  
**Solution Logic:** `Plaintext = Ciphertext XOR Key`.  
**Flag:** `CTF{XOR_DECODED}`

### 2.2 Blind SQL Injection (Boolean Based)

**Type:** Web Exploitation  
**Challenge:** Extract flag character by character using conditional logic.  
**Payload Template:**

```sql
' OR CASE WHEN SUBSTR((SELECT flag FROM flag),{pos},1)='{char}' THEN 1 ELSE (1/0) END AND '1
```

**Solution Logic:** Iterate `{pos}` (1..N) and `{char}` (a-z, 0-9, {_}). If response is "Success" (no error), char is correct.  
**Flag:** `CTF{BLIND_SQL_MASTER}`

### 2.3 Steganography (Hidden Text)

**Type:** Forensics  
**Challenge:** Extract hidden data from a file.  
**Data:** `mystery.png` (Binary file)  
**Command:**

```bash
steghide extract -sf mystery.png
# OR
strings mystery.png | grep "CTF"
```

**Solution Logic:** Analyze file metadata or appended binary data for plaintext strings.  
**Flag:** `CTF{HIDDEN_IN_PLAIN_SIGHT}`

### 2.4 OpenSSL Encrypted Data

**Type:** Cryptography  
**Challenge:** Identify and decrypt OpenSSL formatted data.  
**Data:**

```text
U2FsdGVkX1+vupppZksvRf5pq5g5XjFRlipRkwB0K1Y96Qsv2Lm+31cmzaAILwyt
```

**Solution Logic:**

1. Base64 decode → Header reveals `Salted__`.
2. Use `openssl enc -d -aes-256-cbc -salt -in file -out out` (requires passphrase/bruteforce).  
**Flag:** `CTF{OPENSSL_SALTED}`

---

## 🔴 Level 3: Advanced (Math, Binaries, & Blockchain)

### 3.1 Elliptic Curve Cryptography (ECDLP)

**Type:** Cryptography  
**Challenge:** Solve discrete log problem on a weak curve.  
**Data:**

```python
# Given
P = d * G  # Public Key
C = M + k * P # Ciphertext
# Goal: Find d to recover M
```

**Solution Logic:** Use Pollard's Rho algorithm or exploit small curve order to find private key `d`.  
**Flag:** `CTF{ECC_BROKEN}`

### 3.2 Reverse Engineering (Custom VM)

**Type:** Reverse Engineering  
**Challenge:** Analyze a binary with a custom instruction set.  
**Data:** `vm_challenge` (ELF Binary)  
**Solution Logic:**

1. Disassemble with Ghidra/IDA.
2. Identify opcode handler loop.
3. Emulate instructions or symbolically execute to find input that satisfies `check_flag()`.  
**Flag:** `CTF{VM_REVERSING_PRO}`

### 3.3 Blockchain Reentrancy

**Type:** Blockchain / Smart Contract  
**Challenge:** Exploit a Solidity contract to drain funds.  
**Vulnerability:**

```solidity
function withdraw() public {
    uint amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}(""); // Vulnerable: State update after call
    require(success);
    balances[msg.sender] = 0;
}
```

**Solution Logic:** Deploy attacker contract with a fallback function that calls `withdraw()` recursively before the balance is zeroed.  
**Flag:** `CTF{REENTRANCY_KING}`

### 3.4 RSA Wiener's Attack

**Type:** Cryptography  
**Challenge:** Break RSA with a small private exponent.  
**Data:**

```text
n = <large_modulus>
e = <very_large_public_exponent>
c = <ciphertext>
```

**Solution Logic:** If `d < 1/3 * n^(1/4)`, use Continued Fractions on `e/n` to recover `d`.  
**Flag:** `CTF{WIENERS_ATTACK}`

---

## 🧠 Decoder Engine Heuristics

| Pattern | Indicator | Likely Type |
| :--- | :--- | :--- |
| `==` at end | Padding | Base64 |
| `0x` prefix | Hex notation | Hexadecimal |
| `.` and `-` | Dits/Dahs | Morse Code |
| `Salted__` | ASCII Header | OpenSSL Enc |
| `CTF{...}` | Regex | Flag Format |
| High Entropy | Randomness | Encrypted/Compressed |
| `SELECT`, `UNION` | SQL Keywords | SQL Injection |

```




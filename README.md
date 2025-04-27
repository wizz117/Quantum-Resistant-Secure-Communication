# Quantum-Resistant Secure Communication Suite

A Python implementation of **post-quantum key-establishment** and **symmetric-message protection** in a client-server setting.  
The project demonstrates how to replace vulnerable RSA/Diffie-Hellman handshakes with modern, NIST-candidate algorithms—**Classic McEliece** and **BIKE**—while retaining familiar AES-GCM data confidentiality, integrity, and replay-attack protection.

---

## Why this matters
Current public-key schemes break once practical quantum computers arrive.  
This repo shows a migration path:

| Threat | Classical scheme at risk | PQC replacement here |
|--------|--------------------------|----------------------|
| Shor’s Algorithm (factorisation / discrete log) | RSA, ECDH, ECDSA | Classic McEliece, BIKE |
| Grover’s Algorithm (halves symmetric strength) | AES-128 | Mitigated by AEAD + optional key-doubling |

---

## Features

* **Two interchangeable KEMs**  
  * Classic McEliece (error-correcting code based)  
  * BIKE-L1 / BIKE-L3 (bit-flipping code based via liboqs)
* **Authenticated symmetric channel** with AES-128-GCM
* **Replay-attack detection** via per-message nonces
* **Automated unit & integration tests** (`Encryption_tests.py`)
* **Performance benchmarks** for multiple parameter sets (`Efficiency_tests.py`)
* Clean socket-based **client/server demo** that works on localhost or across the network

---

## Directory / File Guide

| Path | Purpose |
|------|---------|
| `client.py` | Starts a client, sends its PQC public key, receives an AES session key, then exchanges encrypted messages. |
| `server.py` | Listens for clients, encapsulates a secret with their public key, sends the ciphertext / AES key back, then echoes encrypted traffic. |
| `quantum_crypto.py` | Houses both Classic McEliece and BIKE wrappers. Select the algorithm with a single flag. |
| `aes_encryption.py` | Lightweight AES-GCM helpers (`aes_encrypt`, `aes_decrypt`). |
| `encryption_tests.py` | Verifies confidentiality, integrity, and replay-protection. |
| `efficiency_tests.py` | Times key-gen, encapsulation/decapsulation, and AES throughput for different parameter sets. |
| `requirements.txt` | Runtime Python deps (`pyoqs`, `pycryptodome`, etc.). |

---

## Quick-start

```bash
# 1. Clone & install deps
git clone https://github.com/<your-handle>/quantum-secure-comm.git
cd quantum-secure-comm
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt   # includes pyoqs wheels for BIKE

# 2. In one terminal – start the server
python server.py --alg mceliece   # or --alg bike

# 3. In another terminal – run the client
python client.py --alg mceliece   # same flag as server

# 4. Run tests & benchmarks (optional)
pytest encryption_tests.py
python efficiency_tests.py
```

Note: If pyoqs pre-built wheels are unavailable for your platform, compile liboqs from source then reinstall pyoqs with OQS_DIST_DIR pointing to that build.
---
## Benchmark snapshot
Algorithm | Key-gen (ms) | Encaps (ms) | Decaps (ms) | Ciphertext (bytes)
|--------|---------------|-------------|-------------|-------------------|
Classic McEliece n = 300, dv = 6, dc = 10 | ~4 | ~0.5 | ~0.4 | 128
Classic McEliece n = 6936, dv = 3, dc = 6 | ~45 | ~4 | ~3.7 | 10400
BIKE-L3 | ~22 | ~1.8 | ~1.7 | 1540

(See efficiency_tests.py for live numbers on your machine.)



# Evaluating the Impact of XOR and XNOR Operators on AES Execution Speed and Bit-Diffusion Security
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Abstract

This project compares the efficiency and security of AES algorithms between XOR and XNOR by evaluating processing time, memory usage, and bit-diffusion security (Strict Avalanche Criterion, SAC) in the core AES encryption steps: AddRoundKey, MixColumns, and KeyExpansion. Both variants are implemented for all six classic block-cipher modes (ECB, CBC, PCBC, CFB, OFB, CTR) with 128/192/256-bit keys. Across every mode and message size tested (4–16 KB), XOR-AES is consistently about 1.8–2× faster than XNOR-AES, with no measurable difference in memory usage. Both variants satisfy the Strict Avalanche Criterion in every mode, with average bit-diffusion within about 1 percentage point of the ideal 50%. The results support the conclusion that substituting XNOR for XOR in these AES steps costs real performance with no observed security benefit.

## Encryption and Testing Framework

This project contains a collection of Python scripts implementing XOR-based and XNOR-based AES (128/192/256-bit keys, six cipher modes) and evaluating their performance and security properties (Strict Avalanche Criterion).

## Features
- XOR-based (`xor_aes.py`) and XNOR-based (`xnor_aes.py`) AES implementations, each supporting ECB, CBC, PCBC, CFB, OFB, and CTR modes with 128/192/256-bit keys.
- An interactive CLI (`main.py` / `mode_aes.py`) to pick any AES variant + mode combination, encrypt/decrypt a message, and see a timing/memory report.
- A performance benchmarking module (`performance_test.py`) that can time and memory-profile any variant/mode/message-size combination, or sweep all of them at once.
- A Strict Avalanche Criterion (SAC) test (`strict_avalanche_criterion.py`) covering all six modes for both variants.
- Unit test suites for both variants (`xor_tests.py`, `xnor_tests.py`) covering correctness for every mode, key size, and several edge cases (wrong IV length, whole-block padding, long messages, etc.).

## File Structure
- **main.py** — Entry point; launches the interactive CLI.
- **mode_aes.py** — Interactive CLI: choose AES variant (xor/xnor) and mode (ecb/cbc/pcbc/cfb/ofb/ctr), then encrypt/decrypt and run a performance report.
- **xor_aes.py** — XOR-based AES-128/192/256 implementation (all six modes).
- **xnor_aes.py** — XNOR-based AES-128/192/256 implementation (all six modes).
- **performance_test.py** — Timing and memory benchmarking, generic across variant/mode/message size.
- **strict_avalanche_criterion.py** — SAC test across all six modes for both variants; prints a summary table and saves/shows a comparison chart.
- **xor_tests.py** / **xnor_tests.py** — `unittest` suites for correctness of both variants.
- **requirements.txt** — Python dependencies.
- **LICENSE** — MIT License.

## Prerequisites
- Python 3.8 or higher.
- One third-party dependency, `matplotlib` (used only by `strict_avalanche_criterion.py` for plotting; everything else uses only the Python standard library — `os`, `time`, `tracemalloc`, `base64`, `hashlib`, `hmac`, `unittest`).

Install it with:
```bash
pip install -r requirements.txt
```

## Usage

**Interactive encrypt/decrypt with a performance report:**
```bash
python3 main.py
```
You'll be asked to choose an AES variant (`xor` or `xnor`), a mode (`ecb`, `cbc`, `pcbc`, `cfb`, `ofb`, or `ctr`), a key size, and your plaintext.

**Run the full performance benchmark across every variant × mode × message size:**
```bash
python3 performance_test.py
```

**Run the Strict Avalanche Criterion test across every variant × mode:**
```bash
python3 strict_avalanche_criterion.py
```

**Run the correctness unit tests:**
```bash
python3 -m unittest xor_tests xnor_tests
```

## Results

### Performance (4–16 KB messages, all modes, averaged over message size)

| Mode | XOR-AES avg encrypt (s) | XNOR-AES avg encrypt (s) | Slowdown |
|------|------------------------:|-------------------------:|---------:|
| ECB  | 0.112 | 0.200 | 1.78× |
| CBC  | 0.108 | 0.208 | 1.92× |
| PCBC | 0.131 | 0.195 | 1.49× |
| CFB  | 0.118 | 0.214 | 1.81× |
| OFB  | 0.109 | 0.213 | 1.95× |
| CTR  | 0.116 | 0.210 | 1.80× |

Peak memory usage was essentially identical between variants in every mode (~0.11 MB for these message sizes) — the slowdown is purely computational (XNOR-AES additionally complements bytes on top of the XOR, roughly doubling that step's work), not a memory-driven effect. The slowdown was consistent across the whole 4–16 KB range tested; we did not find a specific size band (e.g. 6–8 KB) where the gap was distinctly larger or smaller — that impression in an earlier draft of this README wasn't reproducible against a proper sweep and has been removed.

### Strict Avalanche Criterion (single-block test, all modes)

| Mode | XOR-AES avg bits changed | XNOR-AES avg bits changed | Ideal |
|------|--------------------------:|---------------------------:|------:|
| ECB  | 49.6% | 49.9% | 50% |
| CBC  | 50.2% | 49.8% | 50% |
| PCBC | 50.1% | 49.8% | 50% |
| CFB  | 50.4% | 49.6% | 50% |
| OFB  | 50.4% | 49.6% | 50% |
| CTR  | 50.4% | 49.6% | 50% |

Both variants satisfy SAC in every mode: flipping a single input bit flips close to half the output bits, with no consistent bias in either direction. For CFB/OFB/CTR, note that the bit being flipped is the IV/nonce rather than the plaintext — in those modes the plaintext is only ever XORed with a keystream that doesn't depend on the plaintext, so flipping a plaintext bit in a single-block test only ever flips the one corresponding ciphertext bit (that's the stream-cipher structure of those modes working as intended, not a diffusion failure). Testing the IV/nonce instead exercises the actual AES round function, which is what SAC is meant to evaluate.

### Correctness

All 74 unit tests pass for both variants across every mode, key size (128/192/256-bit), and edge case tested (wrong IV length, whole-block padding, long messages).

### Bug fixed

`strict_avalanche_criterion.py`'s RMSE calculation divided by `n` *after* taking the square root (`sqrt(sum) / n`) instead of before (`sqrt(sum / n)`), understating the reported RMSE by roughly a factor of `sqrt(n)`. It also hardcoded 64 as the "ideal" bit-change value, which only holds for a 128-bit (16-byte) block — CBC/PCBC pad the plaintext to a full extra block, so their ideal value is 128, not 64. Both are fixed, and the ideal value is now derived from the actual ciphertext length for whichever mode is under test.

## Credits & License

* This project includes modified code originally created by [Bo Zhu](http://about.bozhu.me) (Copyright © 2012), which was shared under the MIT License via their repository's README.
* This overall project is released under the [MIT License](LICENSE).

# Performance-and-Security-Comparison-of-AES-using-XOR-and-XNOR

Abstract

This project compares the efficiency and security of AES algorithms between XOR and XNOR by evaluating the efficiency in terms of processing time, memory resource usage, and bit distribution security of data between XOR and XNOR in the important AES encryption processes: AddRoundKey, MixColumns, and KeyExpansion. The experiment uses the XOR and XNOR AES algorithm simulators in Electronic Codebook (ECB) mode to perform encryption and decryption tests with 4-16 KB messages. The experimental results show that XOR takes less processing time than XNOR, especially with 6-8 KB messages. Both XOR and XNOR provide bit distribution values ​​close to 50%, which meets the Strict Avalanche Criterion (SAC). The obtained data enhances the understanding of the efficiency of the AES algorithm and provides guidelines for the development of future encryption systems.

# Encryption and Testing Framework

This project contains a collection of Python scripts for implementing and testing encryption algorithms such as XOR, XNOR, and evaluating their performance and security properties (e.g., Strict Avalanche Criterion).

## Features
- Implementation of XOR and XNOR-based encryption algorithms.
- Performance testing for encryption and decryption.
- Security evaluation using the Strict Avalanche Criterion (SAC).
- Test suites for encryption algorithms.

## File Structure
- **Maes.py**: Core logic for AES-like encryption.
- **XNOR_aes.py**: Implementation of XNOR-based encryption.
- **XOR_aes.py**: Implementation of XOR-based encryption.
- **performance_test.py**: Script for evaluating the performance of encryption algorithms.
- **Strict_Avalanche_Criterion(SAC).py**: Tool for testing the Strict Avalanche Criterion (SAC).
- **XNOR_tests.py**: Unit tests for XNOR encryption.
- **XOR_tests.py**: Unit tests for XOR encryption.
- **โปรแกรมทดสอบการเข้ารหัสและถอดรหัส.py**: User interface for encryption and decryption testing.

## Prerequisites
- Python 3.8 or higher
- Required libraries: Ensure all dependencies are installed. You can install them using:
  ```bash
  pip install -r requirements.txt

## Credits & License

* This project includes modified code originally created by [Bo Zhu](http://about.bozhu.me) (Copyright © 2012), which was shared under the MIT License via their repository's README.
* This overall project is released under the [MIT License](LICENSE).

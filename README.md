# TPM-Bound-Fingerprint  

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)  
[![Python](https://img.shields.io/badge/Python-3.9+-green.svg)](https://www.python.org/)  
[![Platform](https://img.shields.io/badge/OS-Windows%2010/11-lightgrey.svg)]()  

A learning project demonstrating how to generate a **tamper-resistant device fingerprint** securely bound to the **Trusted Platform Module (TPM)**.  

This project explores cryptographic binding of system attributes with TPM-backed primitives to create a trusted hardware identity. It provides hands-on experience with **trusted hardware, device security, and cryptography**.  

---

## 💡 Motivation
The goal of this project is to explore **trusted hardware and secure device identity management**.  
By leveraging the Trusted Platform Module (TPM), this project demonstrates how to create **tamper-resistant, cryptographically bound device fingerprints**, helping developers understand hardware-level security and cryptography concepts.  

---

## 🚀 Features
- Collects stable hardware identifiers:  
  - BIOS serial, CPU ID, disk serial  
  - TPM Endorsement Key (EK) certificate  
- Generates a unique **64-character SHA-256 device fingerprint**  
- Requests administrator privileges automatically for TPM access  
- Runs diagnostics to detect missing or inconsistent data  

---
## Warning
⚠️ SENSITIVE DATA: *This tool outputs unique hardware identifiers. Do NOT share publicly*.
---

## ⚡ Quick Start
```powershell
python -m dpa.client
```

## Requirements
- Windows 10/11 with TPM 2.0 enabled
- Python 3.9+ 
- Administrator privileges (auto-requested)

## Output
- **Hardware Attributes**: BIOS serial, CPU ID, disk serial, TPM EK certificate/serial
- **Device Fingerprint**: SHA-256 hash of canonicalized attributes
- **Device ID**: Same as fingerprint (64 hex characters)

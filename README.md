# TPM-Bound-Fingerprint

Learning project on TPM-bound device fingerprinting and hardware identity.

TPM-Bound-Fingerprint is a learning project that demonstrates how to generate a device fingerprint securely tied to the Trusted Platform Module (TPM). By binding system attributes with TPM-backed cryptographic functions, the project explores techniques for creating a tamper-resistant hardware identity. The purpose is to gain hands-on experience with trusted hardware, device identification, and security primitives.

## Quick Start
```powershell
python -m dpa.client
```

## What It Does
- Collects stable hardware identifiers (BIOS serial, CPU ID, disk serial, TPM EK certificate)
- Generates a unique 64-character SHA-256 device fingerprint
- Automatically requests admin privileges for full TPM access
- Runs comprehensive diagnostics to troubleshoot missing data

## Requirements
- Windows 10/11 with TPM 2.0 enabled
- Python 3.9+ 
- Administrator privileges (auto-requested)

## Output
- **Hardware Attributes**: BIOS serial, CPU ID, disk serial, TPM EK certificate/serial
- **Device Fingerprint**: SHA-256 hash of canonicalized attributes
- **Device ID**: Same as fingerprint (64 hex characters)

## Warning
⚠️ **SENSITIVE DATA**: This tool outputs unique hardware identifiers. Do NOT share publicly.

## License
MIT

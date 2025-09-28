# ZTNA-Device-Fingerprinting

Hardware-based device fingerprinting for Zero Trust Network Access (ZTNA) with TPM 2.0 support.

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
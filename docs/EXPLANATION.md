# Project Explanation

## Top-level
- `README.md`: How to run and what the tool does (client-only, Windows).
- `LICENSE`: MIT license for reuse.
- `docs/design.md`: Design choices, inputs, flow (client-only).
- `docs/diagrams/*.mmd`: Mermaid sources for optional rendered diagrams.

## Client code (Python, Windows-only)
- `dpa/client.py`
  - Role: Client entry point. Orchestrates collection and fingerprinting; prints attributes and the final 64-hex device ID.
  - Why: A minimal, single-command way to run and see the output without any server.
  - Key behavior:
    - Calls `collect_device_attributes()` to gather identifiers.
    - Defines `include_keys` (board serial, cpu id, TPM fields, disk serial).
    - Calls `derive_fingerprint_sha256(..., normalize=False)` to hash values as-is.

- `dpa/collector.py`
  - Role: Collects Windows device identifiers.
  - Why: Centralizes OS- and TPM-specific queries to keep the client thin and consistent.
  - Sources:
    - BIOS/motherboard serial: WMI `Win32_BIOS.SerialNumber`.
    - CPU ID (best-effort): WMI `Win32_Processor.ProcessorId`.
    - Disk serial: WMI `Win32_DiskDrive.SerialNumber`.
    - TPM signals (via `dpa/tpm.py`):
      - EK public certificate PEM (preferred).
      - EK certificate serial number (if exposed).
      - Fallback TPM public material hash when PEM not available.
    - Output: Non-empty keys only; may include `tpm_attest_pub_pem` (PEM or fallback text), `tpm_ek_cert_serial`, `tpm_pubkey_hash`.

- `dpa/tpm.py`
  - Role: Windows TPM helpers with multiple fallbacks to extract EK public/serial.
  - Why: TPM exposure varies by OEM/Windows build; layered fallbacks improve robustness.
  - Main functions:
    - `get_ek_public_pem()`: Try PowerShell `TrustedPlatformModule` (ManufacturerCertificates[0]) for EK cert → PEM; fall back to `tpmtool getdeviceinformation` text if needed.
    - `get_ek_certificate_pem()`: Try `tpmtool getekcertificate`, read saved .cer → PEM.
    - `get_ek_certificate_serial()`: Read EK serial via `Get-TpmEndorsementKeyInfo` or parse `tpmtool getdeviceinformation`.
    - `get_ek_cert_from_certstore_pem_and_serial()`: Read EK cert from `Cert:\LocalMachine\Trusted Platform Module\Certificates`.
    - `get_ek_cert_from_registry_pem_and_serial()`: Read EK cert bytes from `HKLM\SOFTWARE\Microsoft\TPM\EKCertStore`.
    - `get_tpm_public_material_hash()`: As a last resort, compute a hash from any available public material text.

- `dpa/fingerprint.py`
  - Role: Deterministic canonicalization and cryptographic hashing.
  - Why: Guarantees the same input set always produces the same device ID; supports “as-is” hashing.
  - Key parts:
    - `canonicalize_attributes(..., include_keys, normalize=False)`: Build compact, sorted JSON from selected keys. When `normalize=False`, values are used exactly as collected.
    - `derive_fingerprint_sha256(..., include_keys, normalize=False)`: SHA-256 over the canonical JSON → 64-hex device ID.
    - Also includes HMAC variant (unused now) and helpers for stable keys.

## Optional .NET client
- `cs-client/ZTNA.DpaClient/` (C# console)
  - Why: Windows-centric alternative client that uses WMI and `tpmtool`/cert store APIs from .NET.
  - `Program.cs`: Mirrors Python client logic (collect → compute SHA-256 → print).
  - `ZTNA.DpaClient.csproj`: .NET 8 console app project.

## Tests
- `tests/test_fingerprint.py`
  - Role: Validates canonicalization determinism and that fingerprint/device_id are stable for the same inputs.
  - Why: Prevent regressions in the core hashing logic.

## Why these files exist
- Separation of concerns:
  - `collector.py` focuses on gathering stable identifiers from the OS/TPM.
  - `tpm.py` encapsulates all TPM peculiarities and fallbacks.
  - `fingerprint.py` guarantees deterministic input and secure hashing.
  - `client.py` is a simple, user-friendly runner.
- Windows-only enforcement:
  - Ensures consistent availability and semantics for WMI/TPM calls.
- Client-only mode:
  - No server; privacy and simplicity. Everything runs locally and prints outputs for demonstrations/documentation.

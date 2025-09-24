# Project Explanation

This repository implements a Windows‑only, client‑side device fingerprinting demo. It collects specific hardware/TPM attributes and derives a stable device identifier by hashing a canonicalized view of those attributes with SHA‑256. The codebase was originally client+server, but now runs fully locally (client‑only).

## Why this project exists
- Bind access to a real machine by using relatively stable, hardware‑centric attributes.
- Prefer TPM‑backed material where available (EK cert or public material) to make cloning harder.
- Keep the design minimal and auditable: collect → canonicalize → hash → print.

## File-by-file overview (what and why)

- `README.md`
  - Quick start and usage for the client‑only workflow.
  - Lists the attributes used and how the fingerprint is derived.

- `EXPLANATION.md` (this file)
  - Deep dive into architecture, files, and design decisions.

- `LICENSE`
  - MIT license for the project.

- `dpa/collector.py`
  - The attribute collector. Windows‑only enforcement.
  - Gathers:
    - `board_serial`: BIOS/motherboard serial via WMI/WMIC.
    - `cpu_id`: `Win32_Processor.ProcessorId` (best‑effort; not guaranteed unique on all hardware).
    - `disk_serial_or_uuid`: first physical disk serial via WMI/WMIC.
    - TPM‑related:
      - `tpm_attest_pub_pem` (when an EK certificate PEM is retrievable), or plain text info (fallback) if PEM is not available.
      - `tpm_ek_cert_serial` (when available via PowerShell/cert store/registry fallbacks).
      - `tpm_pubkey_hash`: SHA‑256 hash of the EK PEM/bytes (preferred) or other public material (fallback). Used in the fingerprint.
  - Drops empty keys and returns a compact dict of non‑empty attributes.
  - Why: central, auditable place to normalize access to platform‑specific hardware/TPM data.

- `dpa/tpm.py`
  - TPM helper utilities for Windows:
    - `get_ek_public_pem()`: Prefer PowerShell `TrustedPlatformModule`’s `Get-TpmEndorsementKeyInfo` ManufacturerCertificates export to DER→PEM. Falls back to `tpmtool` info if PEM cannot be retrieved.
    - `get_ek_certificate_pem()`: Reads EK certificate via `tpmtool getekcertificate` when supported, converting `.cer` to PEM.
    - `get_ek_certificate_serial()`: Reads EK certificate serial via the PowerShell module or `tpmtool` device information.
    - `get_ek_cert_from_certstore_pem_and_serial()`: Reads EK certificate and serial from the `LocalMachine/Trusted Platform Module/Certificates` store.
    - `get_ek_cert_from_registry_pem_and_serial()`: Reads EK cert bytes and serial from `HKLM\SOFTWARE\Microsoft\TPM\EKCertStore`.
  - Why: centralize Windows TPM retrieval with several fallbacks, recognizing differences across OEMs/Windows builds.

- `dpa/fingerprint.py`
  - Canonicalization and hashing logic.
  - `canonicalize_attributes(...)`:
    - Sorts keys, uses compact JSON, and (optionally) normalizes keys/values.
    - Optional `include_keys`/`exclude_keys` to control which attributes influence the hash.
    - An optional `normalize=False` mode to hash values “as‑is” (no lowercasing/trimming), as requested.
  - `derive_fingerprint_sha256(...)`: SHA‑256 over canonical JSON (no secret), returns a 64‑hex string used as the device ID.
  - Why: ensure deterministic input and a simple, secure hash result.

- `dpa/example_onboard.py`
  - Client‑only demo entrypoint.
  - Calls the collector, prints the attributes, and computes/displays the SHA‑256 device ID using the selected keys.
  - No server calls; kept small for clarity and demo purposes.

- `docs/design.md`
  - Design and threat‑model notes.
  - Now describes the client‑only flow: collect → canonicalize → hash → print.

- `docs/diagrams/*.mmd`
  - Mermaid sources for diagrams (architecture, collection workflow, fingerprint flow).
  - Optional: render to PNG/JPG locally with Mermaid CLI if you want embedded images.

- `tests/test_fingerprint.py`
  - Basic tests showing deterministic canonicalization and hash stability.
  - Why: guard against regressions in canonicalization or hashing behavior.

- `cs-client/ZTNA.DpaClient/*` (optional .NET client)
  - A .NET console client that mirrors the Python client flow on Windows.
  - Demonstrates WMI queries and TPM certificate retrieval in C#.

## Workflow (client-only)
1) Collector reads Windows attributes (BIOS serial, CPU ID, disk serial) via WMI/WMIC.
2) TPM helper attempts to retrieve EK certificate PEM and serial via multiple fallbacks. If PEM is not available, a public‑material hash (or tpmtool info) may be used so you still get `tpm_pubkey_hash`.
3) The fingerprint module canonicalizes a chosen subset of attributes and computes SHA‑256 to derive a 64‑hex device ID.
4) The client prints the attributes and the device ID.

## Why these attributes
- They are relatively stable on bare‑metal Windows installations.
- TPM EK certificate PEM/serial (when available) bind the identity to TPM hardware.
- Multiple fallbacks recognize OEM/Windows variability for EK provisioning.

## Security considerations
- SHA‑256 over canonical JSON provides a strong, collision‑resistant ID for the chosen attributes.
- Choosing a robust subset (e.g., `board_serial`, `cpu_id`, `disk_serial_or_uuid`, `tpm_pubkey_hash`, `tpm_ek_cert_serial`) reduces false changes.
- Normalization is optional; `normalize=False` keeps values exactly as read if you need strict fidelity.
- This is a demo; production systems often add attestation, signing, or policy engines.

## How to run
- Python client:
  - `python -m dpa.example_onboard`
  - Ensure Windows, Python 3.8+, and TPM ready (for EK data).
- Optional .NET client:
  - Install .NET 8 SDK and run the project in `cs-client/ZTNA.DpaClient`.

## Extending
- Add more attributes (e.g., GPU model, NIC PnP IDs) and evaluate their stability.
- Add optional TLS/remote APIs back if you later reintroduce a server.
- Render and commit diagram images for offline documentation (see `docs/diagrams/*.mmd`).

## Limitations
- CPU “serial” is not guaranteed to be unique on modern CPUs; treat it as a weak signal.
- EK certificate availability varies across OEMs/Windows editions and may require initialization/Internet.
- Virtualized/enterprise environments may mask serials.

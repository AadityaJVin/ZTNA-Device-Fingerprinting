# ZTNA-Device-Fingerprinting

Bind a device to relatively stable hardware attributes and derive a cryptographic Device ID for Zero Trust demos.

## Platform
- Windows only (enforced). The client will raise an error on non-Windows.

## Structure
- `dpa/`: Device client
  - `collector.py`: Collect Windows attributes (board serial, CPU ID, TPM EK public, disk serial/UUID)
  - `fingerprint.py`: Canonicalize + compute SHA-256 fingerprint over selected keys
  - `tpm.py`: Windows TPM helpers to read EK public or public material
  - `client.py`: Client entrypoint (collect + print + fingerprint)
- `docs/design.md`: Design & threat model
- `tests/test_fingerprint.py`: Fingerprint unit tests

## Diagram

## Requirements
- Windows with Python 3.8+
- TPM enabled (for EK public visibility, where available)

## Identity inputs (Windows)
- Motherboard/System BIOS serial
- CPU ID (best-effort)
- TPM attestation public key (EK) public material (when retrievable)
- Disk serial/UUID

## Fingerprint
- Canonicalize selected keys and compute `SHA-256` hex digest.
- Device ID equals the full 64-hex fingerprint.

## Quick start (client-only)
```powershell
python -m dpa.client
```
This will:
- Collect Windows attributes (shows `tpm_attest_pub_pem` head/tail if present)
- Compute and display the Device ID (SHA-256)

## WARNING
- This tool prints sensitive hardware identifiers: `board_serial`, `cpu_id`, `disk_serial_or_uuid`, TPM EK certificate/serial, `tpm_pubkey_hash`, `fingerprint`, and `device_id`.
- Do NOT share this output publicly. Treat it as confidential device identity material.
- The authors/code are not liable for any disclosure or misuse of the generated identifiers.

## Endpoints
Not applicable (server removed). Client runs fully locally.

## Notes
- EK public exposure depends on hardware/firmware and permissions; if not available, a TPM public material hash is used when possible.
- License: MIT



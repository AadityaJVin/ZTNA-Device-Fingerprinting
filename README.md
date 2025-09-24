# ZTNA-Device-Fingerprinting

Bind a device to relatively stable hardware attributes and derive a cryptographic Device ID for Zero Trust demos.

## Platform
- Windows only (enforced). The client will raise an error on non-Windows.

## Structure
- `dpa/`: Device client
  - `collector.py`: Collect Windows attributes (board serial, CPU ID, TPM EK public, disk serial/UUID)
  - `fingerprint.py`: Canonicalize + compute SHA-256 fingerprint over selected keys
  - `tpm.py`: Windows TPM helpers to read EK public or public material
  - `example_onboard.py`: Example onboarding/attestation client
- `server/`: Minimal HTTP server
  - `api.py`: `/onboard`, `/attest`, `/devices`
  - `storage.py`: JSON storage (`devices.json`)
- `docs/design.md`: Design & threat model
- `tests/test_fingerprint.py`: Fingerprint unit tests

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

## Quick start
1) Start the server:
```powershell
python -m server.api
```
2) Run the client:
```powershell
python -m dpa.example_onboard
```
This will:
- Collect Windows attributes (shows `tpm_attest_pub_pem` head/tail if present)
- POST to `/onboard`
- POST to `/attest`

3) List enrolled devices:
```text
GET http://127.0.0.1:8080/devices
```

## Endpoints
- `POST /onboard`: `{ "attributes": { ... } }` → `{ device_id, fingerprint }` (device_id == fingerprint)
- `POST /attest`: `{ "device_id", "attributes": { ... } }` → `{ status: "ok"|"mismatch", expected, actual }`
- `GET /devices`: `{ devices: { [device_id]: record } }`

## Notes
- EK public exposure depends on hardware/firmware and permissions; if not available, a TPM public material hash is used when possible.
- License: MIT

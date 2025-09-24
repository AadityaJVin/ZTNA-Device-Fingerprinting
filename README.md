# ZTNA-Device-Fingerprinting

Bind a device to relatively stable hardware/OS attributes and derive a cryptographic Device ID (HMAC) for Zero Trust Network Access demos.

## Structure
- `dpa/`: Device Provisioning Agent (client)
  - `collector.py`: Collect hardware/OS attributes
  - `fingerprint.py`: Canonicalize + HMAC fingerprint
  - `example_onboard.py`: Example onboarding/attestation client
- `server/`: Minimal HTTP server
  - `api.py`: `/onboard`, `/attest`, `/devices`
  - `storage.py`: JSON storage (`devices.json`)
- `docs/design.md`: Design & threat model
- `tests/test_fingerprint.py`: Fingerprint unit tests

## Requirements
- Python 3.8+

## Quick start
1) Start the server (in one terminal):
```bash
# Optional: set a strong secret (recommended)
$Env:DPA_SECRET = "d3c2f0..."   # PowerShell example
python -m server.api
```
Server listens at `http://127.0.0.1:8080` by default.

2) Run the example client (in another terminal):
```bash
# Optional: point to server and use same secret locally for preview
$Env:DPA_SERVER = "http://127.0.0.1:8080"
$Env:DPA_SECRET = "d3c2f0..."
python -m dpa.example_onboard
```
This will:
- Collect device attributes
- POST to `/onboard`
- POST to `/attest`

3) List enrolled devices:
```bash
# In a browser or HTTP client
GET http://127.0.0.1:8080/devices
```

## Endpoints
- `POST /onboard`: `{ "attributes": { ... } }` → `{ device_id, fingerprint }`
- `POST /attest`: `{ "device_id", "attributes": { ... } }` → `{ status: "ok"|"mismatch", expected, actual }`
- `GET /devices`: `{ devices: { [device_id]: record } }`

## Notes
- For demo only. Use TLS and a secure, rotated `DPA_SECRET` in production.
- Fingerprint stability depends on attribute quality; combine multiple signals.

## Testing
```bash
python -m pytest -q
```

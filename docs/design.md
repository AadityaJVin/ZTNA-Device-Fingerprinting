# ZTNA Device Fingerprinting - Design & Threat Model

## Scope
- Windows-only client (enforced). TPM-backed public material preferred.

## Fingerprint Inputs (Windows)
- BIOS/Motherboard serial
- CPU ID (best-effort)
- TPM attestation public key (EK) public material (or hash)
- Disk serial/UUID

## Canonicalization
- Normalize keys/values, include only the four inputs, sort keys, compact JSON.

## Fingerprint
- SHA-256 over canonical JSON (no shared secret). Full 64-hex is the device_id.

## Flows (client-only)
- Collect attributes locally and compute SHA-256 fingerprint.
- Display results; no server calls.

## Whitelisting
- Not applicable in client-only mode.

## Notes
- EK public availability varies; fallbacks attempt to read other TPM public material or skip if unavailable.

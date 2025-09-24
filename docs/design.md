# ZTNA Device Fingerprinting - Design & Threat Model

## Goals
- Bind an endpoint to a relatively stable set of device attributes.
- Derive a cryptographic identifier using HMAC over canonicalized attributes.
- Provide simple onboarding (/onboard) and attestation (/attest) over HTTP.

## Components
- `dpa/collector.py`: Collects OS/hardware attributes (MAC, serial, OS info).
- `dpa/fingerprint.py`: Canonicalization and HMAC-based fingerprint and short device ID.
- `server/api.py`: HTTP server with `/onboard` and `/attest`.
- `server/storage.py`: JSON file storage for device records.

## Canonicalization
- Convert all values to strings.
- Sort keys lexicographically.
- Serialize as compact JSON (no whitespace) to achieve stable input to HMAC.

## Fingerprint
- Use HMAC-SHA256 with server-held secret over canonical JSON.
- The full 64-hex HMAC is the `device_id` (no truncation).

## Onboarding Flow
1. Client collects attributes via `collect_device_attributes()`.
2. Client may compute local fingerprint/device_id for display.
3. Client POSTs attributes to `/onboard`.
4. Server canonicalizes, computes HMAC, stores record under `device_id`.

## Attestation Flow
1. Client POSTs `device_id` and current attributes to `/attest`.
2. Server recomputes HMAC and compares to stored fingerprint using constant-time compare.
3. Returns status `ok`/`mismatch`.

## Threat Model (abridged)
- Attacker can read traffic: TLS should be used in production; demo uses HTTP.
- Attacker can clone OS image: Inclusion of hardware-derived identifiers (serial, MAC) raises bar.
- MAC spoofing: Mitigated by combining multiple attributes; not fully prevented.
- Secret compromise on client: Not assumed; HMAC secret is server-held. Client code uses secret only for local preview.
- Server compromise: Records are in JSON; secret should be stored securely and rotated.

## Operational Notes
- Set `DPA_SECRET` to a strong random value on server.
- Persist storage volume; `devices.json` is small and human-readable.
- Prefer running behind a reverse proxy terminating TLS.

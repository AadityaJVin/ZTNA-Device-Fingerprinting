from __future__ import annotations

import json
import os

from dpa.collector import collect_device_attributes
from dpa.fingerprint import derive_fingerprint_sha256


def post_json(url: str, payload: dict) -> dict:
    raise NotImplementedError("Server calls are disabled in client-only mode.")


def main() -> None:
    # Client-only mode: no server URL or secrets needed

    attributes = collect_device_attributes()
    include = [
        "board_serial",
        "cpu_id",
        "tpm_pubkey_hash",
        "tpm_ek_cert_serial",
        "disk_serial_or_uuid",
    ]
    fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
    # Use full fingerprint as device_id
    device_id = fingerprint

    print("Attributes:")
    to_show = dict(attributes)
    # If EK is long, show first and last 120 chars for visual verification
    if "tpm_attest_pub_pem" in to_show:
        pem = to_show["tpm_attest_pub_pem"]
        if len(pem) > 260:
            to_show["tpm_attest_pub_pem"] = pem[:120] + " ... [truncated] ... " + pem[-120:]
    print(json.dumps(to_show, indent=2))
    print(json.dumps(to_show, indent=2))
    print(f"Local fingerprint: {fingerprint}")
    print(f"Device ID: {device_id}")

    # Server calls removed in client-only mode


if __name__ == "__main__":
    main()



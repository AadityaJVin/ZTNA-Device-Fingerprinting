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
    # Define a stable, ordered set of keys to both display and use for fingerprint derivation
    ordered_keys = [
        "board_serial",
        "cpu_id",
        "tpm_pubkey_hash",
        "tpm_ek_cert_serial",
        "disk_serial_or_uuid",
        # Display-only: include PEM presence (truncated) consistently
        "tpm_attest_pub_pem",
    ]
    include = [k for k in ordered_keys if k != "tpm_attest_pub_pem"]
    fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
    # Use full fingerprint as device_id
    device_id = fingerprint

    print("Attributes:")
    # Build a stable ordered view with defaults so output shape is identical across machines
    to_show = {}
    for key in ordered_keys:
        value = attributes.get(key, "")
        if key == "tpm_attest_pub_pem" and value:
            pem = value
            if len(pem) > 260:
                value = pem[:120] + " ... [truncated] ... " + pem[-120:]
        to_show[key] = value
    print(json.dumps(to_show, indent=2))
    print(f"Local fingerprint: {fingerprint}")
    print(f"Device ID: {device_id}")

    # Server calls removed in client-only mode


if __name__ == "__main__":
    main()



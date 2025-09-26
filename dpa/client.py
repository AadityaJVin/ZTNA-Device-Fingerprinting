from __future__ import annotations

import json

from dpa.collector import collect_device_attributes
from dpa.fingerprint import derive_fingerprint_sha256


def main() -> None:
    attributes = collect_device_attributes()
    ordered_keys = [
        "board_serial",
        "cpu_id",
        "tpm_pubkey_hash",
        "tpm_ek_cert_serial",
        "disk_serial_or_uuid",
        "tpm_attest_pub_pem",
    ]
    include = [k for k in ordered_keys if k != "tpm_attest_pub_pem"]
    fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
    device_id = fingerprint

    print("Attributes:")
    to_show = {}
    for key in ordered_keys:
        value = attributes.get(key, "")
        to_show[key] = value
    print(json.dumps(to_show, indent=2))
    print(f"Local fingerprint: {fingerprint}")
    print(f"Device ID: {device_id}")


if __name__ == "__main__":
    main()



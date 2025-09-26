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
    print("")
    cyan = "\033[96m"
    reset = "\033[0m"
    try:
        print(f"{cyan}Local fingerprint: {fingerprint}{reset}")
        print(f"{cyan}Device ID: {device_id}{reset}")
    except Exception:
        print(f"Local fingerprint: {fingerprint}")
        print(f"Device ID: {device_id}")
    print("")
    bold_red = "\033[1;91m"
    print(f"{bold_red}WARNING: This output contains sensitive hardware identifiers (board_serial, cpu_id, disk_serial_or_uuid, TPM EK cert/serial, tpm_pubkey_hash, fingerprint, device_id). DO NOT share publicly. The author/code is not liable for any disclosure.\033[0m")


if __name__ == "__main__":
    main()



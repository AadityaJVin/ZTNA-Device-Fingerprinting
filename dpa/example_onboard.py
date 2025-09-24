from __future__ import annotations

import json
import os
import urllib.request

from dpa.collector import collect_device_attributes
from dpa.fingerprint import derive_fingerprint_sha256


def post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:  # nosec B310 (example client)
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    server_url = os.environ.get("DPA_SERVER", "http://127.0.0.1:8080")
    secret = (os.environ.get("DPA_SECRET") or "dpa_demo_secret_key_change_me").encode("utf-8")

    attributes = collect_device_attributes()
    include = [
        "board_serial",
        "cpu_id",
        "tpm_pubkey_hash",
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
    print(f"Local fingerprint: {fingerprint}")
    print(f"Device ID: {device_id}")

    onboard_resp = post_json(f"{server_url}/onboard", {"attributes": attributes})
    print("Onboard response:")
    print(json.dumps(onboard_resp, indent=2))

    attest_resp = post_json(
        f"{server_url}/attest",
        {"device_id": onboard_resp.get("device_id", device_id), "attributes": attributes},
    )
    print("Attest response:")
    print(json.dumps(attest_resp, indent=2))


if __name__ == "__main__":
    main()



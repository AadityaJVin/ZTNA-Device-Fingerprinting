"""
Minimal onboarding server with /onboard and /attest endpoints.

Usage:
  set environment variable DPA_SECRET to a strong hex key (32 bytes recommended)
  python -m server.api
"""

from __future__ import annotations

import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Dict

from dpa.fingerprint import derive_fingerprint_sha256, canonicalize_attributes
from server.storage import JsonStorage
from dpa.fingerprint import default_stable_keys


def _load_secret() -> bytes:
    secret = os.environ.get("DPA_SECRET")
    if not secret:
        # For demo purposes only; DO NOT USE in production
        secret = "dpa_demo_secret_key_change_me"
    try:
        # Accept raw string, or hex string
        if all(c in "0123456789abcdefABCDEF" for c in secret) and len(secret) % 2 == 0:
            return bytes.fromhex(secret)
        return secret.encode("utf-8")
    except Exception:
        return secret.encode("utf-8")


class ApiHandler(BaseHTTPRequestHandler):
    storage = JsonStorage()
    secret = _load_secret()
    allow_first_enroll = os.environ.get("DPA_ALLOW_FIRST_ENROLL", "0") in ("1", "true", "True")

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        try:
            raw = self.rfile.read(length) if length > 0 else b"{}"
            req = json.loads(raw or b"{}")
        except Exception:
            self._send(400, {"error": "invalid_json"})
            return

        if self.path == "/onboard":
            self._handle_onboard(req)
        elif self.path == "/attest":
            self._handle_attest(req)
        else:
            self._send(404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/devices":
            self._send(200, {"devices": self.storage.list_devices()})
        else:
            self._send(404, {"error": "not_found"})

    def _handle_onboard(self, req: Dict[str, Any]) -> None:
        attributes = req.get("attributes")
        if not isinstance(attributes, dict):
            self._send(400, {"error": "missing_attributes"})
            return

        # Enforce whitelist by TPM public key hash if provided
        tpm_hash = attributes.get("tpm_pubkey_hash")
        if tpm_hash and not self.storage.is_whitelisted(tpm_hash):
            if not self.allow_first_enroll:
                self._send(403, {"error": "tpm_not_whitelisted"})
                return

        # Restrict to required stable keys
        include = [
            "board_serial",
            "cpu_id",
            "tpm_pubkey_hash",
            "tpm_ek_cert_serial",
            "disk_serial_or_uuid",
        ]
        canonical_json, _ = canonicalize_attributes(attributes, include_keys=include)
        fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
        # Use full HMAC as device_id for maximum security
        device_id = fingerprint

        record = {
            "device_id": device_id,
            "fingerprint": fingerprint,
            "attributes": json.loads(canonical_json),
        }
        self.storage.upsert_device(device_id, record)
        self._send(200, {"device_id": device_id, "fingerprint": fingerprint})

    def _handle_attest(self, req: Dict[str, Any]) -> None:
        device_id = req.get("device_id")
        attributes = req.get("attributes")
        if not device_id or not isinstance(attributes, dict):
            self._send(400, {"error": "missing_params"})
            return

        # Optional whitelist check on every attest
        tpm_hash = attributes.get("tpm_pubkey_hash")
        if tpm_hash and not self.storage.is_whitelisted(tpm_hash):
            self._send(403, {"error": "tpm_not_whitelisted"})
            return

        record = self.storage.get_device(device_id)
        if not record:
            self._send(404, {"error": "unknown_device"})
            return

        expected_fingerprint = record.get("fingerprint")
        include = [
            "board_serial",
            "cpu_id",
            "tpm_pubkey_hash",
            "disk_serial_or_uuid",
        ]
        actual_fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
        ok = hmac_compare_digest(expected_fingerprint, actual_fingerprint)
        status = "ok" if ok else "mismatch"
        self._send(200, {"status": status, "expected": expected_fingerprint, "actual": actual_fingerprint})


def hmac_compare_digest(a: str, b: str) -> bool:
    # constant-time comparison
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode("utf-8"), b.encode("utf-8")):
        result |= x ^ y
    return result == 0


def run(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = HTTPServer((host, port), ApiHandler)
    print(f"[ZTNA] Server listening on http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run()



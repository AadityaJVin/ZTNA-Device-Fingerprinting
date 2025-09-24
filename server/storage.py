"""
Simple JSON file storage for device onboarding records.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Optional


class JsonStorage:
    def __init__(self, path: str = "devices.json") -> None:
        self.path = path
        self._lock = threading.RLock()
        # Ensure file exists
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump({"devices": {}}, f)

    def is_whitelisted(self, tpm_pubkey_hash: str) -> bool:
        data = self._read()
        for dev in data.get("devices", {}).values():
            attrs = dev.get("attributes", {})
            if attrs.get("tpm_pubkey_hash") == tpm_pubkey_hash:
                return True
        return False

    def _read(self) -> Dict[str, Any]:
        with self._lock:
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return {"devices": {}}

    def _write(self, data: Dict[str, Any]) -> None:
        with self._lock:
            tmp_path = f"{self.path}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
            os.replace(tmp_path, self.path)

    def upsert_device(self, device_id: str, record: Dict[str, Any]) -> None:
        data = self._read()
        devices = data.setdefault("devices", {})
        devices[device_id] = record
        self._write(data)

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        data = self._read()
        return data.get("devices", {}).get(device_id)

    def list_devices(self) -> Dict[str, Any]:
        data = self._read()
        return data.get("devices", {})



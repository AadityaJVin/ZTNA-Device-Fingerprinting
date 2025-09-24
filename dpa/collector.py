"""
Device attribute collector

Collects relatively stable hardware and OS attributes to derive a device fingerprint.
Prefers built-in libraries; uses platform-specific commands only as fallbacks.
"""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import uuid
from typing import Dict, Optional
from dpa.tpm import get_tpm_public_material_hash, get_ek_public_pem


def _read_cmd_output(command: list[str]) -> Optional[str]:
    try:
        out = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def _get_primary_mac_address() -> Optional[str]:
    # uuid.getnode may return a random value on some systems; still use as baseline
    node = uuid.getnode()
    if (node >> 40) % 2 == 0:  # universally administered MAC
        return ":".join(f"{(node >> ele) & 0xFF:02x}" for ele in range(40, -1, -8))

    system = platform.system().lower()
    if system == "windows":
        text = _read_cmd_output(["getmac", "/FO", "CSV", "/NH"])
        if text:
            # pick the first MAC that is not all zeros
            for line in text.splitlines():
                parts = [p.strip('"') for p in line.split(",")]
                if parts:
                    mac = parts[0]
                    if mac and mac != "00-00-00-00-00-00":
                        return mac.replace("-", ":").lower()
    elif system == "darwin":
        text = _read_cmd_output(["networksetup", "-listallhardwareports"]) or ""
        current = {}
        for line in text.splitlines():
            if line.startswith("Hardware Port: "):
                current["port"] = line.split(": ", 1)[1]
            elif line.startswith("Device: "):
                current["device"] = line.split(": ", 1)[1]
            elif line.startswith("Ethernet Address: "):
                mac = line.split(": ", 1)[1]
                if mac and mac != "00:00:00:00:00:00":
                    return mac.lower()
    else:  # linux and others
        text = _read_cmd_output(["bash", "-lc", "cat /sys/class/net/*/address 2>/dev/null"]) or ""
        for mac in text.splitlines():
            mac = mac.strip().lower()
            if mac and mac != "00:00:00:00:00:00":
                return mac
    return None


def _get_system_serial() -> Optional[str]:
    system = platform.system().lower()
    if system == "windows":
        # Try wmic (deprecated but widely available), then PowerShell
        serial = _read_cmd_output(["wmic", "bios", "get", "serialnumber"])
        if serial:
            lines = [l.strip() for l in serial.splitlines() if l.strip() and "SerialNumber" not in l]
            if lines:
                return lines[0]
        serial = _read_cmd_output(["powershell", "-NoProfile", "(Get-CimInstance Win32_BIOS).SerialNumber"]) or None
        return serial.strip() if serial else None
    if system == "darwin":
        text = _read_cmd_output(["ioreg", "-l"]) or ""
        for line in text.splitlines():
            if "IOPlatformSerialNumber" in line:
                # Parse like: "IOPlatformSerialNumber" = "C02XXXXX"
                parts = line.split("=", 1)
                if len(parts) == 2:
                    value = parts[1].strip().strip('"')
                    if value:
                        return value
    # linux and others
    for path in [
        "/sys/devices/virtual/dmi/id/product_uuid",
        "/sys/devices/virtual/dmi/id/board_serial",
        "/sys/devices/virtual/dmi/id/product_serial",
    ]:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = f.read().strip()
                if data and data != "None":
                    return data
        except Exception:
            continue
    return None


def collect_device_attributes(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Collect a dictionary of device attributes.

    Only includes non-empty values. Callers can pass `extra` to append custom attributes.
    """
    attributes: Dict[str, str] = {}

    # Restrict to requested attributes: board/system serial, CPU ID (best-effort), TPM pubkey hash, disk serial/UUID
    # Motherboard/system serial
    serial = _get_system_serial()
    if serial:
        attributes["board_serial"] = serial

    # Processor ID (weak/non-unique on many systems; included if available)
    cpu_id = None
    try:
        if platform.system().lower() == "windows":
            text = _read_cmd_output(["wmic", "cpu", "get", "processorid"]) or ""
            lines = [l.strip() for l in text.splitlines() if l.strip() and "ProcessorId" not in l]
            if lines:
                cpu_id = lines[0]
        else:
            # Linux/macOS: no stable CPU serial; attempt model hash as last resort
            cpu_id = platform.processor() or platform.machine()
    except Exception:
        cpu_id = None
    if cpu_id:
        attributes["cpu_id"] = cpu_id

    # TPM attestation public key (EK) and derived hash (Windows focus)
    ek_pem = get_ek_public_pem()
    if ek_pem:
        attributes["tpm_attest_pub_pem"] = ek_pem
        attributes["tpm_pubkey_hash"] = hashlib.sha256(ek_pem.encode("utf-8")).hexdigest()
    else:
        # Fallback to other public material hash if available
        tpm_hash = get_tpm_public_material_hash()
        if tpm_hash:
            attributes["tpm_pubkey_hash"] = tpm_hash

    # Disk serial/UUID best-effort
    disk_id = None
    system = platform.system().lower()
    if system == "windows":
        text = _read_cmd_output(["wmic", "diskdrive", "get", "serialnumber"]) or ""
        lines = [l.strip() for l in text.splitlines() if l.strip() and "SerialNumber" not in l]
        if lines:
            disk_id = lines[0]
    elif system == "darwin":
        text = _read_cmd_output(["bash", "-lc", "diskutil info disk0 2>/dev/null | grep -E 'Device Identifier|Disk / Partition UUID' "]) or ""
        if text:
            disk_id = text.strip()
    else:
        text = _read_cmd_output(["bash", "-lc", "lsblk -ndo SERIAL,UUID 2>/dev/null | head -n1"]) or ""
        if text:
            disk_id = text.strip()
    if disk_id:
        attributes["disk_serial_or_uuid"] = disk_id

    # Optional extras
    if extra:
        for key, value in extra.items():
            if value is not None and value != "":
                attributes[key] = str(value)

    # Drop empty values
    attributes = {k: v for k, v in attributes.items() if v is not None and str(v) != ""}
    return attributes


if __name__ == "__main__":
    print(json.dumps(collect_device_attributes(), indent=2))



"""
Fingerprint generation

Canonicalizes device attributes and computes a stable HMAC-based fingerprint.

Enhanced capabilities (backward compatible defaults):
- Normalization of common attribute formats (e.g., MAC addresses)
- Versioned canonicalization for forward-compatibility
- Optional enrollment nonce binding to prevent replay/cloning across enrollments
- Include/exclude key filters to limit unstable attributes
- Configurable device ID length
"""

from __future__ import annotations

import hmac
import hashlib
import json
from typing import Dict, Iterable, Tuple, Optional, List, Set


def _normalize_mac(value: str) -> str:
    v = value.strip().lower().replace("-", ":")
    # zero-pad segments to 2 chars if needed
    parts = [p.zfill(2) for p in v.split(":") if p]
    return ":".join(parts)


def normalize_attributes(attributes: Dict[str, str]) -> Dict[str, str]:
    """Best-effort normalization for stability across OSes and formats.

    - Lowercase keys
    - Strip whitespace on values
    - Normalize common identifiers (MAC address)
    """
    normalized: Dict[str, str] = {}
    for key, value in attributes.items():
        k = str(key).strip().lower()
        v = "" if value is None else str(value).strip()
        if k in {"primary_mac", "mac", "ethernet_mac", "wifi_mac"} and v:
            v = _normalize_mac(v)
        normalized[k] = v
    return normalized


def canonicalize_attributes(
    attributes: Dict[str, str],
    *,
    version: str = "v1",
    include_keys: Optional[Iterable[str]] = None,
    exclude_keys: Optional[Iterable[str]] = None,
    enroll_nonce: Optional[str] = None,
) -> Tuple[str, str]:
    """Return (canonical_json, canonical_string) of attributes.

    - Normalize and convert all values to strings
    - Optionally filter with include/exclude lists (case-insensitive)
    - Optionally bind an enrollment nonce
    - Sort keys lexicographically
    - Compact JSON (no whitespace)
    - Also emit a newline-delimited key=value string for debugging
    """
    base = normalize_attributes(attributes)

    include: Optional[Set[str]] = set(k.lower() for k in include_keys) if include_keys else None
    exclude: Set[str] = set(k.lower() for k in exclude_keys) if exclude_keys else set()

    filtered: Dict[str, str] = {}
    for k, v in base.items():
        if include is not None and k not in include:
            continue
        if k in exclude:
            continue
        filtered[k] = v

    payload: Dict[str, str] = {
        "_canon_version": version,
        **filtered,
    }
    if enroll_nonce:
        payload["_enroll_nonce"] = str(enroll_nonce)

    items = sorted(payload.items(), key=lambda kv: kv[0])
    canonical_json = json.dumps({k: v for k, v in items}, separators=(",", ":"), ensure_ascii=False)
    canonical_string = "\n".join(f"{k}={v}" for k, v in items)
    return canonical_json, canonical_string


def derive_fingerprint_hmac(
    attributes: Dict[str, str],
    secret: bytes,
    hash_name: str = "sha256",
    *,
    version: str = "v1",
    include_keys: Optional[Iterable[str]] = None,
    exclude_keys: Optional[Iterable[str]] = None,
    enroll_nonce: Optional[str] = None,
) -> str:
    """Compute HMAC over canonical JSON with the provided secret.

    Optional parameters allow binding to a nonce and filtering attributes.
    Returns hex digest string.
    """
    canonical_json, _ = canonicalize_attributes(
        attributes,
        version=version,
        include_keys=include_keys,
        exclude_keys=exclude_keys,
        enroll_nonce=enroll_nonce,
    )
    digestmod = getattr(hashlib, hash_name)
    mac = hmac.new(secret, canonical_json.encode("utf-8"), digestmod)
    return mac.hexdigest()


def derive_device_id(
    attributes: Dict[str, str],
    secret: bytes,
    *,
    length: int = 32,
    version: str = "v1",
    include_keys: Optional[Iterable[str]] = None,
    exclude_keys: Optional[Iterable[str]] = None,
    enroll_nonce: Optional[str] = None,
) -> str:
    """Return a short device ID prefix of the HMAC.

    - `length`: hex chars to return (default 32 = 128 bits)
    - Other options must mirror the fingerprint call for consistent IDs
    """
    full = derive_fingerprint_hmac(
        attributes,
        secret,
        "sha256",
        version=version,
        include_keys=include_keys,
        exclude_keys=exclude_keys,
        enroll_nonce=enroll_nonce,
    )
    return full[:length]


def default_stable_keys() -> List[str]:
    """Suggestion of relatively stable keys for IoT/endpoint use.

    Caller may pass this list as `include_keys` to reduce volatility.
    """
    return [
        "os_name",
        "platform_machine",
        "platform_processor",
        "primary_mac",
        "system_serial",
    ]



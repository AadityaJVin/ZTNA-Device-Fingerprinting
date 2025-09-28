"""
Device Fingerprint Generation

Generates deterministic cryptographic fingerprints from hardware attributes.
- Canonicalizes attributes for consistent ordering and formatting
- Normalizes common identifiers (MAC addresses, serial numbers)
- Supports both HMAC (with secret) and SHA-256 (without secret) modes
- Filters attributes via include/exclude lists for stability
- Versioned canonicalization for forward compatibility
"""

from __future__ import annotations

import hmac
import hashlib
import json
from typing import Dict, Iterable, Tuple, Optional, List, Set
import hashlib


def _normalize_mac(value: str) -> str:
    """
    Normalize MAC address to consistent format.
    
    Converts to lowercase, replaces dashes with colons, and zero-pads segments.
    Example: "00-1A-2B-3C-4D-5E" -> "00:1a:2b:3c:4d:5e"
    """
    v = value.strip().lower().replace("-", ":")
    # Zero-pad segments to 2 chars if needed
    parts = [p.zfill(2) for p in v.split(":") if p]
    return ":".join(parts)


def normalize_attributes(attributes: Dict[str, str]) -> Dict[str, str]:
    """
    Normalize attributes for consistent fingerprinting across systems.
    
    Performs:
    - Lowercase all keys
    - Strip whitespace from values
    - Normalize MAC addresses to standard format
    - Convert None values to empty strings
    
    Args:
        attributes: Raw attribute dictionary
        
    Returns:
        Normalized attribute dictionary
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
    """
    Canonicalize attributes for deterministic fingerprinting.
    
    Creates a consistent representation by:
    - Normalizing all attribute values
    - Filtering by include/exclude key lists (case-insensitive)
    - Adding version and optional enrollment nonce
    - Sorting keys lexicographically
    - Generating compact JSON and debug string formats
    
    Args:
        attributes: Raw attribute dictionary
        version: Canonicalization version for forward compatibility
        include_keys: Only include these keys (if specified)
        exclude_keys: Exclude these keys from canonicalization
        enroll_nonce: Optional nonce to bind to enrollment
        
    Returns:
        Tuple of (canonical_json, canonical_debug_string)
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


def derive_fingerprint_sha256(
    attributes: Dict[str, str],
    *,
    version: str = "v1",
    include_keys: Optional[Iterable[str]] = None,
    exclude_keys: Optional[Iterable[str]] = None,
    enroll_nonce: Optional[str] = None,
) -> str:
    """
    Generate SHA-256 device fingerprint from hardware attributes.
    
    Creates a deterministic 64-character hex fingerprint by:
    - Canonicalizing selected attributes
    - Computing SHA-256 hash of canonical JSON
    - No shared secret required (uses attribute entropy)
    
    Args:
        attributes: Hardware attribute dictionary
        version: Canonicalization version
        include_keys: Only include these keys in fingerprint
        exclude_keys: Exclude these keys from fingerprint
        enroll_nonce: Optional enrollment nonce for binding
        
    Returns:
        64-character hex SHA-256 fingerprint
    """
    canonical_json, _ = canonicalize_attributes(
        attributes,
        version=version,
        include_keys=include_keys,
        exclude_keys=exclude_keys,
        enroll_nonce=enroll_nonce,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def derive_device_id(
    attributes: Dict[str, str],
    secret: bytes,
    *,
    length: int = 64,
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



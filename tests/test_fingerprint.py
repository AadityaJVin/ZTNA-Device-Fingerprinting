from __future__ import annotations

from dpa.fingerprint import canonicalize_attributes, derive_fingerprint_hmac, derive_device_id


def test_canonicalization_is_deterministic():
    attrs1 = {"b": "2", "a": "1"}
    attrs2 = {"a": "1", "b": "2"}
    j1, s1 = canonicalize_attributes(attrs1)
    j2, s2 = canonicalize_attributes(attrs2)
    assert j1 == j2
    assert s1 == s2


def test_hmac_and_device_id_stable():
    secret = b"secret"
    attrs = {"os": "linux", "mac": "00:11:22:33:44:55"}
    fp1 = derive_fingerprint_hmac(attrs, secret)
    fp2 = derive_fingerprint_hmac(dict(reversed(list(attrs.items()))), secret)
    assert fp1 == fp2
    dev1 = derive_device_id(attrs, secret)
    dev2 = derive_device_id(attrs, secret)
    assert dev1 == dev2



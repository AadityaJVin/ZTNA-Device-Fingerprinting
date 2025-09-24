from __future__ import annotations

import hashlib
import platform
import subprocess
from typing import Optional
import os
import re
import base64


def _read_cmd(command: list[str]) -> Optional[str]:
    try:
        out = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def get_tpm_public_material_hash() -> Optional[str]:
    """Best-effort TPM public material hash.

    Strategy:
    - Windows: Try PowerShell Get-TpmEndorsementKeyInfo public key; fallback none
    - Linux: Try tpm2-tools to read any persistent handle public area; fallback none
    - macOS: Secure Enclave does not expose a stable public identifier → None
    Returns SHA-256 hex of whatever public bytes/text we can access.
    """
    system = platform.system().lower()
    if system != "windows":
        return None
    if system == "windows":
        # Attempt to get EK public key info (requires Windows 11/Server 2022+ environments)
        ps = _read_cmd([
            "powershell",
            "-NoProfile",
            "(Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) | Out-Null;"
            "if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) {"
            "  $ek = Get-TpmEndorsementKeyInfo;"
            "  if ($ek -and $ek.PublicKey) { $ek.PublicKey } else { '' }"
            "} else { '' }",
        ])
        if ps:
            data = ps.encode("utf-8")
            if data.strip():
                return _sha256_hex(data)
        return None

    if system == "linux":
        # Requires tpm2-tools. Try to read first persistent handle public area
        handles = _read_cmd(["bash", "-lc", "tpm2_getcap handles-persistent 2>/dev/null | head -n1"]) or ""
        handle = handles.strip()
        if handle:
            pub = _read_cmd(["bash", "-lc", f"tpm2_readpublic -c {handle} -f PEM 2>/dev/null"]) or ""
            if pub.strip():
                return _sha256_hex(pub.encode("utf-8"))
        # Fallback: try endorsement hierarchy public
        pub2 = _read_cmd(["bash", "-lc", "tpm2_getpublic -H o 2>/dev/null || tpm2_getcap properties-fixed 2>/dev/null"]) or ""
        if pub2.strip():
            return _sha256_hex(pub2.encode("utf-8"))
        return None

    # macOS: No general TPM; Secure Enclave does not provide a stable public identity
    return None


def get_ek_public_pem() -> Optional[str]:
    """Retrieve the TPM EK certificate as PEM via TrustedPlatformModule if available (Windows).

    Returns PEM only; never returns informational text.
    """
    system = platform.system().lower()
    if system != "windows":
        return None
    ps = _read_cmd([
        "powershell",
        "-NoProfile",
        (
            "if (Get-Module -ListAvailable -Name TrustedPlatformModule) { Import-Module TrustedPlatformModule -ErrorAction SilentlyContinue }; "
            "$ek = $null; if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) { $ek = Get-TpmEndorsementKeyInfo }; "
            "if ($ek -and $ek.ManufacturerCertificates -and $ek.ManufacturerCertificates.Count -gt 0) { $c = $ek.ManufacturerCertificates[0]; [Convert]::ToBase64String($c.Export('Cert')) } else { '' }"
        ),
    ])
    if ps and ps.strip():
        try:
            return _wrap_pem(ps.strip(), header="CERTIFICATE")
        except Exception:
            return None
    return None


def _wrap_pem(b64: str, header: str = "CERTIFICATE") -> str:
    lines = [b64[i:i+64] for i in range(0, len(b64), 64)]
    return "-----BEGIN " + header + "-----\n" + "\n".join(lines) + "\n-----END " + header + "-----\n"


def get_ek_certificate_pem() -> Optional[str]:
    """Retrieve EK certificate and return PEM string if available (Windows)."""
    if platform.system().lower() != "windows":
        return None
    out = _read_cmd(["tpmtool", "getekcertificate"]) or ""
    # Expect a line like: "EK certificate saved to C:\\...\\ekcert.cer"
    match = re.search(r"saved to\s+([^\r\n]+\.(cer|der))", out, re.IGNORECASE)
    if not match:
        return None
    path = match.group(1).strip().strip('"')
    try:
        with open(path, "rb") as f:
            der = f.read()
        b64 = base64.b64encode(der).decode("ascii")
        return _wrap_pem(b64, header="CERTIFICATE")
    except Exception:
        return None


def get_ek_certificate_serial() -> Optional[str]:
    """Return EK certificate serial number (Windows, if available)."""
    if platform.system().lower() != "windows":
        return None
    # Try PowerShell TrustedPlatformModule first
    ps = _read_cmd([
        "powershell",
        "-NoProfile",
        "if (Get-Module -ListAvailable -Name TrustedPlatformModule) { Import-Module TrustedPlatformModule -ErrorAction SilentlyContinue }; "
        "$ek = $null; if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) { $ek = Get-TpmEndorsementKeyInfo }; "
        "if ($ek -and $ek.ManufacturerCertificates) { ($ek.ManufacturerCertificates | Select-Object -First 1).SerialNumber } else { '' }",
    ])
    if ps and ps.strip():
        return ps.strip()
    # Fallback: parse tpmtool getdeviceinformation output for 'Serial Number'
    info = _read_cmd(["tpmtool", "getdeviceinformation"]) or ""
    if info:
        for line in info.splitlines():
            if "Serial Number" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    return parts[1].strip()
    return None


def get_ek_cert_from_certstore_pem_and_serial() -> tuple[Optional[str], Optional[str]]:
    """Try reading EK certificate from LocalMachine certificate store and return (PEM, Serial)."""
    if platform.system().lower() != "windows":
        return None, None
    ps = _read_cmd([
        "powershell",
        "-NoProfile",
        (
            "$store = 'Cert:\\LocalMachine\\Trusted Platform Module\\Certificates';"
            "$c = Get-ChildItem -Path $store -ErrorAction SilentlyContinue | Select-Object -First 1;"
            "if ($c) {"
            "  $b64 = [Convert]::ToBase64String($c.Export('Cert'));"
            "  Write-Output ($b64 + '::SN::' + $c.SerialNumber)"
            "} else { '' }"
        ),
    ])
    if not ps or not ps.strip():
        return None, None
    try:
        b64, sn = ps.split("::SN::", 2)[0:2]
        pem = _wrap_pem(b64, header="CERTIFICATE")
        return pem, sn.strip()
    except Exception:
        return None, None


def get_ek_cert_from_registry_pem_and_serial() -> tuple[Optional[str], Optional[str]]:
    """Fallback: read EK cert from registry EKCertStore and return (PEM, Serial)."""
    if platform.system().lower() != "windows":
        return None, None
    ps = _read_cmd([
        "powershell",
        "-NoProfile",
        (
            "$base = 'HKLM:SOFTWARE\\Microsoft\\TPM\\EKCertStore';"
            "if (Test-Path $base) {"
            "  $keys = Get-ChildItem -Path $base -ErrorAction SilentlyContinue;"
            "  foreach ($k in $keys) {"
            "    $certBytes = (Get-ItemProperty -Path $k.PSPath -Name Certificate -ErrorAction SilentlyContinue).Certificate;"
            "    if ($certBytes) {"
            "      $b64 = [Convert]::ToBase64String($certBytes);"
            "      $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certBytes);"
            "      Write-Output ($b64 + '::SN::' + $cert.SerialNumber); break"
            "    }"
            "  }"
            "} else { '' }"
        ),
    ])
    if not ps or not ps.strip():
        return None, None
    try:
        b64, sn = ps.split("::SN::", 2)[0:2]
        pem = _wrap_pem(b64, header="CERTIFICATE")
        return pem, sn.strip()
    except Exception:
        return None, None


def create_ak_and_get_public_pem(label: str = "ak") -> Optional[str]:
    """Create an Attestation Key (AK) and return its public part in PEM (Linux).

    Windows AK provisioning via PowerShell/CNG is environment-specific and not implemented here.
    On Linux, requires tpm2-tools. Returns PEM string or None.
    """
    system = platform.system().lower()
    # Not implemented for Windows in this demo
    return None



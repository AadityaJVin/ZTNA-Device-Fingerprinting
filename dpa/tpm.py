from __future__ import annotations

import hashlib
import platform
import subprocess
from typing import Optional


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



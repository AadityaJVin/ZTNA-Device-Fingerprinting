"""
Hardware Attribute Collector

Collects stable hardware identifiers from Windows systems for device fingerprinting.
- BIOS/motherboard serial number via WMI
- CPU processor ID via WMI  
- Disk serial number via WMI
- TPM Endorsement Key certificate and serial via multiple methods
- TPM public key hash for fingerprinting

Uses PowerShell TrustedPlatformModule as primary TPM data source with fallbacks.
"""

from __future__ import annotations

import json
import platform
import subprocess
import hashlib
from typing import Dict, Optional
from dpa.tpm import (
    get_tpm_public_material_hash,
    get_ek_public_pem,
    get_ek_certificate_pem,
    get_ek_certificate_serial,
    get_ek_cert_from_certstore_pem_and_serial,
    get_ek_cert_from_registry_pem_and_serial,
)


def _read_cmd_output(command: list[str]) -> Optional[str]:
    try:
        out = subprocess.check_output(command, stderr=subprocess.DEVNULL)
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def _get_primary_mac_address() -> Optional[str]:
    # Windows: use getmac
    text = _read_cmd_output(["getmac", "/FO", "CSV", "/NH"])
    if text:
        for line in text.splitlines():
            parts = [p.strip('"') for p in line.split(",")]
            if parts:
                mac = parts[0]
                if mac and mac != "00-00-00-00-00-00":
                    return mac.replace("-", ":").lower()
    return None


def _get_system_serial() -> Optional[str]:
    # Windows BIOS serial
    serial = _read_cmd_output(["wmic", "bios", "get", "serialnumber"])
    if serial:
        lines = [l.strip() for l in serial.splitlines() if l.strip() and "SerialNumber" not in l]
        if lines:
            return lines[0]
    serial = _read_cmd_output(["powershell", "-NoProfile", "(Get-CimInstance Win32_BIOS).SerialNumber"]) or None
    return serial.strip() if serial else None


def collect_device_attributes(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """
    Collect stable hardware attributes for device fingerprinting.
    
    Collects:
    - BIOS/motherboard serial number (Win32_BIOS)
    - CPU processor ID (Win32_Processor)
    - Primary disk serial number (Win32_DiskDrive)
    - TPM Endorsement Key certificate and serial (multiple methods)
    - TPM public key hash
    
    Args:
        extra: Optional additional attributes to include
        
    Returns:
        Dict mapping attribute names to values (empty string if not available)
    """
    attributes: Dict[str, str] = {}

    # Enforce Windows-only for WMI and TPM access
    if platform.system().lower() != "windows":
        raise RuntimeError("This collector supports Windows only.")

    # Collect core hardware identifiers for device fingerprinting
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

    # TPM Endorsement Key (EK) collection - primary security identifier
    # Try multiple Windows sources for EK certificate and serial with comprehensive error handling
    print("Collecting TPM data...")
    
    # Method 1: PowerShell TrustedPlatformModule (most reliable for TPM EK access)
    try:
        import subprocess
        # PowerShell script to get TPM Endorsement Key certificate and serial
        ps_script = """
        if (Get-Module -ListAvailable -Name TrustedPlatformModule) { 
            Import-Module TrustedPlatformModule -ErrorAction SilentlyContinue 
        }
        $ek = $null
        if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) { 
            $ek = Get-TpmEndorsementKeyInfo 
        }
        if ($ek) {
            $cert = $null
            if ($ek.ManufacturerCertificates -and $ek.ManufacturerCertificates.Count -gt 0) { 
                $cert = $ek.ManufacturerCertificates | Select-Object -First 1 
            }
            if ($cert) {
                $serial = $cert.SerialNumber
                $b64 = [Convert]::ToBase64String($cert.Export('Cert'))
                # Split base64 into 64-character lines for proper PEM formatting
                $lines = @()
                for ($i = 0; $i -lt $b64.Length; $i += 64) {
                    $lineLength = [Math]::Min(64, $b64.Length - $i)
                    $lines += $b64.Substring($i, $lineLength)
                }
                $pem = '-----BEGIN CERTIFICATE-----' + [Environment]::NewLine + 
                       ($lines -join [Environment]::NewLine) + [Environment]::NewLine + 
                       '-----END CERTIFICATE-----'
                Write-Output "SERIAL:$serial"
                Write-Output "PEM:$pem"
            } else {
                Write-Output "SERIAL:"
                Write-Output "PEM:"
            }
        } else {
            Write-Output "SERIAL:"
            Write-Output "PEM:"
        }
        """
        
        result = subprocess.run(['powershell', '-NoProfile', '-Command', ps_script], 
                              capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            # Parse PowerShell output to extract serial and PEM certificate
            serial = ""
            pem = ""
            in_pem = False
            pem_lines = []
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('SERIAL:'):
                    serial = line[7:].strip()
                elif line.startswith('PEM:'):
                    pem_content = line[4:].strip()
                    if pem_content:
                        pem = pem_content
                    in_pem = True
                elif in_pem and line and not line.startswith('SERIAL:'):
                    pem_lines.append(line)
            
            # Reconstruct full PEM if it was split across multiple lines
            if pem_lines:
                pem = pem + '\n' + '\n'.join(pem_lines)
            
            # Validate and store complete TPM EK certificate
            if pem and pem.startswith('-----BEGIN') and '-----END CERTIFICATE-----' in pem:
                attributes["tpm_attest_pub_pem"] = pem
                attributes["tpm_pubkey_hash"] = hashlib.sha256(pem.encode("utf-8")).hexdigest()
                print("  ✓ TPM EK via PowerShell")
            elif pem and pem.startswith('-----BEGIN'):
                print(f"  ⚠ TPM EK partial via PowerShell (length: {len(pem)})")
            if serial:
                attributes["tpm_ek_cert_serial"] = serial
                print("  ✓ TPM EK serial via PowerShell")
    except Exception as e:
        print(f"  ✗ PowerShell TPM error: {e}")
    
    # Method 2: Fallback to alternative TPM data sources if PowerShell failed
    if not attributes.get("tpm_attest_pub_pem"):
        print("  Trying fallback TPM methods...")
        
        # Try direct EK public key extraction
        ek_pem = get_ek_public_pem()
        if ek_pem and ek_pem.lstrip().startswith("-----BEGIN"):
            attributes["tpm_attest_pub_pem"] = ek_pem
            attributes["tpm_pubkey_hash"] = hashlib.sha256(ek_pem.encode("utf-8")).hexdigest()
            print("  ✓ TPM EK via get_ek_public_pem")
        elif not ek_pem:
            # Try EK certificate extraction
            ek_pem = get_ek_certificate_pem()
            if ek_pem:
                attributes["tpm_attest_pub_pem"] = ek_pem
                attributes["tpm_pubkey_hash"] = hashlib.sha256(ek_pem.encode("utf-8")).hexdigest()
                print("  ✓ TPM EK via get_ek_certificate_pem")
        
        # Try Windows certificate store for EK certificate
        if not attributes.get("tpm_ek_cert_serial"):
            pem2, sn2 = get_ek_cert_from_certstore_pem_and_serial()
            if sn2:
                attributes["tpm_ek_cert_serial"] = sn2
                print("  ✓ TPM EK serial via cert store")
            elif not attributes.get("tpm_attest_pub_pem") and pem2:
                attributes["tpm_attest_pub_pem"] = pem2
                attributes["tpm_pubkey_hash"] = hashlib.sha256(pem2.encode("utf-8")).hexdigest()
                print("  ✓ TPM EK via cert store")
        
        # Try Windows registry for EK certificate
        if not attributes.get("tpm_ek_cert_serial"):
            pem3, sn3 = get_ek_cert_from_registry_pem_and_serial()
            if sn3:
                attributes["tpm_ek_cert_serial"] = sn3
                print("  ✓ TPM EK serial via registry")
            elif not attributes.get("tpm_attest_pub_pem") and pem3:
                attributes["tpm_attest_pub_pem"] = pem3
                attributes["tpm_pubkey_hash"] = hashlib.sha256(pem3.encode("utf-8")).hexdigest()
                print("  ✓ TPM EK via registry")
    
    # Final fallback: try to get TPM public material hash if no certificate available
    if not attributes.get("tpm_pubkey_hash"):
        tpm_hash = get_tpm_public_material_hash()
        if tpm_hash:
            attributes["tpm_pubkey_hash"] = tpm_hash
            print("  ✓ TPM hash via public material")
    
    # Final serial fallback: try direct serial extraction
    if not attributes.get("tpm_ek_cert_serial"):
        ek_serial = get_ek_certificate_serial()
        if ek_serial:
            attributes["tpm_ek_cert_serial"] = ek_serial
            print("  ✓ TPM EK serial via final fallback")


    # Disk serial/UUID best-effort
    disk_id = None
    text = _read_cmd_output(["wmic", "diskdrive", "get", "serialnumber"]) or ""
    lines = [l.strip() for l in text.splitlines() if l.strip() and "SerialNumber" not in l]
    if lines:
        disk_id = lines[0]
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



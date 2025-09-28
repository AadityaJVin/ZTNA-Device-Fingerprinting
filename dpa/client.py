"""
ZTNA Device Fingerprinting Client

Main entry point for hardware-based device fingerprinting.
- Automatically requests administrator privileges for TPM access
- Runs comprehensive system diagnostics
- Collects hardware attributes and generates device fingerprint
- Displays results with colorized output and security warnings
"""

from __future__ import annotations

import json
import sys
import ctypes
import subprocess
import platform

from dpa.collector import collect_device_attributes
from dpa.fingerprint import derive_fingerprint_sha256


def main() -> None:
    """
    Main execution flow for device fingerprinting.
    
    Workflow:
    1. Check for admin privileges, request elevation if needed
    2. Run system diagnostics to verify TPM/hardware access
    3. Collect hardware attributes (BIOS, CPU, disk, TPM)
    4. Generate device fingerprint from canonicalized attributes
    5. Display results with colorized output and security warnings
    """
    # Check and request admin elevation - TPM access requires elevated privileges
    if not is_admin():
        print("This tool requires administrator privileges for full TPM access.")
        print("Requesting elevation...")
        try:
            # Use Windows UAC to elevate the current process
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        except Exception as e:
            print(f"Failed to elevate: {e}")
            print("Please run as administrator manually.")
            sys.exit(1)
    
    print("Running with administrator privileges.")
    print("=" * 60)
    
    # Run comprehensive diagnostics to verify system capabilities
    run_diagnostics()
    print("=" * 60)
    
    # Collect hardware attributes from Windows WMI and TPM
    attributes = collect_device_attributes()
    
    # Define the ordered set of keys for consistent output display
    ordered_keys = [
        "board_serial",        # Motherboard/BIOS serial number
        "cpu_id",             # CPU processor ID
        "tpm_pubkey_hash",    # SHA-256 hash of TPM EK certificate
        "tpm_ek_cert_serial", # TPM EK certificate serial number
        "disk_serial_or_uuid", # Primary disk serial number
        "tpm_attest_pub_pem", # Full TPM EK certificate in PEM format
    ]
    
    # Exclude PEM from fingerprint calculation (too large, use hash instead)
    include = [k for k in ordered_keys if k != "tpm_attest_pub_pem"]
    
    # Generate deterministic device fingerprint from selected attributes
    fingerprint = derive_fingerprint_sha256(attributes, include_keys=include)
    device_id = fingerprint  # Device ID is the same as fingerprint

    # Display collected attributes in JSON format
    print("Attributes:")
    to_show = {}
    for key in ordered_keys:
        value = attributes.get(key, "")
        to_show[key] = value
    print(json.dumps(to_show, indent=2))
    print("")
    
    # Display fingerprint and device ID with cyan color (if supported)
    cyan = "\033[96m"
    reset = "\033[0m"
    try:
        print(f"{cyan}Local fingerprint: {fingerprint}{reset}")
        print(f"{cyan}Device ID: {device_id}{reset}")
    except Exception:
        # Fallback to plain text if color codes fail
        print(f"Local fingerprint: {fingerprint}")
        print(f"Device ID: {device_id}")
    print("")
    
    # Display security warning in bold red
    bold_red = "\033[1;91m"
    print(f"{bold_red}WARNING: This output contains sensitive hardware identifiers (board_serial, cpu_id, disk_serial_or_uuid, TPM EK cert/serial, tpm_pubkey_hash, fingerprint, device_id). DO NOT share publicly. The author/code is not liable for any disclosure.\033[0m")


def is_admin():
    """
    Check if the current process is running with administrator privileges.
    
    Returns:
        bool: True if running as admin, False otherwise
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_diagnostics():
    """
    Run comprehensive system diagnostics to verify hardware access capabilities.
    
    Checks:
    - Operating system and Python version
    - TPM status and availability
    - PowerShell TrustedPlatformModule availability
    - WMI access for hardware attributes
    - TPM tools availability
    """
    print("DIAGNOSTICS REPORT")
    print("-" * 40)
    
    # Display system information
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Python: {sys.version}")
    
    # Verify TPM functionality and access
    check_tpm_status()
    
    # Check PowerShell module availability
    check_powershell_modules()
    
    # Test WMI access for hardware attributes
    check_wmi_access()
    
    # Verify TPM command-line tools
    check_tpm_tools()


def check_tpm_status():
    """
    Check TPM status using PowerShell Get-Tpm cmdlet.
    
    Verifies:
    - TPM presence and readiness
    - TPM enabled status
    - Basic TPM information
    """
    print("\nTPM Status:")
    try:
        result = subprocess.run(['powershell', '-Command', 'Get-Tpm'], 
                             capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  ✓ TPM PowerShell cmdlets available")
            lines = result.stdout.strip().split('\n')
            for line in lines[:3]:  # Show first 3 lines
                if line.strip():
                    print(f"    {line.strip()}")
        else:
            print(f"  ✗ TPM PowerShell error: {result.stderr.strip()}")
    except Exception as e:
        print(f"  ✗ TPM PowerShell error: {e}")


def check_powershell_modules():
    """
    Check if PowerShell TrustedPlatformModule is available.
    
    This module is required for accessing TPM Endorsement Key information.
    """
    print("\nPowerShell Modules:")
    try:
        result = subprocess.run(['powershell', '-Command', 
                               'Get-Module -ListAvailable TrustedPlatformModule'], 
                             capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and 'TrustedPlatformModule' in result.stdout:
            print("  ✓ TrustedPlatformModule available")
        else:
            print("  ✗ TrustedPlatformModule not found")
    except Exception as e:
        print(f"  ✗ PowerShell module check error: {e}")


def check_wmi_access():
    """
    Test WMI access for hardware attribute collection.
    
    Verifies access to:
    - BIOS serial number (Win32_BIOS)
    - CPU processor ID (Win32_Processor) 
    - Disk serial number (Win32_DiskDrive)
    """
    print("\nWMI Access:")
    wmi_checks = [
        ("BIOS Serial", "Win32_BIOS", "SerialNumber"),
        ("CPU ID", "Win32_Processor", "ProcessorId"),
        ("Disk Serial", "Win32_DiskDrive", "SerialNumber")
    ]
    
    for name, class_name, property_name in wmi_checks:
        try:
            result = subprocess.run(['powershell', '-Command', 
                                   f'Get-CimInstance {class_name} | Select-Object -First 1 -ExpandProperty {property_name}'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                print(f"  ✓ {name}: {result.stdout.strip()[:50]}...")
            else:
                print(f"  ✗ {name}: Not accessible")
        except Exception as e:
            print(f"  ✗ {name}: Error - {e}")


def check_tpm_tools():
    """
    Check availability of Windows TPM command-line tools.
    
    Tests tpmtool.exe for basic TPM device information access.
    """
    print("\nTPM Tools:")
    try:
        result = subprocess.run(['tpmtool', 'getdeviceinformation'], 
                             capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("  ✓ tpmtool available")
            # Show TPM info
            lines = result.stdout.split('\n')[:5]  # First 5 lines
            for line in lines:
                if line.strip():
                    print(f"    {line.strip()}")
        else:
            print(f"  ✗ tpmtool error: {result.stderr.strip()}")
    except Exception as e:
        print(f"  ✗ tpmtool error: {e}")


if __name__ == "__main__":
    main()



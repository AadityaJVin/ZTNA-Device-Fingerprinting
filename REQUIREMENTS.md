## Device Fingerprinting Requirements (Windows)

This document lists the prerequisites and steps to ensure the onboarding script consistently outputs all expected attributes.

Target attributes to populate:
- board_serial
- cpu_id
- tpm_attest_pub_pem (real PEM, begins with "-----BEGIN CERTIFICATE-----")
- tpm_ek_cert_serial
- tpm_pubkey_hash
- disk_serial_or_uuid

General notes:
- Run in Windows PowerShell as Administrator.
- Python 3.9+ on PATH. No extra Python packages are required.
- This collector supports Windows only.

1) Enable TPM 2.0 in BIOS/UEFI
- Intel: enable PTT (Platform Trust Technology)
- AMD: enable fTPM
- Save and reboot
- Verify: run `tpm.msc` → TPM is ready for use; Specification Version: 2.0

2) Ensure Windows TPM tooling is available
- PowerShell module (usually built-in):
  - `Get-Module -ListAvailable TrustedPlatformModule`
- TPM tool:
  - `tpmtool getdeviceinformation`
- If missing, update Windows to the latest build and try again.

3) Obtain EK certificate (for real PEM and serial)
- Request EK certificate (prints the saved path):
  - `tpmtool getekcertificate`
- Verify serial from the saved cert:
  - `$p = "<path from above>"`
  - `$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($p)`
  - `$c.SerialNumber`
- Optional (helps multiple methods succeed): import cert into Local Machine TPM store:
  - `$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Trusted Platform Module","LocalMachine")`
  - `$store.Open("ReadWrite")`
  - `$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($p)`
  - `$store.Add($cert)`
  - `$store.Close()`

4) Board/motherboard serial should be readable
- `wmic bios get serialnumber`
- Fallback:
  - `(Get-CimInstance Win32_BIOS).SerialNumber`
- If empty, check OEM/BIOS privacy settings; update BIOS/UEFI; disable serial masking.

5) CPU ID (ProcessorId)
- `wmic cpu get processorid`
- If empty, verify virtualization/security settings aren’t masking CPUID; many systems still return it.

6) Disk serial/UUID
- `wmic diskdrive get serialnumber`
- If empty, update storage drivers in Device Manager; try another controller/port if applicable.

7) Validate TrustedPlatformModule cmdlets
- `Import-Module TrustedPlatformModule`
- `Get-TpmEndorsementKeyInfo`
- If ManufacturerCertificates are shown, the EK certificate/serial should populate.

8) Run the script
- `python -m dpa.example_onboard`

Expected behavior after setup:
- `tpm_attest_pub_pem` will be a real PEM (begins with "-----BEGIN CERTIFICATE-----").
- `tpm_ek_cert_serial` and `tpm_pubkey_hash` are non-empty.
- `board_serial`, `cpu_id`, and `disk_serial_or_uuid` are non-empty unless the platform masks them.

Troubleshooting (if attributes are blank):
- Ensure you are on Windows and using an elevated PowerShell.
- Check PATH includes System32 (for `tpmtool`, `wmic`).
- Make sure TPM is ready in `tpm.msc`.
- Apply Windows updates and reboot.



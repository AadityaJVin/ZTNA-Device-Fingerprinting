/*
 * ZTNA Device Fingerprinting C# Client
 * 
 * Collects hardware attributes and generates device fingerprints for Zero Trust Network Access.
 * - Collects BIOS serial, CPU ID, disk serial, TPM EK certificate via WMI and PowerShell
 * - Generates deterministic SHA-256 device fingerprint
 * - Supports optional server communication for device attestation
 * - Displays results with colorized output and security warnings
 */

using System;
using System.IO;
using System.Linq;
using System.Management; // for WMI
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Cryptography.X509Certificates;

class Program
{
    /// <summary>
    /// Main entry point for device fingerprinting client.
    /// Collects hardware attributes, generates fingerprint, and optionally communicates with server.
    /// </summary>
    static int Main(string[] args)
    {
        try
        {
            // Collect hardware attributes from Windows WMI and TPM
            var attributes = CollectAttributes();
            
            // Define keys to include in fingerprint calculation (exclude large PEM)
            var includeKeys = new[] { "board_serial", "cpu_id", "tpm_attest_pub_pem", "tpm_pubkey_hash", "tpm_ek_cert_serial", "disk_serial_or_uuid" };
            
            // Canonicalize attributes and generate SHA-256 fingerprint
            var canonical = Canonicalize(attributes, includeKeys);
            var fingerprint = Sha256Hex(Encoding.UTF8.GetBytes(canonical));

            // Display collected attributes in JSON format
            Console.WriteLine("Attributes:");
            var toShow = new System.Collections.Generic.Dictionary<string, string>(attributes);
            Console.WriteLine(JsonSerializer.Serialize(toShow, new JsonSerializerOptions { WriteIndented = true }));

            // Display fingerprint and device ID with cyan color
            Console.WriteLine();
            var cyan = "\u001b[96m";
            var reset = "\u001b[0m";
            try
            {
                Console.WriteLine($"{cyan}Local fingerprint: {fingerprint}{reset}");
                Console.WriteLine($"{cyan}Device ID: {fingerprint}{reset}");
            }
            catch
            {
                Console.WriteLine($"Local fingerprint: {fingerprint}");
                Console.WriteLine($"Device ID: {fingerprint}");
            }
            Console.WriteLine();
            var boldRed = "\u001b[1;91m";
            Console.WriteLine($"{boldRed}WARNING: This output contains sensitive hardware identifiers (board_serial, cpu_id, disk_serial_or_uuid, TPM EK cert/serial, tpm_pubkey_hash, fingerprint, device_id). DO NOT share publicly. The author/code is not liable for any disclosure.\u001b[0m");

            var server = Environment.GetEnvironmentVariable("DPA_SERVER");
            if (!string.IsNullOrWhiteSpace(server))
            {
                using var http = new HttpClient();
                var onboardPayload = new { attributes };
                var onboardResp = http.PostAsJsonAsync(server + "/onboard", onboardPayload).Result;
                var onboardJson = onboardResp.Content.ReadAsStringAsync().Result;
                Console.WriteLine("Onboard response:");
                Console.WriteLine(onboardJson);

                using var doc = JsonDocument.Parse(onboardJson);
                var deviceId = doc.RootElement.GetProperty("device_id").GetString() ?? fingerprint;
                var attestPayload = new { device_id = deviceId, attributes };
                var attestResp = http.PostAsJsonAsync(server + "/attest", attestPayload).Result;
                Console.WriteLine("Attest response:");
                Console.WriteLine(attestResp.Content.ReadAsStringAsync().Result);
            }
            else
            {
                Console.WriteLine("Skipping server calls (client-only mode). Set DPA_SERVER to enable.");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    /// <summary>
    /// Canonicalize attributes for deterministic fingerprinting.
    /// Filters to include only specified keys, sorts alphabetically, and creates compact JSON.
    /// </summary>
    static string Canonicalize(System.Collections.Generic.IDictionary<string, string> attrs, string[] include)
    {
        var filtered = attrs
            .Where(kv => include.Contains(kv.Key))
            .OrderBy(kv => kv.Key)
            .ToDictionary(kv => kv.Key, kv => kv.Value ?? string.Empty);
        return JsonSerializer.Serialize(filtered, new JsonSerializerOptions { WriteIndented = false });
    }

    /// <summary>
    /// Compute SHA-256 hash and return as hex string.
    /// </summary>
    static string Sha256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    /// <summary>
    /// Collect hardware attributes for device fingerprinting.
    /// Gathers BIOS serial, CPU ID, disk serial, and TPM Endorsement Key data.
    /// </summary>
    static System.Collections.Generic.Dictionary<string, string> CollectAttributes()
    {
        var dict = new System.Collections.Generic.Dictionary<string, string>();

        // Get motherboard/BIOS serial number via WMI
        dict["board_serial"] = QueryWmiSingle("Win32_BIOS", "SerialNumber") ?? string.Empty;

        // Get CPU processor ID via WMI (best-effort, may not be unique)
        dict["cpu_id"] = QueryWmiSingle("Win32_Processor", "ProcessorId") ?? string.Empty;

        // Get primary disk serial number via WMI
        dict["disk_serial_or_uuid"] = QueryWmiSingle("Win32_DiskDrive", "SerialNumber") ?? string.Empty;

        // Get TPM Endorsement Key certificate and serial from multiple sources
        var (pem, serial, pubMaterial) = TryGetEkViaPreferredSources();
        if (!string.IsNullOrWhiteSpace(pem))
        {
            dict["tpm_attest_pub_pem"] = pem;
        }
        if (!string.IsNullOrWhiteSpace(serial))
        {
            dict["tpm_ek_cert_serial"] = serial;
        }
        if (!string.IsNullOrWhiteSpace(pem))
        {
            // Use full PEM certificate for hash
            dict["tpm_pubkey_hash"] = Sha256Hex(Encoding.UTF8.GetBytes(pem));
        }
        else if (!string.IsNullOrWhiteSpace(pubMaterial))
        {
            // Fallback to public key material hash
            dict["tpm_pubkey_hash"] = Sha256Hex(Encoding.UTF8.GetBytes(pubMaterial));
        }

        // Remove empty values to keep output clean
        var keys = dict.Keys.ToList();
        foreach (var k in keys) if (string.IsNullOrWhiteSpace(dict[k])) dict.Remove(k);
        return dict;
    }

    /// <summary>
    /// Query WMI for a single property value from the first matching object.
    /// </summary>
    static string? QueryWmiSingle(string wmiClass, string property)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
            foreach (ManagementObject obj in searcher.Get())
            {
                var val = obj[property];
                if (val != null)
                {
                    var s = val.ToString();
                    if (!string.IsNullOrWhiteSpace(s)) return s;
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>
    /// Try multiple sources to get TPM Endorsement Key certificate and serial.
    /// Prioritizes PowerShell TrustedPlatformModule, then certificate store, then tpmtool.
    /// </summary>
    static (string? pem, string? serial, string? pubMaterial) TryGetEkViaPreferredSources()
    {
        // 1) PowerShell TrustedPlatformModule (most reliable)
        var (pemPs, serialPs, pubPs) = GetEkViaPowerShell();
        if (!string.IsNullOrWhiteSpace(pemPs) || !string.IsNullOrWhiteSpace(serialPs) || !string.IsNullOrWhiteSpace(pubPs))
        {
            return (pemPs, serialPs, pubPs);
        }
        
        // 2) Windows certificate store fallback
        var (pemStore, snStore) = GetEkCertFromCertStore();
        if (!string.IsNullOrWhiteSpace(pemStore) || !string.IsNullOrWhiteSpace(snStore))
        {
            return (pemStore, snStore, null);
        }
        
        // 3) tpmtool device info as last resort for serial only
        var info = GetTpmDeviceInfoViaTpmtool();
        string? serialFromInfo = null;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var line = info.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                           .FirstOrDefault(s => s.Contains("Serial Number", StringComparison.OrdinalIgnoreCase));
            if (line != null)
            {
                var parts = line.Split(':');
                if (parts.Length >= 2) serialFromInfo = parts[1].Trim();
            }
        }
        return (null, serialFromInfo, null);
    }

    static (string? pem, string? serial, string? publicMaterial) GetEkViaPowerShell()
    {
        try
        {
            // Ensure module and fetch EK
            string script = string.Join("; ", new[]
            {
                "if (Get-Module -ListAvailable -Name TrustedPlatformModule) { Import-Module TrustedPlatformModule -ErrorAction SilentlyContinue }",
                "$ek = $null; if (Get-Command Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue) { $ek = Get-TpmEndorsementKeyInfo }",
                // Emit three lines separated by markers so we can parse reliably
                "if ($ek) {",
                "  $cert = $null; if ($ek.ManufacturerCertificates -and $ek.ManufacturerCertificates.Count -gt 0) { $cert = $ek.ManufacturerCertificates | Select-Object -First 1 }",
                "  $serial = if ($cert) { $cert.SerialNumber } else { '' }",
                "  $pemb64 = if ($cert) { [Convert]::ToBase64String($cert.Export('Cert')) } else { '' }",
                "  $pub = if ($ek.PublicKey) { $ek.PublicKey.Format($false) } else { '' }",
                "  Write-Output ('__SERIAL__:' + $serial)",
                "  Write-Output ('__PEM_B64__:' + $pemb64)",
                "  Write-Output ('__PUB__:' + $pub)",
                "} else { Write-Output '__SERIAL__:'; Write-Output '__PEM__:'; Write-Output '__PUB__:' }"
            });

            var psPath = Environment.ExpandEnvironmentVariables(@"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
            var psi = new ProcessStartInfo(psPath, "-NoProfile -ExecutionPolicy Bypass -Command \"" + script.Replace("\"", "\\\"") + "\"")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);

            string? serial = null, pem = null, pub = null, pemb64 = null;
            foreach (var line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.StartsWith("__SERIAL__:")) serial = line.Substring("__SERIAL__:".Length).Trim();
                else if (line.StartsWith("__PEM_B64__:")) pemb64 = line.Substring("__PEM_B64__:".Length).Trim();
                else if (line.StartsWith("__PUB__:")) pub = line.Substring("__PUB__:".Length);
            }
            if (!string.IsNullOrWhiteSpace(pemb64))
            {
                pem = WrapPem(pemb64, "CERTIFICATE");
            }
            var wantDebug = !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DPA_DEBUG"));
            if (wantDebug)
            {
                Console.Error.WriteLine("[debug] PS serial: " + (serial ?? "<none>"));
                Console.Error.WriteLine("[debug] PS pemB64: " + (!string.IsNullOrWhiteSpace(pemb64) ? "<present>" : "<none>"));
                Console.Error.WriteLine("[debug] PS pub material: " + (!string.IsNullOrWhiteSpace(pub) ? "<present>" : "<none>"));
            }
            return (string.IsNullOrWhiteSpace(pem) ? null : pem, string.IsNullOrWhiteSpace(serial) ? null : serial, string.IsNullOrWhiteSpace(pub) ? null : pub);
        }
        catch { return (null, null, null); }
    }

    static string? GetTpmDeviceInfoViaTpmtool()
    {
        try
        {
            var psi = new ProcessStartInfo("tpmtool", "getdeviceinformation")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            return string.IsNullOrWhiteSpace(output) ? null : output;
        }
        catch { return null; }
    }

    static (string? pem, string? serial) GetEkCertFromCertStore()
    {
        try
        {
            using var lm = new X509Store("Trusted Platform Module\\Certificates", StoreLocation.LocalMachine);
            lm.Open(OpenFlags.ReadOnly);
            foreach (var cert in lm.Certificates)
            {
                var b64 = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                var pem = WrapPem(b64, "CERTIFICATE");
                return (pem, cert.SerialNumber);
            }
        }
        catch { }
        return (null, null);
    }

    static string WrapPem(string b64, string header)
    {
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(header).AppendLine("-----");
        for (int i = 0; i < b64.Length; i += 64)
        {
            var len = Math.Min(64, b64.Length - i);
            sb.AppendLine(b64.Substring(i, len));
        }
        sb.Append("-----END ").Append(header).AppendLine("-----");
        return sb.ToString();
    }
}




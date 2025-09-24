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
    static int Main(string[] args)
    {
        try
        {
            var attributes = CollectAttributes();
            var includeKeys = new[] { "board_serial", "cpu_id", "tpm_attest_pub_pem", "tpm_pubkey_hash", "tpm_ek_cert_serial", "disk_serial_or_uuid" };
            var canonical = Canonicalize(attributes, includeKeys);
            var fingerprint = Sha256Hex(Encoding.UTF8.GetBytes(canonical));

            Console.WriteLine("Attributes:");
            var toShow = new System.Collections.Generic.Dictionary<string, string>(attributes);
            if (toShow.TryGetValue("tpm_attest_pub_pem", out var pem) && pem.Length > 260)
            {
                toShow["tpm_attest_pub_pem"] = pem.Substring(0, 120) + " ... [truncated] ... " + pem.Substring(pem.Length - 120);
            }
            Console.WriteLine(JsonSerializer.Serialize(toShow, new JsonSerializerOptions { WriteIndented = true }));

            Console.WriteLine($"Fingerprint: {fingerprint}");
            Console.WriteLine($"Device ID: {fingerprint}");

            var server = Environment.GetEnvironmentVariable("DPA_SERVER") ?? "http://127.0.0.1:8080";
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

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.ToString());
            return 1;
        }
    }

    static string Canonicalize(System.Collections.Generic.IDictionary<string, string> attrs, string[] include)
    {
        var filtered = attrs
            .Where(kv => include.Contains(kv.Key))
            .OrderBy(kv => kv.Key)
            .ToDictionary(kv => kv.Key, kv => kv.Value ?? string.Empty);
        return JsonSerializer.Serialize(filtered, new JsonSerializerOptions { WriteIndented = false });
    }

    static string Sha256Hex(byte[] data)
    {
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(data);
        var sb = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    static System.Collections.Generic.Dictionary<string, string> CollectAttributes()
    {
        var dict = new System.Collections.Generic.Dictionary<string, string>();

        // BIOS/Motherboard serial
        dict["board_serial"] = QueryWmiSingle("Win32_BIOS", "SerialNumber") ?? string.Empty;

        // CPU ID (best-effort)
        dict["cpu_id"] = QueryWmiSingle("Win32_Processor", "ProcessorId") ?? string.Empty;

        // Disk serial (first physical disk)
        dict["disk_serial_or_uuid"] = QueryWmiSingle("Win32_DiskDrive", "SerialNumber") ?? string.Empty;

        // TPM EK public PEM and serial from multiple sources
        var (pem, serial) = TryGetEkCertPemAndSerial();
        if (!string.IsNullOrWhiteSpace(pem))
        {
            dict["tpm_attest_pub_pem"] = pem;
            dict["tpm_pubkey_hash"] = Sha256Hex(Encoding.UTF8.GetBytes(pem));
        }
        if (!string.IsNullOrWhiteSpace(serial))
        {
            dict["tpm_ek_cert_serial"] = serial;
        }

        // Remove empties
        var keys = dict.Keys.ToList();
        foreach (var k in keys) if (string.IsNullOrWhiteSpace(dict[k])) dict.Remove(k);
        return dict;
    }

    static (string? pem, string? serial) TryGetEkCertPemAndSerial()
    {
        // 1) tpmtool getekcertificate -> saved .cer
        var pem = GetEkPublicPemViaTpmtool();
        if (!string.IsNullOrWhiteSpace(pem))
        {
            // Serial may not be known here
            return (pem, null);
        }
        // 2) Parse tpmtool device info (no PEM, but serial may exist)
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
        // 3) Cert store fallback
        var (pemStore, snStore) = GetEkCertFromCertStore();
        if (!string.IsNullOrWhiteSpace(pemStore) || !string.IsNullOrWhiteSpace(snStore))
        {
            return (pemStore, snStore ?? serialFromInfo);
        }
        return (null, serialFromInfo);
    }

    static string? GetEkPublicPemViaTpmtool()
    {
        try
        {
            var psi = new ProcessStartInfo("tpmtool", "getekcertificate")
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(3000);
            var line = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                             .FirstOrDefault(s => s.Contains("saved to", StringComparison.OrdinalIgnoreCase));
            if (line == null) return null;
            var parts = line.Split(new[] { "saved to" }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) return null;
            var path = parts[1].Trim().Trim('"');
            if (!File.Exists(path)) return null;
            var der = File.ReadAllBytes(path);
            var b64 = Convert.ToBase64String(der);
            return WrapPem(b64, "CERTIFICATE");
        }
        catch { return null; }
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




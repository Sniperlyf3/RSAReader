using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RSAReader.Research;

public sealed record FileObservation(string Name, string Fid, int SelectStatus, int Length, string? Error);
public sealed record ObjectObservation(string Directory, string Kind, string? Label, string? KeyIdHash,
    string? Path, string? Usage, string? Access, string? AuthReference);
public sealed record CertificateObservation(string Path, string Fingerprint, string PublicKeyHash,
    string PublicKeyAlgorithm, string SignatureAlgorithm, string NotBefore, string NotAfter,
    string KeyUsage, string ExtendedKeyUsage, string BasicConstraints, string SubjectKeyIdentifier,
    string AuthorityKeyIdentifier, string Policies, string ChainResult);

// This is the export format. It intentionally contains no raw ASN.1, certificate
// subject/issuer, serial number, data-object value, CAN, or wire APDU.
public sealed class Pkcs15Report
{
    public int SchemaVersion { get; init; } = 1;
    public string ApplicationAid { get; set; } = "";
    public List<FileObservation> Files { get; init; } = [];
    public List<ObjectObservation> Objects { get; init; } = [];
    public List<CertificateObservation> Certificates { get; init; } = [];
    public List<string> Findings { get; init; } = [];

    public string ToJson() => JsonSerializer.Serialize(this, ResearchJsonContext.Default.Pkcs15Report);
    public static Pkcs15Report FromJson(string json) => JsonSerializer.Deserialize(json, ResearchJsonContext.Default.Pkcs15Report)
        ?? throw new FormatException("Empty research report.");

    public string Summary()
    {
        var b = new StringBuilder();
        b.AppendLine($"PKCS#15 AID: {ApplicationAid}");
        foreach (var f in Files) b.AppendLine($"{f.Name} ({f.Fid}): {(f.SelectStatus == 0xFFFF ? "SELECT 9000; READ FAILED" : $"SELECT {f.SelectStatus:X4}")}, {f.Length} bytes" +
            (f.Error is null ? "" : $", read error: {f.Error}"));
        foreach (var o in Objects) b.AppendLine($"{o.Directory}: {o.Kind}, label={o.Label ?? "?"}, path={o.Path ?? "?"}, key ID SHA-256={o.KeyIdHash ?? "?"}, usage={o.Usage ?? "?"}, access={o.Access ?? "?"}, auth ref={o.AuthReference ?? "?"}");
        foreach (var c in Certificates)
        {
            b.AppendLine($"Certificate {c.Path}: SHA-256 {c.Fingerprint}");
            b.AppendLine($"  Public key: {c.PublicKeyAlgorithm} SHA-256 {c.PublicKeyHash}; signature: {c.SignatureAlgorithm}");
            b.AppendLine($"  Valid: {c.NotBefore} .. {c.NotAfter}; key usage: {c.KeyUsage}; EKU: {c.ExtendedKeyUsage}");
            b.AppendLine($"  CA: {c.BasicConstraints}; SKI: {c.SubjectKeyIdentifier}; AKI: {c.AuthorityKeyIdentifier}; policies: {c.Policies}");
            b.AppendLine($"  Chain: {c.ChainResult}");
        }
        foreach (var finding in Findings) b.AppendLine($"• {finding}");
        return b.ToString();
    }

    public string Compare(Pkcs15Report prior)
    {
        var current = Objects.Select(x => $"{x.Directory}:{x.Kind}:{x.Path}:{x.KeyIdHash}").ToHashSet();
        var previous = prior.Objects.Select(x => $"{x.Directory}:{x.Kind}:{x.Path}:{x.KeyIdHash}").ToHashSet();
        var certs = Certificates.Select(x => x.Fingerprint).ToHashSet();
        var oldCerts = prior.Certificates.Select(x => x.Fingerprint).ToHashSet();
        return $"Object records: {Objects.Count} now, {prior.Objects.Count} before. Added {current.Except(previous).Count()}, missing {previous.Except(current).Count()}. Certificates: {Certificates.Count} now, {prior.Certificates.Count} before; {certs.Intersect(oldCerts).Count()} same fingerprints.";
    }
}

public sealed class Pkcs15Collector
{
    private readonly Dictionary<string, byte[]> _raw = [];
    public Pkcs15Report Report { get; } = new();

    public void Observe(string name, byte[] fid, int status, byte[] data, string? error = null)
    {
        var path = Convert.ToHexString(fid);
        Report.Files.Add(new FileObservation(name, path, status, data.Length, error));
        if (status == 0x9000 && error is null && data.Length > 0) _raw[path] = data.ToArray();
    }

    public void SetApplication(byte[] aid) => Report.ApplicationAid = Convert.ToHexString(aid);

    public Pkcs15Report Analyze()
    {
        ParseDirectory("5001", "Private key");
        ParseDirectory("5002", "Public key");
        ParseDirectory("5003", "Certificate");
        ParseDirectory("5005", "Data object");
        ParseDirectory("5006", "Authentication object");
        foreach (var file in Report.Files.Where(x => x.Name.StartsWith("Certificate value", StringComparison.Ordinal)))
            if (_raw.TryGetValue(file.Fid, out var der)) InspectCertificate(file.Fid, der);
        var privateFile = Report.Files.FirstOrDefault(x => x.Fid == "5001");
        if (privateFile?.SelectStatus == 0xFFFF) Report.Findings.Add("PrKDF was selected, but reading failed. Its contents and capabilities remain unknown.");
        if (privateFile is { Length: 0 }) Report.Findings.Add("PrKDF returned no bytes. A read error or access rule may explain this; private-key absence is unproven.");
        if (Report.Certificates.Count > 0) Report.Findings.Add("A certificate on the chip does not establish issuer trust without an authenticated CA chain and revocation evidence.");
        foreach (var key in Report.Objects.Where(x => x.Directory == "5002" && x.KeyIdHash is not null))
        {
            if (Report.Objects.Any(x => x.Directory == "5003" && x.KeyIdHash == key.KeyIdHash))
                Report.Findings.Add($"{key.Kind} and a certificate directory entry share a PKCS#15 key ID. This links records, but does not compare their public-key bytes.");
        }
        if (Report.Objects.Any(x => x.Directory == "5002")) Report.Findings.Add("PuKDF directory entries identify public keys, but their key material has not been read; certificate-to-PuKDF equality is unverified.");
        return Report;
    }

    private void ParseDirectory(string fid, string kind)
    {
        if (!_raw.TryGetValue(fid, out var data)) return;
        try
        {
            foreach (var outer in Asn1Tree.Read(data))
            {
                // PKCS#15 uses an IMPLICIT [0] CHOICE arm for EC keys. Its A0
                // value contains the PKCS15Object fields directly (common,
                // class, type), with no extra SEQUENCE around them.
                var record = outer.Tag is 0x30 or 0xA0 ? outer : null;
                if (record is null) continue;
                var objectKind = kind.Contains("key", StringComparison.OrdinalIgnoreCase)
                    ? kind + (outer.Tag == 0xA0 ? " (EC)" : " (RSA)") : kind;
                var common = record.Children.FirstOrDefault();
                var classAttrs = record.Children.Skip(1).FirstOrDefault();
                var label = common?.Child(0x0C) is { } labelNode ? SafeLabel(Encoding.UTF8.GetString(labelNode.Value)) : null;
                var keyId = kind is "Private key" or "Public key" or "Certificate"
                    ? classAttrs?.Child(0x04)?.Value : null;
                var idHash = keyId is { Length: > 0 } ? Hash(keyId) : null;
                // ObjectValue.indirect is a Path SEQUENCE in the type attributes.
                // A path OCTET STRING is constrained to 2/4/6 bytes and begins in
                // the file-system tree, preventing a key identifier being mistaken for it.
                var path = record.Descendants(0x04).Select(x => x.Value)
                    .Where(x => x.Length is 2 or 4 or 6 && x[0] is 0x3F or 0x50 or 0xB0 or 0xB1)
                    .LastOrDefault();
                var bits = classAttrs?.Children.Where(x => x.Tag == 0x03).Select(x => x.Value).ToList() ?? [];
                var usage = kind.Contains("key", StringComparison.OrdinalIgnoreCase) && bits.Count > 0
                    ? BitNames(bits[0], ["encrypt", "decrypt", "sign", "signRecover", "wrap", "unwrap", "verify", "verifyRecover", "derive", "nonRepudiation"])
                    : null;
                var access = kind == "Private key" && bits.Count > 1
                    ? BitNames(bits[1], ["sensitive", "extractable", "alwaysSensitive", "neverExtractable", "local"])
                    : null;
                Report.Objects.Add(new ObjectObservation(fid, objectKind, label, idHash,
                    path is null ? null : Convert.ToHexString(path), usage, access, null));
            }
        }
        catch (FormatException ex) { Report.Findings.Add($"{kind} directory {fid} could not be decoded: {ex.Message}"); }
    }

    private void InspectCertificate(string path, byte[] der)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(der);
            var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            var basic = cert.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            var ski = cert.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
            var aki = cert.Extensions["2.5.29.35"];
            var policies = cert.Extensions["2.5.29.32"];
            // ExportSubjectPublicKeyInfo is canonical for comparing certificate and PuKDF keys.
            var spki = cert.PublicKey.ExportSubjectPublicKeyInfo();
            // No trusted Home Affairs root has been configured. Do not interpret a
            // platform-chain result as independent card authenticity verification.
            Report.Certificates.Add(new CertificateObservation(path, Hash(der), Hash(spki),
                cert.PublicKey.Oid?.FriendlyName ?? cert.PublicKey.Oid?.Value ?? "unknown",
                cert.SignatureAlgorithm?.Value ?? "unknown", cert.NotBefore.ToString("yyyy-MM-dd"),
                cert.NotAfter.ToString("yyyy-MM-dd"), keyUsage?.KeyUsages.ToString() ?? "not present",
                eku is null ? "not present" : string.Join(", ", eku.EnhancedKeyUsages.Cast<Oid>().Select(x => x.Value)),
                basic is null ? "not present" : basic.CertificateAuthority ? $"CA=true, path length {basic.PathLengthConstraint}" : "CA=false",
                ski is null ? "not present" : Hash(Convert.FromHexString(ski.SubjectKeyIdentifier ?? "")),
                aki is null ? "not present" : DescribeAuthorityKeyIdentifier(aki.RawData),
                policies is null ? "not present" : DescribePolicies(policies.RawData),
                "Unverified: no trusted issuer chain supplied"));
        }
        catch (Exception ex) { Report.Findings.Add($"Certificate {path} could not be decoded: {ex.GetType().Name}"); }
    }

    private static string Hash(byte[] value) => Convert.ToHexString(SHA256.HashData(value));
    private static string SafeLabel(string value) => value is
        "Label ELC Keyset 1" or "Label RSA Keyset 1" or "Default Key Container" or "User PIN" or "SO PIN" or "Sample"
        ? value : "[redacted label]";
    private static string DescribeAuthorityKeyIdentifier(byte[] raw)
    {
        try
        {
            var keyId = Asn1Tree.Read(raw).SelectMany(x => x.Descendants(0x80)).FirstOrDefault();
            return keyId is null ? "present; key ID unavailable" : $"key ID SHA-256 {Hash(keyId.Value)}";
        }
        catch (FormatException) { return "present; parse failed"; }
    }
    private static string DescribePolicies(byte[] raw)
    {
        try
        {
            // CertificatePolicies ::= SEQUENCE OF PolicyInformation, whose first
            // child is the policy OID. Qualifier OIDs must not be called policies.
            var policies = Asn1Tree.Read(raw).FirstOrDefault(x => x.Tag == 0x30);
            var oids = policies?.Children.Select(x => x.Child(0x06))
                .Where(x => x is not null).Select(x => Asn1Tree.Oid(x!.Value)).ToList() ?? [];
            return oids.Count == 0 ? "present; no policy OIDs" : string.Join(", ", oids);
        }
        catch (FormatException) { return "present; parse failed"; }
    }
    private static string BitNames(byte[] bitString, string[] names)
    {
        if (bitString.Length < 2) return "none";
        var result = names.Where((_, bit) => bit / 8 + 1 < bitString.Length &&
            (bitString[1 + bit / 8] & (0x80 >> (bit % 8))) != 0);
        return string.Join(", ", result);
    }
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(Pkcs15Report))]
internal partial class ResearchJsonContext : JsonSerializerContext;

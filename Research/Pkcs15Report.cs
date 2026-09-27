using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RSAReader.Research;

public sealed record ReadObservation(int Offset, int Requested, int Status, int Returned);
public sealed record FileAuditObservation(string Path, int SelectStatus, int? DeclaredSize,
    int ParsedPrefixLength, int BytesRead, int TailNonPaddingBytes, string Completion,
    List<ReadObservation> Reads, List<string> Signatures);

public sealed record FileObservation(string Name, string Fid, int SelectStatus, int Length, string? Error);
public sealed record MetadataObservation(string Reference, int Status, int Length, string? TagLengths, string? Error,
    string? ControlValues = null, string? AccessRule = null);
public sealed record ApplicationObservation(string Name, string Aid, int SelectStatus, int FciStatus,
    int FciLength, string? FciTagLengths);
public sealed record ObjectObservation(string Directory, string Kind, string? Label, string? KeyIdHash,
    string? Path, string? Usage, string? Access, string? AuthReference);
public sealed record ShortEfObservation(int Sfi, int SelectStatus, int? DeclaredSize, int BytesRead,
    string? TlvTags, List<string> Signatures, string Completion,
    string? Context = null, int? TerminalStatus = null, List<ReadObservation>? Reads = null, string? ParseError = null)
{
    // Set during Analyze() once every short EF has been captured: whether this SFI's
    // content is identical to (or a prefix of) an already-mapped file, a duplicate of
    // another SFI, padding only, or genuinely new/unmapped content.
    public string? IdentityMatch { get; set; }
}
public sealed record SecurityInfoObservation(string Source, string Oid, string Name, string? Detail);
public sealed record DiscoveredAidObservation(string RequestedPrefix, string? DiscoveredDfName,
    int SelectStatus, int FciLength, string? FciTagLengths, string Occurrence);
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
    public List<FileAuditObservation> FileAudits { get; init; } = [];
    public List<FileObservation> Files { get; init; } = [];
    public List<MetadataObservation> SelectionMetadata { get; init; } = [];
    public List<MetadataObservation> BiometricInformation { get; init; } = [];
    public List<ApplicationObservation> Applications { get; init; } = [];
    public List<ObjectObservation> Objects { get; init; } = [];
    public List<CertificateObservation> Certificates { get; init; } = [];
    public List<ShortEfObservation> ShortEfs { get; init; } = [];
    public List<SecurityInfoObservation> SecurityInfos { get; init; } = [];
    public List<DiscoveredAidObservation> DiscoveredAids { get; init; } = [];
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
        foreach (var a in FileAudits)
            b.AppendLine($"Audit {a.Path}: {a.BytesRead}/{a.DeclaredSize} bytes, parsed prefix {a.ParsedPrefixLength}, tail nonpadding {a.TailNonPaddingBytes}; {a.Completion}; {string.Join(", ", a.Signatures)}");
        foreach (var f in SelectionMetadata)
            b.AppendLine($"FCI {f.Reference}: SELECT {f.Status:X4}, {f.Length} bytes, TLV tags/lengths: {f.TagLengths ?? "unavailable"}" +
                (f.ControlValues is null ? "" : $", file controls: {f.ControlValues}") +
                (f.AccessRule is null ? "" : $", access rule: {f.AccessRule}") +
                (f.Error is null ? "" : $", {f.Error}"));
        foreach (var f in BiometricInformation)
            b.AppendLine($"Biometric information tag {f.Reference}: GET DATA {f.Status:X4}, {f.Length} bytes, TLV tags/lengths: {f.TagLengths ?? "unavailable"}" +
                (f.Error is null ? "" : $", {f.Error}"));
        foreach (var app in Applications)
            b.AppendLine($"Application {app.Name} ({app.Aid}): SELECT {app.SelectStatus:X4}, FCI request {app.FciStatus:X4}, {app.FciLength} FCI bytes, tags/lengths: {app.FciTagLengths ?? "unavailable"}");
        foreach (var s in SecurityInfos)
            b.AppendLine($"SecurityInfo [{s.Source}]: {s.Name} ({s.Oid})" + (s.Detail is null ? "" : $"; {s.Detail}"));
        foreach (var e in ShortEfs)
            b.AppendLine($"Short EF [{e.Context ?? "unspecified context"}] {e.Sfi} (SFI {e.Sfi:X2}): initial READ {(e.SelectStatus == 0xFFFF ? "FAILED" : e.SelectStatus.ToString("X4"))}, declared {e.DeclaredSize?.ToString() ?? "?"}, {e.BytesRead} bytes read; terminal {e.TerminalStatus?.ToString("X4") ?? "unavailable"}; {e.Completion}" +
                (e.IdentityMatch is null ? "" : $"; identity: {e.IdentityMatch}") +
                (e.TlvTags is null ? "" : $"; TLV tags/lengths: {e.TlvTags}") +
                (e.ParseError is null ? "" : $"; TLV parse: {e.ParseError}") +
                (e.Signatures.Count == 0 ? "" : $"; signatures: {string.Join(", ", e.Signatures)}"));
        foreach (var a in DiscoveredAids)
            b.AppendLine($"Partial-AID {a.Occurrence} for prefix {a.RequestedPrefix}: SELECT {a.SelectStatus:X4}" +
                (a.DiscoveredDfName is null ? "" : $", DF name {a.DiscoveredDfName}") +
                $", {a.FciLength} FCI bytes, tags/lengths: {a.FciTagLengths ?? "unavailable"}");
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
    // Raw short-EF captures kept locally for content classification in Analyze().
    private readonly List<(int Sfi, string Context, byte[] Bytes, ShortEfObservation Obs)> _shortEfCaptures = [];
    public Pkcs15Report Report { get; } = new();

    public void Observe(string name, byte[] fid, int status, byte[] data, string? error = null)
    {
        var path = Convert.ToHexString(fid);
        Report.Files.Add(new FileObservation(name, path, status, data.Length, error));
        if (status == 0x9000 && error is null && data.Length > 0) _raw[path] = data.ToArray();
    }

    public void SetApplication(byte[] aid) => Report.ApplicationAid = Convert.ToHexString(aid);

    public void ObserveApplication(string name, byte[] aid, int selectStatus, int fciStatus, byte[] fci)
    {
        string? error = null;
        var tags = DescribeTlv(fci, ref error);
        Report.Applications.Add(new ApplicationObservation(name, Convert.ToHexString(aid),
            selectStatus, fciStatus, fci.Length, tags));
    }

    public void ObserveFci(byte[] fid, int status, byte[] fci, string? error = null)
    {
        // FCI may contain file names or proprietary values. Export only TLV tags
        // and lengths, never the raw bytes or values.
        var tags = DescribeTlv(fci, ref error);
        var controls = DescribeFciControls(fci);
        var rule = DescribeCompactEfAccess(fci);
        Report.SelectionMetadata.Add(new MetadataObservation(Convert.ToHexString(fid), status, fci.Length, tags, error, controls, rule));
    }

    private static string? DescribeFciControls(byte[] fci)
    {
        if (fci.Length == 0) return null;
        try
        {
            var template = Asn1Tree.Read(fci).FirstOrDefault(x => x.Tag == 0x6F);
            if (template is null) return null;
            // Only fixed-size ISO file-control fields. A DF name (84) and all
            // proprietary or variable-length values are deliberately omitted.
            var expectedLengths = new Dictionary<int, int> { [0x81] = 2, [0x82] = 1,
                [0x83] = 2, [0x8A] = 1 };
            var parts = template.Children
                .Where(x => expectedLengths.TryGetValue(x.Tag, out var size) && x.Value.Length == size)
                .Concat(template.Children.Where(x => x.Tag == 0x8C && x.Value.Length is 2 or 3))
                .Select(x => $"{x.Tag:X2}={Convert.ToHexString(x.Value)}");
            var result = string.Join(" ", parts);
            return result.Length == 0 ? null : result;
        }
        catch (FormatException) { return null; }
    }

    private static string? DescribeCompactEfAccess(byte[] fci)
    {
        try
        {
            var template = Asn1Tree.Read(fci).FirstOrDefault(x => x.Tag == 0x6F);
            var descriptor = template?.Child(0x82)?.Value;
            var rule = template?.Child(0x8C)?.Value;
            // Transparent EF, one compact rule: b2 UPDATE, b1 READ. ISO 7816-4
            // places the security bytes in descending bit order.
            if (descriptor is not [0x01] || rule is not [0x03, _, _]) return null;
            return $"UPDATE/ERASE: {DescribeSecurityCondition(rule[1])}; READ: {DescribeSecurityCondition(rule[2])}";
        }
        catch (FormatException) { return null; }
    }

    private static string DescribeSecurityCondition(byte value)
    {
        if (value == 0x00) return "no condition";
        if (value == 0xFF) return "never";
        var requirements = new List<string>();
        if ((value & 0x40) != 0) requirements.Add("secure messaging");
        if ((value & 0x20) != 0) requirements.Add("external authentication");
        if ((value & 0x10) != 0) requirements.Add("user authentication");
        if (requirements.Count == 0) return $"unrecognized condition {value:X2}";
        var joiner = (value & 0x80) != 0 ? " and " : " or ";
        var environment = value & 0x0F;
        return string.Join(joiner, requirements) +
            (environment == 0 ? " (default security environment)" : environment == 15
                ? " (reserved environment reference)" : $" (security environment {environment})");
    }

    public void ObserveBiometricInformation(byte[] tag, int status, byte[] data, string? error = null)
    {
        // A BIT may contain the biometric reference itself. Never retain its
        // values, even in the in-memory collector.
        var tags = DescribeTlv(data, ref error);
        Report.BiometricInformation.Add(new MetadataObservation(Convert.ToHexString(tag), status, data.Length, tags, error));
    }

    public void ObserveSecurityInfos(IEnumerable<SecurityInfoObservation> infos) =>
        Report.SecurityInfos.AddRange(infos);

    public void ObserveShortEf(int sfi, int status, int? declaredSize, byte[] body, string completion,
        string? context = null, int? terminalStatus = null, List<ReadObservation>? reads = null)
    {
        // Content bytes stay local. Only the TLV shape and signature offsets are exported.
        string? error = null;
        var tags = DescribeTlv(body, ref error);
        var obs = new ShortEfObservation(sfi, status, declaredSize, body.Length, tags,
            ImageScan.Scan(body), completion, context, terminalStatus, reads, error);
        Report.ShortEfs.Add(obs);
        if (body.Length > 0) _shortEfCaptures.Add((sfi, context ?? "unspecified", body.ToArray(), obs));
    }

    // Classify each short-EF capture by content so complete reads of already-mapped
    // files are not mislabelled and genuinely new data is called out separately from
    // duplicates and padding. Runs after every EF has been captured. Content stays
    // local; only the identity verdict and a per-context summary are exported.
    private void ClassifyShortEfs()
    {
        if (_shortEfCaptures.Count == 0) return;
        var known = _raw.Where(kv => kv.Value.Length > 0).ToList();
        var seen = new List<(int Sfi, string Context, byte[] Bytes)>();
        var rows = new List<(string Context, string Category, int Sfi)>();
        foreach (var cap in _shortEfCaptures)
        {
            string category, verdict;
            if (cap.Bytes.All(b => b is 0x00 or 0xFF))
            {
                (category, verdict) = ("padding-only", "padding only (no content)");
            }
            else if (known.FirstOrDefault(k => IsSameOrPrefix(cap.Bytes, k.Value)) is { Value: not null } match)
            {
                category = "known-EF";
                verdict = cap.Bytes.Length == match.Value.Length
                    ? $"identical to already-mapped EF {match.Key}"
                    : $"prefix of already-mapped EF {match.Key} (first {cap.Bytes.Length} bytes)";
            }
            else if (seen.FirstOrDefault(s => s.Bytes.Length == cap.Bytes.Length && s.Bytes.SequenceEqual(cap.Bytes)) is { Bytes: not null } dup)
            {
                (category, verdict) = ("duplicate", $"duplicate of SFI {dup.Sfi:X2} [{dup.Context}]");
            }
            else
            {
                (category, verdict) = ("distinct", "distinct / not matched to any mapped file");
            }
            cap.Obs.IdentityMatch = verdict;
            rows.Add((cap.Context, category, cap.Sfi));
            seen.Add((cap.Sfi, cap.Context, cap.Bytes));
        }
        foreach (var group in rows.GroupBy(r => r.Context))
        {
            string List(string category)
            {
                var hits = group.Where(r => r.Category == category).Select(r => $"{r.Sfi:X2}").ToList();
                return hits.Count == 0 ? "none" : string.Join(", ", hits);
            }
            Report.Findings.Add($"Short-EF classification ({group.Key}): genuinely new/unmapped SFIs [{List("distinct")}]; " +
                $"identical or prefix of mapped EFs [{List("known-EF")}]; duplicate SFIs [{List("duplicate")}]; padding-only SFIs [{List("padding-only")}].");
        }
        if (rows.Any(r => r.Category == "distinct"))
            Report.Findings.Add("Access rules for genuinely new SFIs were not retrieved: short-EF addressing selects a file without exposing its file identifier, so no FCI/SELECT could be issued for those entries. Their access conditions remain unknown; a matched SFI inherits the access rule already recorded for its file identifier.");
    }

    // True when candidate is exactly, or a leading prefix of, reference. A capped SFI
    // capture is a prefix of the full file read under its file identifier.
    private static bool IsSameOrPrefix(byte[] candidate, byte[] reference) =>
        candidate.Length > 0 && reference.Length >= candidate.Length &&
        reference.AsSpan(0, candidate.Length).SequenceEqual(candidate);

    public void ObserveDiscoveredAid(byte[] requestedPrefix, int selectStatus, byte[] fci, string occurrence)
    {
        string? error = null;
        var tags = DescribeTlv(fci, ref error);
        string? dfName = null;
        try
        {
            // The DF name (tag 84) is the applet identifier that was actually selected;
            // it is a public identifier, not cardholder data, so record it as the find.
            if (Asn1Tree.Read(fci).FirstOrDefault(x => x.Tag == 0x6F)?.Child(0x84)?.Value is { Length: > 0 } v)
                dfName = Convert.ToHexString(v);
        }
        catch (FormatException) { }
        Report.DiscoveredAids.Add(new DiscoveredAidObservation(Convert.ToHexString(requestedPrefix),
            dfName, selectStatus, fci.Length, tags, occurrence));
    }

    // Inspect a certificate that did not come from a CDF path (e.g. a CMS signer cert
    // embedded in EF.CardSecurity). Reuses the redacting certificate inspector.
    public void ObserveEmbeddedCertificate(string source, byte[] der) => InspectCertificate(source, der);

    private static string? DescribeTlv(byte[] data, ref string? error)
    {
        if (data.Length == 0) return null;
        try { return string.Join(" ", Asn1Tree.Read(data).Select(FormatTag)); }
        catch (FormatException) { error = "response is not a bounded BER-TLV tree"; return null; }
    }

    private static string FormatTag(Asn1Node node) => $"{node.Tag:X}:{node.Value.Length}" +
        (node.Children.Count == 0 ? "" : $"({string.Join(" ", node.Children.Select(FormatTag))})");

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
        if (privateFile is { Length: 0 })
            Report.Findings.Add(Report.Findings.Any(x => x.Contains("PrKDF one-byte READ BINARY returned 6982", StringComparison.Ordinal))
                ? "PrKDF READ BINARY reported security condition not satisfied in this PACE/CAN session. Its contents and private-key capabilities remain unknown."
                : "PrKDF returned no bytes. A read error or access rule may explain this; private-key absence is unproven.");
        if (Report.Certificates.Count > 0) Report.Findings.Add("A certificate on the chip does not establish issuer trust without an authenticated CA chain and revocation evidence.");
        foreach (var key in Report.Objects.Where(x => x.Directory == "5002" && x.KeyIdHash is not null))
        {
            if (Report.Objects.Any(x => x.Directory == "5003" && x.KeyIdHash == key.KeyIdHash))
                Report.Findings.Add($"{key.Kind} and a certificate directory entry share a PKCS#15 key ID. This links records, but does not compare their public-key bytes.");
        }
        if (Report.Objects.Any(x => x.Directory == "5002")) Report.Findings.Add("PuKDF directory entries identify public keys, but their key material has not been read; certificate-to-PuKDF equality is unverified.");
        ClassifyShortEfs();
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
                var record = outer.Tag is 0x30 or 0xA0 ||
                    (kind == "Authentication object" && (outer.Tag == 0xA1 || outer.Tag == 0xA2)) ? outer : null;
                if (record is null) continue;
                var objectKind = kind == "Authentication object" ? outer.Tag switch
                {
                    0x30 => "PIN authentication object",
                    0xA0 => "Biometric template authentication object",
                    0xA1 => "Authentication key object",
                    0xA2 => "External authentication object",
                    _ => "Authentication object"
                } : kind.Contains("key", StringComparison.OrdinalIgnoreCase)
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
                string? usage = kind.Contains("key", StringComparison.OrdinalIgnoreCase) && bits.Count > 0
                    ? BitNames(bits[0], ["encrypt", "decrypt", "sign", "signRecover", "wrap", "unwrap", "verify", "verifyRecover", "derive", "nonRepudiation"])
                    : null;
                string? access = kind == "Private key" && bits.Count > 1
                    ? BitNames(bits[1], ["sensitive", "extractable", "alwaysSensitive", "neverExtractable", "local"])
                    : null;
                string? authReference = null;
                if (kind == "Authentication object")
                    (usage, access, authReference) = DescribeAuthentication(outer);
                if (objectKind == "PIN authentication object" &&
                    access?.Contains("unblocking-PIN", StringComparison.Ordinal) == true &&
                    access.Contains("SO-PIN", StringComparison.Ordinal))
                    Report.Findings.Add("A PIN record sets both unblocking-PIN and SO-PIN flags. PKCS#15 v1.1 disallows that combination; retain the raw flag interpretation but do not infer a supported operation from it.");
                Report.Objects.Add(new ObjectObservation(fid, objectKind, label, idHash,
                    path is null ? null : Convert.ToHexString(path), usage, access, authReference));
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
    private static (string? Usage, string? Flags, string? Reference) DescribeAuthentication(Asn1Node outer)
    {
        var attrs = outer.Child(0xA1)?.Child(0x30);
        if (attrs is null) return (null, null, null);
        var flags = attrs.Child(0x03)?.Value;
        if (outer.Tag == 0x30) // PinAttributes
        {
            var pinType = attrs.Child(0x0A)?.Value;
            var type = (pinType is { Length: > 0 } ? pinType[^1] : -1) switch
            {
                0 => "BCD", 1 => "ASCII numeric", 2 => "UTF-8", 3 => "half-nibble BCD", 4 => "ISO 9564-1", _ => "unknown"
            };
            var lengths = attrs.Children.Where(x => x.Tag == 0x02).Select(x => PositiveInteger(x.Value)).ToList();
            var description = $"{type} PIN" + (lengths.Count >= 2 ? $"; minimum {lengths[0]}, stored {lengths[1]} bytes" : "") +
                (lengths.Count >= 3 ? $", maximum {lengths[2]}" : "");
            var reference = attrs.Child(0x80) is { } pinRef ? $"PIN reference {PositiveInteger(pinRef.Value)}" : null;
            return (description, flags is null ? null : BitNames(flags,
                ["case-sensitive", "local", "change-disabled", "unblock-disabled", "initialized", "needs-padding", "unblocking-PIN", "SO-PIN", "disable-allowed", "integrity-protected", "confidentiality-protected", "exchange-ref-data"]), reference);
        }
        if (outer.Tag == 0xA0) // BiometricAttributes; metadata only
        {
            var oid = attrs.Child(0x06) is { } templateId ? Asn1Tree.Oid(templateId.Value) : "unknown";
            var bioType = attrs.Child(0x30)?.Children.Where(x => x.Tag == 0x0A)
                .Select(x => PositiveInteger(x.Value)).ToArray() ?? [];
            var reference = attrs.Child(0x02) is { } bioRef ? $"biometric reference {PositiveInteger(bioRef.Value)}" : null;
            var typeDescription = bioType is [0, 0] ? "left thumb fingerprint (0/0)" :
                bioType is [1, 0] ? "right thumb fingerprint (1/0)" :
                $"type {string.Join("/", bioType)}";
            return ($"template OID {oid}; {typeDescription}", flags is null ? null : BitNames(flags,
                ["reserved", "local", "change-disabled", "unblock-disabled", "initialized", "reserved", "reserved", "reserved", "disable-allowed", "integrity-protected", "confidentiality-protected"]), reference);
        }
        return (null, null, null);
    }

    private static int PositiveInteger(byte[] bytes)
    {
        if (bytes.Length is < 1 or > 4 || (bytes[0] & 0x80) != 0) return -1;
        var value = 0;
        foreach (var b in bytes) value = (value << 8) | b;
        return value;
    }
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

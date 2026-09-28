using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;

namespace RSAReader.Research;

// Raw cardholder data: only create on explicit user request; never upload automatically.
public sealed record RawDumpEntry(string Path, byte[] Bytes, string Completion,
    int? SelectStatus = null, int? DeclaredSize = null);
public sealed record RawDumpManifestEntry(string Path, int Length, string Sha256, string Completion,
    int? SelectStatus, int? DeclaredSize);
public sealed record RawDumpManifest(int SchemaVersion, string CreatedUtc, string Scope,
    List<RawDumpManifestEntry> Files);

public static class RawDumpArchive
{
    public static void Write(Stream destination, IReadOnlyList<RawDumpEntry> files)
    {
        using var archive = new ZipArchive(destination, ZipArchiveMode.Create, leaveOpen: true);
        var manifest = new List<RawDumpManifestEntry>();
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in files)
        {
            // Do not allow caller-provided names to escape the archive root.
            if (file.Bytes.Length == 0 || file.Bytes.Length > 1024 * 1024 ||
                file.Path.StartsWith('/') || file.Path.Contains("..", StringComparison.Ordinal) ||
                string.Equals(file.Path, "manifest.json", StringComparison.OrdinalIgnoreCase) ||
                file.Path.Contains('\\') || file.Path.Split('/').Any(s => s.Length == 0 ||
                    !s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) ||
                !used.Add(file.Path))
                throw new ArgumentException("Invalid or duplicate dump entry.");
            var entry = archive.CreateEntry(file.Path, CompressionLevel.Optimal);
            using (var output = entry.Open()) output.Write(file.Bytes);
            manifest.Add(new(file.Path, file.Bytes.Length,
                Convert.ToHexString(SHA256.HashData(file.Bytes)), file.Completion,
                file.SelectStatus, file.DeclaredSize));
        }
        var index = archive.CreateEntry("manifest.json");
        using var stream = index.Open();
        JsonSerializer.Serialize(stream, new RawDumpManifest(1, DateTime.UtcNow.ToString("O"),
            "Readable bytes captured during the last PACE scan only; NOT a complete chip image.", manifest));
    }
}

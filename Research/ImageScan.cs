namespace RSAReader.Research;

// Read-only signature scan for portrait / biometric payloads in any blob the card
// hands back. A hit is a byte-pattern match, never a decoded or validated image; it
// only says "worth a closer look", so every result is labelled "not validated".
internal static class ImageScan
{
    // Ordered from most to least specific. The two BER tags (5F2E, 7F2E) are the
    // ISO 7816-11 / ICAO biometric data-block templates that would wrap a face or
    // fingerprint record; finding the tag does not mean its value is readable.
    public static readonly (string Name, byte[] Marker)[] Signatures =
    {
        ("JPEG", [0xFF, 0xD8, 0xFF]),
        ("JPEG2000 codestream", [0xFF, 0x4F, 0xFF, 0x51]),
        ("JPEG2000 (JP2 signature box)", [0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]),
        ("ISO 19794-5 face record", [0x46, 0x41, 0x43, 0x00]),
        ("Biometric data template tag 5F2E", [0x5F, 0x2E]),
        ("Biometric data template tag 7F2E", [0x7F, 0x2E]),
    };

    public static List<string> Scan(ReadOnlySpan<byte> body, int limit = 32)
    {
        var hits = new List<string>();
        foreach (var (name, marker) in Signatures)
        {
            for (var i = 0; i + marker.Length <= body.Length && hits.Count < limit; i++)
                if (body.Slice(i, marker.Length).SequenceEqual(marker))
                    hits.Add($"{name} candidate at {i}; not validated");
            if (hits.Count >= limit) break;
        }
        return hits;
    }
}

namespace RSAReader.Research;

// A bounded BER TLV reader. Unknown tags are retained so new PKCS#15 profiles can
// be inspected without guessing that every OCTET STRING is a file identifier.
internal sealed record Asn1Node(int Tag, byte[] Value, IReadOnlyList<Asn1Node> Children)
{
    public Asn1Node? Child(int tag) => Children.FirstOrDefault(x => x.Tag == tag);
    public IEnumerable<Asn1Node> Descendants(int tag) =>
        Children.SelectMany(x => (x.Tag == tag ? new[] { x } : Array.Empty<Asn1Node>()).Concat(x.Descendants(tag)));
}

internal static class Asn1Tree
{
    private const int MaxDepth = 16;
    private const int MaxBytes = 64 * 1024;

    public static IReadOnlyList<Asn1Node> Read(byte[] bytes)
    {
        if (bytes.Length > MaxBytes) throw new FormatException("ASN.1 input exceeds the research limit.");
        return ReadRange(bytes, 0, bytes.Length, 0);
    }

    public static string Oid(byte[] bytes)
    {
        if (bytes.Length == 0) throw new FormatException("Empty object identifier.");
        var values = new List<ulong>();
        ulong value = 0;
        foreach (var b in bytes)
        {
            if (value > (ulong.MaxValue >> 7)) throw new FormatException("OID arc too large.");
            value = (value << 7) | (uint)(b & 0x7F);
            if ((b & 0x80) == 0) { values.Add(value); value = 0; }
        }
        if ((bytes[^1] & 0x80) != 0) throw new FormatException("Incomplete OID arc.");
        var first = values[0];
        var arcs = new List<ulong> { first < 40 ? 0UL : first < 80 ? 1UL : 2UL,
            first < 40 ? first : first < 80 ? first - 40 : first - 80 };
        arcs.AddRange(values.Skip(1));
        return string.Join(".", arcs);
    }

    private static IReadOnlyList<Asn1Node> ReadRange(byte[] bytes, int start, int end, int depth)
    {
        if (depth > MaxDepth) throw new FormatException("ASN.1 nesting is too deep.");
        var nodes = new List<Asn1Node>();
        var offset = start;
        while (offset < end)
        {
            var first = bytes[offset++];
            if (first is 0x00 or 0xFF) // trailing EF padding
            {
                if (bytes.AsSpan(offset - 1, end - offset + 1).ToArray().Any(x => x != first))
                    throw new FormatException("Unexpected ASN.1 padding.");
                break;
            }
            var tag = (int)first;
            if ((first & 0x1F) == 0x1F)
            {
                tag = first;
                int count = 0;
                do
                {
                    if (offset >= end || ++count > 3) throw new FormatException("Invalid ASN.1 high tag.");
                    tag = (tag << 8) | bytes[offset++];
                } while ((bytes[offset - 1] & 0x80) != 0);
            }
            if (offset >= end) throw new FormatException("Missing ASN.1 length.");
            var lengthByte = bytes[offset++];
            int length;
            if (lengthByte < 0x80) length = lengthByte;
            else
            {
                var count = lengthByte & 0x7F;
                if (count is < 1 or > 3 || offset + count > end)
                    throw new FormatException("Unsupported ASN.1 length.");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | bytes[offset++];
            }
            if (length > end - offset) throw new FormatException("ASN.1 length exceeds input.");
            var value = bytes.AsSpan(offset, length).ToArray();
            var children = (first & 0x20) != 0
                ? ReadRange(bytes, offset, offset + length, depth + 1)
                : Array.Empty<Asn1Node>();
            nodes.Add(new Asn1Node(tag, value, children));
            offset += length;
        }
        return nodes;
    }
}

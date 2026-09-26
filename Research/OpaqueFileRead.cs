namespace RSAReader.Research;

internal static class OpaqueFileRead
{
    // Data-object EFs need not contain TLV records. Find the largest successful
    // Le at each offset because this card returns empty 6282 if Le passes EOF.
    public static byte[] WholeFile(Func<int, int, byte[]> readChunk)
    {
        var data = new List<byte>();
        const int cap = 0x8000;
        while (data.Count < cap)
        {
            var max = Math.Min(0xC0, cap - data.Count);
            var part = readChunk(data.Count, max);
            if (part.Length == 0)
            {
                var low = 1;
                var high = max - 1;
                while (low <= high)
                {
                    var middle = low + (high - low) / 2;
                    var candidate = readChunk(data.Count, middle);
                    if (candidate.Length > 0) { part = candidate; low = middle + 1; }
                    else high = middle - 1;
                }
            }
            if (part.Length == 0) break;
            data.AddRange(part);
            if (part.Length < max) break;
        }
        return data.ToArray();
    }
}

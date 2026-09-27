namespace RSAReader.Research;

internal static class FileAudit
{
    // Tag 81 can include structural overhead. Treat it as a bounded research target,
    // not proof that every byte is readable content. Never probe beyond 32 KiB.
    public static FileAuditObservation Run(ISecureMessaging sm, byte[] path, int status,
        byte[] fci, int prefixLength)
    {
        int? size = null;
        try
        {
            var controls = Asn1Tree.Read(fci).SelectMany(n => n.Children).ToArray();
            var n = controls.FirstOrDefault(n => n.Tag == 0x80) ?? controls.FirstOrDefault(n => n.Tag == 0x81);
            if (n is not null && n.Value.Length is > 0 and <= 4)
            {
                long value = 0;
                foreach (var b in n.Value) value = value * 256 + b;
                if (value <= int.MaxValue) size = (int)value;
            }
            if (!controls.Any(n => n.Tag == 0x82 && n.Value.Length > 0 && (n.Value[0] & 7) == 1))
                return new(Convert.ToHexString(path), status, size, prefixLength, 0, 0, "Not identified as transparent EF", [], []);
        }
        catch (FormatException) { }
        if (status != 0x9000 || size is null or <= 0)
            return new(Convert.ToHexString(path), status, size, prefixLength, 0, 0, "No usable FCI size", [], []);
        var target = Math.Min(size.Value, 0x8000);
        var bytes = new List<byte>();
        var reads = new List<ReadObservation>();
        var completion = "Declared size reached";
        while (bytes.Count < target && reads.Count < 512)
        {
            var requested = Math.Min(0xC0, target - bytes.Count);
            while (true)
            {
                var (sw, data) = sm.ReadAt(bytes.Count, requested);
                reads.Add(new(bytes.Count, requested, sw, data.Length));
                if (data.Length > requested) throw new EmrtdException("READ BINARY exceeded requested length.");
                if (sw is not (0x9000 or 0x6282)) { completion = $"Stopped at {sw:X4}"; goto Finished; }
                if (data.Length == 0 && requested > 1 && reads.Count < 512)
                { requested = Math.Max(1, requested / 2); continue; }
                if (data.Length == 0) { completion = $"No data at {sw:X4}"; goto Finished; }
                bytes.AddRange(data);
                break;
            }
        }
        if (bytes.Count < target) completion = "Command limit reached";
        else if (size > target) completion = "32 KiB limit reached";
    Finished:
        var body = bytes.ToArray();
        var signatures = ImageScan.Scan(body);
        return new(Convert.ToHexString(path), status, size, prefixLength, bytes.Count,
            body.Skip(prefixLength).Count(b => b is not (0 or 0xFF)), completion, reads, signatures);
    }
}

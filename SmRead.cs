namespace RSAReader;

/// <summary>
/// Shared logic for reading a whole EF over secure messaging by walking its TLV records
/// with exact-length READ BINARYs. Some cards (e.g. this Gemalto profile) return 6282
/// with no data when the requested Le exceeds the file size, so the reader must never
/// ask for more bytes than the current record actually contains.
/// </summary>
internal static class SmRead
{
    /// <param name="readChunk">Reads <c>length</c> bytes at <c>offset</c>; returns the bytes,
    /// or an empty array at end of file / on error.</param>
    public static byte[] WholeFileByRecords(Func<int, int, byte[]> readChunk)
    {
        var data = new List<byte>();
        var offset = 0;
        const int cap = 0x8000;
        while (offset < cap)
        {
            // Read a short header to learn this record's total length.
            var head = readChunk(offset, 4);
            if (head.Length < 2) break;                 // end of file
            if (head[0] is 0x00 or 0xFF) break;         // padding after the last record

            int recordLen;
            try { recordLen = Emrtd.TlvTotalLength(head); }
            catch { data.AddRange(head); break; }

            if (recordLen <= 0) { data.AddRange(head); break; }
            if (recordLen <= head.Length)
            {
                data.AddRange(head[..recordLen]);
                offset += recordLen;
                continue;
            }

            data.AddRange(head);
            var got = head.Length;
            while (got < recordLen)
            {
                var want = Math.Min(0xC0, recordLen - got);
                var part = readChunk(offset + got, want);
                if (part.Length == 0) break;
                data.AddRange(part);
                got += part.Length;
            }
            offset += got;
            if (got < recordLen) break; // short read: stop rather than loop
        }
        return data.ToArray();
    }
}

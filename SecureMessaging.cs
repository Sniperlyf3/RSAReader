namespace RSAReader;

/// <summary>
/// ICAO 9303 secure messaging over an established BAC session. Wraps each command APDU
/// with encrypted data objects and a checksum, verifies the response checksum, and
/// decrypts the returned data. Handles the SELECT-EF and READ-BINARY commands needed
/// to retrieve a data group.
/// </summary>
internal sealed class SecureMessaging : ISecureMessaging
{
    private readonly Func<byte[], byte[]> _transceive;
    private readonly byte[] _ksEnc;
    private readonly byte[] _ksMac;
    private byte[] _ssc;

    public SecureMessaging(Func<byte[], byte[]> transceive, byte[] ksEnc, byte[] ksMac, byte[] ssc)
    {
        _transceive = transceive;
        _ksEnc = ksEnc;
        _ksMac = ksMac;
        _ssc = ssc;
    }

    /// <summary>SELECT an application by AID (P1=04, P2=0C); returns the status word.</summary>
    public Action<string>? Trace { get; set; }

    public (int Status, byte[] Data) ReadAt(int offset, int length)
    {
        if (offset < 0 || offset >= 0x8000 || length < 1 || length > 0xC0 || offset + length > 0x8000)
            throw new ArgumentOutOfRangeException(nameof(offset));
        return SendRaw([0x0C, 0xB0, (byte)(offset >> 8), (byte)offset], null, true, (byte)length);
    }

    public (int Status, byte[] Fci) TrySelectPath(byte[] path)
    {
        if (path.Length < 2 || path.Length % 2 != 0 || path.Length > 16)
            throw new ArgumentException("Expected a bounded file path.");
        if (path.Length == 2) return TrySelectFileWithFci(path);
        var absolute = path[0] == 0x3F && path[1] == 0;
        var selected = SendRaw([0x0C, 0xA4, (byte)(absolute ? 0x08 : 0x09), 0x00],
            absolute ? path[2..] : path, true);
        if (selected.Sw is not (0x6A86 or 0x6D00)) return selected;
        // Only a rejected selection method triggers the explicit hierarchy fallback.
        var start = 0;
        if (absolute)
        {
            var root = SendRaw([0x0C, 0xA4, 0x00, 0x0C], [0x3F, 0x00], false);
            if (root.Sw != 0x9000) return root;
            start = 2;
        }
        for (var i = start; i < path.Length - 2; i += 2)
        {
            var directory = SendRaw([0x0C, 0xA4, 0x01, 0x0C], path[i..(i + 2)], false);
            if (directory.Sw != 0x9000) return directory;
        }
        return TrySelectFileWithFci(path[^2..]);
    }

    public int TrySelectApplication(byte[] aid) => SendRaw(new byte[] { 0x0C, 0xA4, 0x04, 0x0C }, aid, false).Sw;

    public (int Status, byte[] Fci) TrySelectApplicationWithFci(byte[] aid)
    {
        var (status, fci) = SendRaw(new byte[] { 0x0C, 0xA4, 0x04, 0x00 }, aid, true);
        return (status, fci);
    }

    /// <summary>SELECT EF by file identifier (P1=02, P2=0C); returns the status word.</summary>
    public int TrySelectFile(byte[] fileId) => SendRaw(new byte[] { 0x0C, 0xA4, 0x02, 0x0C }, fileId, false).Sw;

    public (int Status, byte[] Fci) TrySelectFileWithFci(byte[] fileId)
    {
        var (status, fci) = SendRaw(new byte[] { 0x0C, 0xA4, 0x02, 0x00 }, fileId, true);
        return (status, fci);
    }

    public (int Status, byte[] Data) TryGetData(byte p1, byte p2)
    {
        var (status, data) = SendRaw(new byte[] { 0x0C, 0xCA, p1, p2 }, null, true);
        return (status, data);
    }

    public (int Status, byte[] Data) ReadShortEf(int sfi, int offset, int length)
    {
        if (sfi is < 1 or > 30) throw new ArgumentOutOfRangeException(nameof(sfi));
        if (offset is < 0 or > 0xFF || length is < 1 or > 0xC0) throw new ArgumentOutOfRangeException(nameof(offset));
        return SendRaw([0x0C, 0xB0, (byte)(0x80 | sfi), (byte)offset], null, true, (byte)length);
    }

    public (int Status, byte[] Fci) TrySelectApplicationByName(byte[] name, bool next)
    {
        if (name.Length is < 1 or > 16) throw new ArgumentException("Expected a 1-16 byte DF name.");
        return SendRaw([0x0C, 0xA4, 0x04, (byte)(next ? 0x02 : 0x00)], name, true);
    }

    public void SelectApplication(byte[] aid) => Ensure(TrySelectApplication(aid));

    public void SelectFile(byte[] fileId) => Ensure(TrySelectFile(fileId));

    /// <summary>Read the currently selected transparent EF in full.</summary>
    public byte[] ReadFile()
    {
        // Read the first 4 bytes to determine the TLV length.
        var head = ReadBinary(0, 4);
        var total = TlvTotalLength(head);
        if (total <= 0 || total > 0x10000) throw new EmrtdException("Unexpected data-group length.");

        var data = new List<byte>(head);
        var offset = data.Count;
        while (offset < total)
        {
            var chunk = Math.Min(0xDF, total - offset); // keep well under 256; SM adds overhead
            var part = ReadBinary(offset, chunk);
            if (part.Length == 0) break;
            data.AddRange(part);
            offset += part.Length;
        }
        return data.ToArray();
    }

    public byte[] ReadEntireFile() => SmRead.WholeFileByRecords(ReadChunk);

    public byte[] ReadOpaqueFile() => Research.OpaqueFileRead.WholeFile(ReadChunk);

    public int ProbeReadByteStatus() => SendRaw([0x0C, 0xB0, 0x00, 0x00], null, true, 0x01).Sw;

    private byte[] ReadChunk(int offset, int length)
    {
        var header = new byte[] { 0x0C, 0xB0, (byte)(offset >> 8 & 0x7F), (byte)(offset & 0xFF) };
        var (sw, part) = SendRaw(header, null, expectResponse: true, le: (byte)length);
        return sw is 0x9000 or 0x6282 ? part : Array.Empty<byte>();
    }

    private byte[] ReadBinary(int offset, int length)
    {
        var header = new byte[] { 0x0C, 0xB0, (byte)(offset >> 8 & 0xFF), (byte)(offset & 0xFF) };
        var (sw, plain) = SendRaw(header, commandData: null, expectResponse: true, le: (byte)length);
        if (sw != 0x9000 && sw != 0x6282)
        {
            if (offset == 0) throw new EmrtdException($"READ BINARY failed (status {sw:X4}).");
            return Array.Empty<byte>();
        }
        return plain;
    }

    private static void Ensure(int sw)
    {
        if (sw != 0x9000) throw new EmrtdException($"Secure-messaging command failed (status {sw:X4}).");
    }

    // ----- Core secure-messaging wrap/unwrap ----------------------------------

    private (int Sw, byte[] Plain) SendRaw(byte[] header, byte[]? commandData, bool expectResponse, byte le = 0x00)
    {
        // header is the 4-byte CLA(0x0C) INS P1 P2. Pad it to the block size for the MAC.
        var maskedHeader = Emrtd.Pad(header);

        byte[] do87 = Array.Empty<byte>();
        if (commandData is { Length: > 0 })
        {
            var encrypted = Emrtd.DesEdeCbcEncrypt(_ksEnc, Emrtd.Pad(commandData));
            // DO87: tag 87, len, 0x01 (padding-content indicator), cryptogram
            var value = Emrtd.Concat(new byte[] { 0x01 }, encrypted);
            do87 = Emrtd.Concat(new byte[] { 0x87, (byte)value.Length }, value);
        }

        byte[] do97 = Array.Empty<byte>();
        if (expectResponse)
            do97 = new byte[] { 0x97, 0x01, le };

        // Compute checksum over SSC || maskedHeader || DO87 || DO97.
        // RetailMac applies ISO 9797-1 padding itself, so pass the unpadded value.
        _ssc = Increment(_ssc);
        var m = Emrtd.Concat(maskedHeader, do87, do97);
        var n = Emrtd.Concat(_ssc, m);
        var cc = Emrtd.RetailMac(_ksMac, n);
        var do8E = Emrtd.Concat(new byte[] { 0x8E, 0x08 }, cc);

        var body = Emrtd.Concat(do87, do97, do8E);
        var apdu = Emrtd.Concat(header, new byte[] { (byte)body.Length }, body, new byte[] { 0x00 });

        Trace?.Invoke($"PLAIN TX {Convert.ToHexString(header)} DATA={Convert.ToHexString(commandData ?? [])} Le={(expectResponse ? le.ToString("X2") : "none")}");
        var resp = _transceive(apdu);
        if (resp is null || resp.Length < 2) throw new EmrtdException("No secure-messaging response.");
        var sw = (resp[^2] << 8) | resp[^1];

        // Advance the counter for the response too, so it stays aligned even after a
        // non-9000 status.
        _ssc = Increment(_ssc);
        if (resp.Length == 2)
            throw new EmrtdException($"Unprotected response {sw:X4}; end this session and retap.");
        var plain = VerifyAndExtract(resp[..^2], out var innerStatus);
        Trace?.Invoke($"PLAIN RX SW={innerStatus:X4} OUTER={sw:X4} DATA={Convert.ToHexString(plain)}");
        return (innerStatus, plain);
    }

    private byte[] VerifyAndExtract(byte[] respBody, out int innerStatus)
    {
        var nodes = Research.Asn1Tree.Read(respBody);
        if (nodes.Count is < 2 or > 3 || nodes[^2].Tag != 0x99 || nodes[^2].Value.Length != 2 ||
            nodes[^1].Tag != 0x8E || nodes[^1].Value.Length != 8 ||
            (nodes.Count == 3 && (nodes[0].Tag != 0x87 || nodes[0].Value.Length < 2 || nodes[0].Value[0] != 1)))
            throw new EmrtdException("Malformed protected response.");
        innerStatus = (nodes[^2].Value[0] << 8) | nodes[^2].Value[1];
        byte[] do87Data = Array.Empty<byte>();
        byte[] do99 = Array.Empty<byte>();
        byte[] do8E = Array.Empty<byte>();
        byte[] encryptedContent = Array.Empty<byte>();

        var i = 0;
        while (i < respBody.Length)
        {
            var tag = respBody[i];
            if (tag == 0x87)
            {
                var (len, hdr) = ReadLen(respBody, i + 1);
                var start = i + 1 + hdr;
                var value = respBody[start..(start + len)];
                do87Data = respBody[i..(start + len)];
                encryptedContent = value[1..]; // drop the 0x01 padding-content indicator
                i = start + len;
            }
            else if (tag == 0x99)
            {
                var len = respBody[i + 1];
                do99 = respBody[i..(i + 2 + len)];
                i += 2 + len;
            }
            else if (tag == 0x8E)
            {
                var len = respBody[i + 1];
                do8E = respBody[(i + 2)..(i + 2 + len)];
                i += 2 + len;
            }
            else break;
        }

        // RetailMac pads internally; concatenate SSC || DO87 || DO99 without pre-padding.
        var k = Emrtd.Concat(_ssc, do87Data, do99);
        var expected = Emrtd.RetailMac(_ksMac, k);
        if (!System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expected, do8E))
            throw new EmrtdException("Response checksum did not verify (session integrity error).");

        if (encryptedContent.Length == 0) return Array.Empty<byte>();
        var decrypted = Emrtd.DesEdeCbcDecrypt(_ksEnc, encryptedContent);
        return Emrtd.Unpad(decrypted);
    }

    private static (int Len, int HeaderBytes) ReadLen(byte[] data, int p)
    {
        var b = data[p];
        if (b < 0x80) return (b, 1);
        if (b == 0x81) return (data[p + 1], 2);
        if (b == 0x82) return ((data[p + 1] << 8) | data[p + 2], 3);
        throw new EmrtdException("Unsupported TLV length encoding.");
    }

    private static int TlvTotalLength(byte[] head)
    {
        // head starts with the DG tag (1-2 bytes) then a BER length.
        var p = 1;
        if ((head[0] & 0x1F) == 0x1F) p = 2; // multi-byte tag
        var b = head[p];
        int len, lenBytes;
        if (b < 0x80) { len = b; lenBytes = 1; }
        else if (b == 0x81) { len = head[p + 1]; lenBytes = 2; }
        else if (b == 0x82) { len = (head[p + 1] << 8) | head[p + 2]; lenBytes = 3; }
        else throw new EmrtdException("Unsupported data-group length encoding.");
        return p + lenBytes + len;
    }

    private static byte[] Increment(byte[] counter)
    {
        var c = (byte[])counter.Clone();
        for (var i = c.Length - 1; i >= 0; i--)
        {
            c[i]++;
            if (c[i] != 0) break;
        }
        return c;
    }
}

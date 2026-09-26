using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace RSAReader;

/// <summary>
/// AES-based ICAO 9303 secure messaging, as established by PACE. Encryption is
/// AES-CBC with an IV derived from the send-sequence counter (SSC); integrity is
/// AES-CMAC truncated to 8 bytes. Handles the SELECT-EF and READ-BINARY commands
/// needed to read a data group.
/// </summary>
internal sealed class AesSecureMessaging : ISecureMessaging
{
    private const int Block = 16;

    private readonly Func<byte[], byte[]> _transceive;
    private readonly byte[] _ksEnc;
    private readonly byte[] _ksMac;
    private byte[] _ssc; // 16-byte counter, starts at zero after PACE

    public AesSecureMessaging(Func<byte[], byte[]> transceive, byte[] ksEnc, byte[] ksMac)
    {
        _transceive = transceive;
        _ksEnc = ksEnc;
        _ksMac = ksMac;
        _ssc = new byte[Block];
    }

    public int TrySelectApplication(byte[] aid) => SendRaw(new byte[] { 0x0C, 0xA4, 0x04, 0x0C }, aid, false).Sw;

    public int TrySelectFile(byte[] fileId) => SendRaw(new byte[] { 0x0C, 0xA4, 0x02, 0x0C }, fileId, false).Sw;

    public void SelectApplication(byte[] aid) => Ensure(TrySelectApplication(aid));

    public void SelectFile(byte[] fileId) => Ensure(TrySelectFile(fileId));

    public byte[] ReadFile()
    {
        var head = ReadBinary(0, 4);
        var total = Emrtd.TlvTotalLength(head);
        if (total <= 0 || total > 0x20000) throw new EmrtdException("Unexpected data-group length.");

        var data = new List<byte>(head);
        var offset = data.Count;
        while (offset < total)
        {
            var chunk = Math.Min(0xC0, total - offset);
            var part = ReadBinary(offset, chunk);
            if (part.Length == 0) break;
            data.AddRange(part);
            offset += part.Length;
        }
        return data.ToArray();
    }

    public byte[] ReadEntireFile() => SmRead.WholeFileByRecords(ReadChunk);

    public byte[] ReadOpaqueFile() => Research.OpaqueFileRead.WholeFile(ReadChunk);

    private byte[] ReadChunk(int offset, int length)
    {
        var header = new byte[] { 0x0C, 0xB0, (byte)(offset >> 8 & 0x7F), (byte)(offset & 0xFF) };
        var (sw, part) = SendRaw(header, null, expectResponse: true, le: (byte)length);
        return sw is 0x9000 or 0x6282 ? part : Array.Empty<byte>();
    }

    private byte[] ReadBinary(int offset, int length)
    {
        var header = new byte[] { 0x0C, 0xB0, (byte)(offset >> 8 & 0x7F), (byte)(offset & 0xFF) };
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

    private (int Sw, byte[] Plain) SendRaw(byte[] header, byte[]? commandData, bool expectResponse, byte le = 0x00)
    {
        _ssc = Increment(_ssc);

        var maskedHeader = PadBlock(header);

        byte[] do87 = Array.Empty<byte>();
        if (commandData is { Length: > 0 })
        {
            var cryptogram = AesCbc(true, _ksEnc, ComputeIv(_ssc), PadBlock(commandData));
            var value = Emrtd.Concat(new byte[] { 0x01 }, cryptogram);
            do87 = Emrtd.Concat(new byte[] { 0x87 }, EncodeLength(value.Length), value);
        }

        byte[] do97 = Array.Empty<byte>();
        if (expectResponse)
            do97 = new byte[] { 0x97, 0x01, le };

        var m = Emrtd.Concat(maskedHeader, do87, do97);
        var cc = Cmac(_ksMac, PadBlock(Emrtd.Concat(_ssc, m)));
        var do8E = Emrtd.Concat(new byte[] { 0x8E, 0x08 }, cc);

        var body = Emrtd.Concat(do87, do97, do8E);
        var apdu = Emrtd.Concat(header, EncodeLength(body.Length), body, new byte[] { 0x00 });

        var resp = _transceive(apdu);
        if (resp is null || resp.Length < 2) throw new EmrtdException("No secure-messaging response.");
        var sw = (resp[^2] << 8) | resp[^1];

        // Advance the counter for the response too, so it stays aligned even after a
        // non-9000 status (the card increments on every command/response pair).
        _ssc = Increment(_ssc);
        // 0x9000 = OK; 0x6282 = end of file reached before Le bytes, but data is still returned.
        if (sw == 0x9000 || sw == 0x6282) return (sw, VerifyAndExtract(resp[..^2]));
        return (sw, Array.Empty<byte>());
    }

    private byte[] VerifyAndExtract(byte[] respBody)
    {
        byte[] do87Raw = Array.Empty<byte>();
        byte[] do99 = Array.Empty<byte>();
        byte[] do8E = Array.Empty<byte>();
        byte[] cryptogram = Array.Empty<byte>();

        var i = 0;
        while (i < respBody.Length)
        {
            var tag = respBody[i];
            if (tag == 0x87)
            {
                var (len, hdr) = ReadLen(respBody, i + 1);
                var start = i + 1 + hdr;
                do87Raw = respBody[i..(start + len)];
                cryptogram = respBody[(start + 1)..(start + len)]; // drop 0x01 indicator
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

        var expected = Cmac(_ksMac, PadBlock(Emrtd.Concat(_ssc, do87Raw, do99)));
        if (!expected.SequenceEqual(do8E))
            throw new EmrtdException("Response checksum did not verify (session integrity error).");

        if (cryptogram.Length == 0) return Array.Empty<byte>();
        var plain = AesCbc(false, _ksEnc, ComputeIv(_ssc), cryptogram);
        return UnpadBlock(plain);
    }

    // ----- primitives ---------------------------------------------------------

    private byte[] ComputeIv(byte[] ssc)
    {
        // IV = AES-ECB(KSenc, SSC), i.e. a single-block CBC encryption with a zero IV.
        return AesCbc(true, _ksEnc, new byte[Block], ssc);
    }

    private static byte[] AesCbc(bool encrypt, byte[] key, byte[] iv, byte[] data)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        var output = new byte[cipher.GetOutputSize(data.Length)];
        var n = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output[..n];
    }

    private static byte[] Cmac(byte[] key, byte[] data)
    {
        var mac = new CMac(new AesEngine(), 128);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);
        return full[..8];
    }

    private static byte[] PadBlock(byte[] data)
    {
        var padLen = Block - data.Length % Block;
        var padded = new byte[data.Length + padLen];
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;
        return padded;
    }

    private static byte[] UnpadBlock(byte[] data)
    {
        var i = data.Length - 1;
        while (i >= 0 && data[i] == 0x00) i--;
        if (i < 0 || data[i] != 0x80) return data;
        return data[..i];
    }

    private static byte[] EncodeLength(int len)
    {
        if (len < 0x80) return new[] { (byte)len };
        if (len < 0x100) return new byte[] { 0x81, (byte)len };
        return new byte[] { 0x82, (byte)(len >> 8), (byte)len };
    }

    private static (int Len, int HeaderBytes) ReadLen(byte[] data, int p)
    {
        var b = data[p];
        if (b < 0x80) return (b, 1);
        if (b == 0x81) return (data[p + 1], 2);
        if (b == 0x82) return ((data[p + 1] << 8) | data[p + 2], 3);
        throw new EmrtdException("Unsupported TLV length encoding.");
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

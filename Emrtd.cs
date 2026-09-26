using System.Security.Cryptography;
using System.Text;

namespace RSAReader;

/// <summary>
/// Implements the ICAO 9303 Basic Access Control (BAC) flow and the secure-messaging
/// reads needed to retrieve the machine-readable-zone data group (DG1) from an
/// electronic travel-document / eID chip.
///
/// BAC is not an authentication bypass: the access key is derived from data that is
/// printed on the card the holder is physically presenting (document/ID number, date
/// of birth, date of expiry). Only the legitimate holder of the card can supply those
/// values, which is exactly how off-the-shelf passport-reader apps work.
/// </summary>
public sealed class Emrtd
{
    private readonly Func<byte[], byte[]> _transceive;

    public Emrtd(Func<byte[], byte[]> transceive) => _transceive = transceive;

    /// <summary>Result of a successful chip read.</summary>
    public sealed record Result(string Mrz, string Summary);

    // ----- Public entry point -------------------------------------------------

    /// <summary>
    /// Runs SELECT applet -> BAC mutual authentication -> secure-messaging read of DG1.
    /// Throws <see cref="EmrtdException"/> with a human-readable message on any failure.
    /// </summary>
    public Result ReadDg1(string documentNumber, string dateOfBirthYyMmDd, string dateOfExpiryYyMmDd)
    {
        documentNumber = (documentNumber ?? "").Trim().ToUpperInvariant();
        dateOfBirthYyMmDd = Digits(dateOfBirthYyMmDd);
        dateOfExpiryYyMmDd = Digits(dateOfExpiryYyMmDd);

        if (documentNumber.Length == 0) throw new EmrtdException("Enter the document / ID number.");
        if (dateOfBirthYyMmDd.Length != 6) throw new EmrtdException("Date of birth must be 6 digits (YYMMDD).");
        if (dateOfExpiryYyMmDd.Length != 6) throw new EmrtdException("Date of expiry must be 6 digits (YYMMDD).");

        // 1. Select the eMRTD application. Some cards expose it as default, so a
        //    non-9000 here is not necessarily fatal; BAC below is the real test.
        TrySelectApplet();

        // 2. Derive the BAC key seed from the printed key.
        var kSeed = ComputeKSeed(documentNumber, dateOfBirthYyMmDd, dateOfExpiryYyMmDd);
        var kEnc = DeriveKey(kSeed, 1);
        var kMac = DeriveKey(kSeed, 2);

        // 3. GET CHALLENGE -> RND.IC (8 bytes)
        var (challengeResp, sw1) = Transmit(new byte[] { 0x00, 0x84, 0x00, 0x00, 0x08 });
        if (sw1 != 0x9000 || challengeResp.Length < 8)
            throw new EmrtdException($"GET CHALLENGE failed (status {sw1:X4}). The card did not start authentication.");
        var rndIc = challengeResp[..8];

        // 4. Build EXTERNAL AUTHENTICATE payload.
        var rndIfd = RandomBytes(8);
        var kIfd = RandomBytes(16);
        var s = Concat(rndIfd, rndIc, kIfd);                       // 32 bytes
        var eIfd = DesEdeCbcEncrypt(kEnc, s);                      // 32 bytes
        var mIfd = RetailMac(kMac, eIfd);                          // 8 bytes
        var cmdData = Concat(eIfd, mIfd);                          // 40 bytes

        var extAuth = Concat(new byte[] { 0x00, 0x82, 0x00, 0x00, (byte)cmdData.Length }, cmdData, new byte[] { 0x28 });
        var (authResp, authSw) = Transmit(extAuth);
        if (authSw != 0x9000)
            throw new EmrtdException(
                $"Mutual authentication failed (status {authSw:X4}). " +
                "The most common cause is a wrong document number, date of birth or expiry date.");
        if (authResp.Length < 40)
            throw new EmrtdException("Authentication response was too short.");

        // 5. Verify and decrypt the card's response.
        var eIc = authResp[..32];
        var mIc = authResp[32..40];
        if (!ConstantTimeEquals(mIc, RetailMac(kMac, eIc)))
            throw new EmrtdException("Card authentication MAC did not verify.");

        var r = DesEdeCbcDecrypt(kEnc, eIc);                       // RND.IC || RND.IFD || K.IC
        var rndIfdEcho = r[8..16];
        if (!ConstantTimeEquals(rndIfdEcho, rndIfd))
            throw new EmrtdException("Card did not echo our challenge; authentication rejected.");
        var kIc = r[16..32];

        // 6. Establish session keys and send-sequence counter.
        var kSessionSeed = Xor(kIfd, kIc);
        var ksEnc = DeriveKey(kSessionSeed, 1);
        var ksMac = DeriveKey(kSessionSeed, 2);
        var ssc = Concat(rndIc[4..8], rndIfd[4..8]);              // 8 bytes

        var sm = new SecureMessaging(_transceive, ksEnc, ksMac, ssc);

        // 7. Select EF.DG1 (file id 0101) and read it.
        sm.SelectFile(new byte[] { 0x01, 0x01 });
        var dg1 = sm.ReadFile();

        return BuildResultFromDg1(dg1);
    }

    /// <summary>Parses a DG1 data group into an MRZ string and a display summary.</summary>
    internal static Result BuildResultFromDg1(byte[] dg1)
    {
        var mrz = ParseDg1Mrz(dg1);
        return new Result(mrz, SummariseMrz(mrz));
    }

    /// <summary>Total on-card length of a data group from its leading tag+length bytes.</summary>
    internal static int TlvTotalLength(byte[] head)
    {
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

    // ----- APDU helpers -------------------------------------------------------

    private void TrySelectApplet()
    {
        // 00 A4 04 0C 07 A0 00 00 02 47 10 01  (SELECT by AID, no response data)
        var aid = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        var apdu = Concat(new byte[] { 0x00, 0xA4, 0x04, 0x0C, (byte)aid.Length }, aid);
        try { Transmit(apdu); } catch { /* fall through; BAC is the real gate */ }
    }

    private (byte[] Data, int Sw) Transmit(byte[] apdu)
    {
        var resp = _transceive(apdu);
        if (resp is null || resp.Length < 2)
            throw new EmrtdException("The card returned no response.");
        var sw = (resp[^2] << 8) | resp[^1];
        return (resp[..^2], sw);
    }

    // ----- Key derivation and MRZ key seed ------------------------------------

    private static byte[] ComputeKSeed(string doc, string dob, string exp)
    {
        var mrzInfo = doc + CheckDigit(doc) + dob + CheckDigit(dob) + exp + CheckDigit(exp);
        using var sha1 = SHA1.Create();
        var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(mrzInfo));
        return hash[..16];
    }

    private static byte[] DeriveKey(byte[] seed, int counter)
    {
        var d = Concat(seed, new byte[] { 0x00, 0x00, 0x00, (byte)counter });
        using var sha1 = SHA1.Create();
        var h = sha1.ComputeHash(d);
        var ka = h[..8];
        var kb = h[8..16];
        AdjustParity(ka);
        AdjustParity(kb);
        return Concat(ka, kb); // 16-byte two-key 3DES key
    }

    internal static char CheckDigit(string input)
    {
        int[] weights = { 7, 3, 1 };
        var sum = 0;
        for (var i = 0; i < input.Length; i++)
            sum += CharValue(input[i]) * weights[i % 3];
        return (char)('0' + sum % 10);
    }

    private static int CharValue(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'Z') return c - 'A' + 10;
        return 0; // '<' filler and anything else
    }

    private static void AdjustParity(byte[] key)
    {
        for (var i = 0; i < key.Length; i++)
        {
            var b = key[i];
            var ones = 0;
            for (var bit = 1; bit < 8; bit++) if ((b & (1 << bit)) != 0) ones++;
            // DES keys use odd parity: set (never toggle) the low bit so the total set-bit count is odd.
            key[i] = (byte)((b & 0xFE) | (ones % 2 == 0 ? 1 : 0));
        }
    }

    // ----- Cryptographic primitives -------------------------------------------

    internal static byte[] DesEdeCbcEncrypt(byte[] key16, byte[] data)
    {
        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.None;
        tdes.Key = key16;
        tdes.IV = new byte[8];
        using var enc = tdes.CreateEncryptor();
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    internal static byte[] DesEdeCbcDecrypt(byte[] key16, byte[] data)
    {
        using var tdes = TripleDES.Create();
        tdes.Mode = CipherMode.CBC;
        tdes.Padding = PaddingMode.None;
        tdes.Key = key16;
        tdes.IV = new byte[8];
        using var dec = tdes.CreateDecryptor();
        return dec.TransformFinalBlock(data, 0, data.Length);
    }

    /// <summary>ISO 9797-1 MAC algorithm 3 (retail MAC) with DES and padding method 2.</summary>
    internal static byte[] RetailMac(byte[] key16, byte[] data)
    {
        var ka = key16[..8];
        var kb = key16[8..16];
        var padded = Pad(data);

        using var des = DES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;

        // CBC-DES over all blocks with Ka.
        des.Key = ka;
        des.IV = new byte[8];
        byte[] y;
        using (var enc = des.CreateEncryptor())
        {
            var all = enc.TransformFinalBlock(padded, 0, padded.Length);
            y = all[^8..];
        }

        // Decrypt last block with Kb, then re-encrypt with Ka.
        des.Key = kb;
        des.IV = new byte[8];
        byte[] step;
        using (var dec = des.CreateDecryptor())
            step = dec.TransformFinalBlock(y, 0, 8);

        des.Key = ka;
        des.IV = new byte[8];
        using (var enc = des.CreateEncryptor())
            return enc.TransformFinalBlock(step, 0, 8);
    }

    internal static byte[] Pad(byte[] data)
    {
        var padLen = 8 - data.Length % 8;
        var padded = new byte[data.Length + padLen];
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;
        return padded;
    }

    internal static byte[] Unpad(byte[] data)
    {
        var i = data.Length - 1;
        while (i >= 0 && data[i] == 0x00) i--;
        if (i < 0 || data[i] != 0x80) return data; // not padded as expected; return as-is
        return data[..i];
    }

    // ----- Small utilities ----------------------------------------------------

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    internal static byte[] Concat(params byte[][] parts)
    {
        var len = parts.Sum(p => p.Length);
        var result = new byte[len];
        var offset = 0;
        foreach (var p in parts) { Array.Copy(p, 0, result, offset, p.Length); offset += p.Length; }
        return result;
    }

    private static byte[] Xor(byte[] a, byte[] b)
    {
        var r = new byte[a.Length];
        for (var i = 0; i < a.Length; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    private static bool ConstantTimeEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static string Digits(string? s) => new((s ?? "").Where(char.IsDigit).ToArray());

    // ----- DG1 / MRZ parsing --------------------------------------------------

    private static string ParseDg1Mrz(byte[] dg1)
    {
        // DG1 is a TLV: tag 61, containing tag 5F1F whose value is the MRZ string.
        var idx = IndexOf(dg1, new byte[] { 0x5F, 0x1F });
        if (idx < 0)
        {
            // Fall back to extracting the printable MRZ-looking characters.
            var printable = new string(dg1
                .Where(b => b == (byte)'<' || (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z'))
                .Select(b => (char)b).ToArray());
            if (printable.Length == 0) throw new EmrtdException("Could not locate MRZ data in DG1.");
            return printable;
        }

        var p = idx + 2;
        // Length may be one or more bytes (BER-TLV); MRZ is short so handle 1-byte and 0x81 forms.
        int len;
        if (dg1[p] == 0x81) { len = dg1[p + 1]; p += 2; }
        else { len = dg1[p]; p += 1; }
        var value = dg1[p..(p + len)];
        return Encoding.ASCII.GetString(value);
    }

    private static string SummariseMrz(string mrz)
    {
        // Split the raw MRZ into its fixed-width lines (TD1 = 3x30, TD3 = 2x44).
        var sb = new StringBuilder();
        int lineLen = mrz.Length % 30 == 0 ? 30 : (mrz.Length % 44 == 0 ? 44 : 0);
        if (lineLen > 0)
        {
            for (var i = 0; i + lineLen <= mrz.Length; i += lineLen)
                sb.AppendLine(mrz.Substring(i, lineLen));
        }
        else
        {
            sb.AppendLine(mrz);
        }

        // Best-effort field extraction for TD1 (identity-card) layout.
        if (lineLen == 30 && mrz.Length >= 90)
        {
            var l1 = mrz[..30];
            var l3 = mrz.Substring(60, 30);
            var docType = l1[..2].Replace("<", " ").Trim();
            var issuer = l1.Substring(2, 3).Replace("<", "");
            var names = l3.Replace('<', ' ').Trim();
            sb.AppendLine();
            sb.AppendLine($"Document type: {docType}");
            sb.AppendLine($"Issuing authority: {issuer}");
            sb.AppendLine($"Name: {names}");
        }

        sb.AppendLine();
        sb.Append("Data read from the chip after successful authentication. It is shown on this screen only and is not saved.");
        return sb.ToString();
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var found = true;
            for (var j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { found = false; break; }
            if (found) return i;
        }
        return -1;
    }
}

public sealed class EmrtdException : Exception
{
    public EmrtdException(string message) : base(message) { }
}

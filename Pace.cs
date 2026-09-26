using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcEcPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace RSAReader;

/// <summary>
/// Implements PACE (Password Authenticated Connection Establishment, ICAO 9303
/// Part 11 / BSI TR-03110) with the Card Access Number (CAN) as the password, using
/// the ECDH Generic Mapping variant. This is authenticated access with a value
/// printed on the card the holder presents, not an authentication bypass.
///
/// The elliptic-curve arithmetic, AES-CMAC and ASN.1 parsing are provided by
/// BouncyCastle; this class drives the card protocol on top of them.
/// </summary>
public sealed class Pace
{
    private readonly Func<byte[], byte[]> _transceive;

    public Pace(Func<byte[], byte[]> transceive) => _transceive = transceive;

    private enum CipherAlg { Aes, TripleDes }

    private sealed record PaceParameters(DerObjectIdentifier Oid, CipherAlg Cipher, int KeyBytes, string CurveName);

    // ----- public entry point -------------------------------------------------

    public Emrtd.Result ReadDg1WithCan(string can)
    {
        can = (can ?? "").Trim();
        if (can.Length == 0) throw new EmrtdException("Enter the Card Access Number (CAN).");

        var pace = ReadPaceParametersFromCardAccess();

        var password = Encoding.ASCII.GetBytes(can);
        var kPi = DeriveKey(password, 3, pace);

        // MSE:Set AT — select PACE with the CAN password.
        MseSetAt(pace.Oid);

        // Step 1: obtain and decrypt the card's nonce.
        var encNonce = GeneralAuthenticate(0x10, Tlv(0x7C, Array.Empty<byte>()), expectedInnerTag: 0x80);
        var s = DecryptNonce(pace, kPi, encNonce);

        // Curve / domain parameters.
        var x9 = ResolveCurve(pace.CurveName);
        var curve = x9.Curve;
        var dp = new ECDomainParameters(curve, x9.G, x9.N, x9.H, x9.GetSeed());
        var rng = new SecureRandom();

        // Step 2: Generic Mapping. Exchange mapping keys and build a fresh generator.
        var (d1, q1) = GenerateKeyPair(dp, rng);
        var q2Bytes = GeneralAuthenticate(0x10, Tlv(0x7C, Tlv(0x81, q1.GetEncoded(false))), expectedInnerTag: 0x82);
        var q2 = curve.DecodePoint(q2Bytes);
        var h = q2.Multiply(d1).Normalize();
        var sInt = new BcBigInteger(1, s);
        var gHat = x9.G.Multiply(sInt).Add(h).Normalize();
        var dpMapped = new ECDomainParameters(curve, gHat, x9.N, x9.H);

        // Step 3: ephemeral key agreement over the mapped generator.
        var (d2, q3) = GenerateKeyPair(dpMapped, rng);
        var q4Bytes = GeneralAuthenticate(0x10, Tlv(0x7C, Tlv(0x83, q3.GetEncoded(false))), expectedInnerTag: 0x84);
        var q4 = curve.DecodePoint(q4Bytes);
        var shared = q4.Multiply(d2).Normalize();
        var sharedX = shared.AffineXCoord.GetEncoded();

        var ksEnc = DeriveKey(sharedX, 1, pace);
        var ksMac = DeriveKey(sharedX, 2, pace);

        // Step 4: exchange and verify authentication tokens.
        var tPcd = Mac(pace, ksMac, EncodePublicKey(pace.Oid, q4));
        var tPiccBytes = GeneralAuthenticate(0x00, Tlv(0x7C, Tlv(0x85, tPcd)), expectedInnerTag: 0x86);
        var tPiccExpected = Mac(pace, ksMac, EncodePublicKey(pace.Oid, q3));
        if (!tPiccExpected.SequenceEqual(tPiccBytes))
            throw new EmrtdException("PACE authentication token did not verify. The most common cause is a wrong CAN.");

        // Secure messaging established. Select the LDS application and read DG1.
        return ReadDg1OverSecureMessaging(pace, ksEnc, ksMac);
    }

    // ----- EF.CardAccess ------------------------------------------------------

    private byte[] ReadEfCardAccess()
    {
        // EF.CardAccess is FID 011C under the master file and is readable without authentication.
        var (_, sw) = Transmit(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C });
        if (sw != 0x9000)
        {
            Transmit(new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00 }); // SELECT MF
            var (_, sw2) = Transmit(new byte[] { 0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1C });
            if (sw2 != 0x9000)
                throw new EmrtdException($"Could not select EF.CardAccess (status {sw2:X4}). This card may not support PACE.");
        }

        var (data, readSw) = Transmit(new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x00 });
        if (readSw != 0x9000 || data.Length == 0)
            throw new EmrtdException($"Could not read EF.CardAccess (status {readSw:X4}).");
        return data;
    }

    private PaceParameters ReadPaceParametersFromCardAccess()
    {
        var content = ReadEfCardAccess();
        var set = (Asn1Set)Asn1Object.FromByteArray(content);
        foreach (var entry in set)
        {
            var seq = Asn1Sequence.GetInstance(entry);
            if (seq.Count < 3) continue; // need protocol, version and a standardized parameterId
            var oid = DerObjectIdentifier.GetInstance(seq[0]);
            var oidStr = oid.Id;
            if (!oidStr.StartsWith("0.4.0.127.0.7.2.2.4.2")) continue; // id-PACE-ECDH-GM only

            var parameterId = DerInteger.GetInstance(seq[2]).Value.IntValue;
            var (cipher, keyBytes) = oidStr switch
            {
                "0.4.0.127.0.7.2.2.4.2.1" => (CipherAlg.TripleDes, 16),
                "0.4.0.127.0.7.2.2.4.2.2" => (CipherAlg.Aes, 16),
                "0.4.0.127.0.7.2.2.4.2.3" => (CipherAlg.Aes, 24),
                "0.4.0.127.0.7.2.2.4.2.4" => (CipherAlg.Aes, 32),
                _ => throw new EmrtdException($"Unsupported PACE algorithm {oidStr}.")
            };
            return new PaceParameters(oid, cipher, keyBytes, CurveNameFor(parameterId));
        }
        throw new EmrtdException("The card does not advertise a supported PACE-ECDH-GM profile in EF.CardAccess.");
    }

    private static string CurveNameFor(int parameterId) => parameterId switch
    {
        8 => "secp192r1",
        9 => "brainpoolP192r1",
        10 => "secp224r1",
        11 => "brainpoolP224r1",
        12 => "secp256r1",
        13 => "brainpoolP256r1",
        14 => "brainpoolP320r1",
        15 => "secp384r1",
        16 => "brainpoolP384r1",
        17 => "brainpoolP512r1",
        18 => "secp521r1",
        _ => throw new EmrtdException($"Unsupported PACE domain parameter id {parameterId}.")
    };

    private static X9ECParameters ResolveCurve(string name)
    {
        // ECNamedCurveTable aggregates the SEC/NIST (secp*) and TeleTrusT (brainpool*) curves.
        var x9 = ECNamedCurveTable.GetByName(name);
        if (x9 is null) throw new EmrtdException($"Curve {name} is not available.");
        return x9;
    }

    // ----- card protocol steps ------------------------------------------------

    private void MseSetAt(DerObjectIdentifier oid)
    {
        var oidValue = OidContentBytes(oid);
        var data = Emrtd.Concat(
            Tlv(0x80, oidValue),
            new byte[] { 0x83, 0x01, 0x02 }); // password reference 0x02 = CAN
        var apdu = Emrtd.Concat(new byte[] { 0x00, 0x22, 0xC1, 0xA4 }, LengthPrefix(data), data);
        var (_, sw) = Transmit(apdu);
        if (sw != 0x9000) throw new EmrtdException($"MSE:Set AT for PACE failed (status {sw:X4}).");
    }

    private byte[] GeneralAuthenticate(byte cla, byte[] dynamicAuthData, byte expectedInnerTag)
    {
        var apdu = Emrtd.Concat(new byte[] { cla, 0x86, 0x00, 0x00 }, LengthPrefix(dynamicAuthData), dynamicAuthData, new byte[] { 0x00 });
        var (data, sw) = Transmit(apdu);
        if (sw != 0x9000) throw new EmrtdException($"PACE GENERAL AUTHENTICATE failed (status {sw:X4}).");

        // Response is a 0x7C dynamic authentication data object; return the requested inner value.
        var inner = TlvValue(data, 0x7C);
        return TlvValue(inner, expectedInnerTag);
    }

    private byte[] DecryptNonce(PaceParameters pace, byte[] kPi, byte[] encNonce)
    {
        return pace.Cipher == CipherAlg.Aes
            ? AesCbcNoPad(false, kPi, new byte[16], encNonce)
            : DesEdeCbcNoPad(false, kPi, new byte[8], encNonce);
    }

    private Emrtd.Result ReadDg1OverSecureMessaging(PaceParameters pace, byte[] ksEnc, byte[] ksMac)
    {
        ISecureMessaging sm = pace.Cipher == CipherAlg.Aes
            ? new AesSecureMessaging(_transceive, ksEnc, ksMac)
            // 3DES PACE reuses the retail-MAC secure messaging with a zero send-sequence counter.
            : new SecureMessaging(_transceive, ksEnc, ksMac, new byte[8]);

        var report = new StringBuilder();
        report.AppendLine("PACE authentication succeeded. Card structure probe:");

        // 1. Standard ICAO eMRTD application, then EF.DG1.
        var aid = new byte[] { 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01 };
        var swApp = sm.TrySelectApplication(aid);
        report.AppendLine($"• SELECT eMRTD app A0000002471001: {swApp:X4}");
        if (swApp == 0x9000)
        {
            var swDg1 = sm.TrySelectFile(new byte[] { 0x01, 0x01 });
            report.AppendLine($"• SELECT EF.DG1 (0101): {swDg1:X4}");
            if (swDg1 == 0x9000) return Emrtd.BuildResultFromDg1(sm.ReadFile());
        }

        // Reset to the master file for the remaining probes.
        report.AppendLine($"• SELECT MF (3F00): {sm.TrySelectFile(new byte[] { 0x3F, 0x00 }):X4}");

        // 2. EF.DIR lists the applications on the card (identifiers only, no personal data).
        var (swDir, dir) = TryReadFile(sm, new byte[] { 0x2F, 0x00 });
        report.AppendLine($"• EF.DIR (2F00): {swDir:X4}" + (dir.Length > 0 ? $" -> {Convert.ToHexString(dir)}" : ""));

        // 3. EF.COM lists which data groups are present (tags only, no personal data).
        var (swCom, com) = TryReadFile(sm, new byte[] { 0x01, 0x1E });
        report.AppendLine($"• EF.COM (011E): {swCom:X4}" + (com.Length > 0 ? $" -> {Convert.ToHexString(com)}" : ""));

        // 4. EF.DG1 directly under the master file.
        var swDg1Mf = sm.TrySelectFile(new byte[] { 0x01, 0x01 });
        report.AppendLine($"• SELECT EF.DG1 at MF (0101): {swDg1Mf:X4}");
        if (swDg1Mf == 0x9000) return Emrtd.BuildResultFromDg1(sm.ReadFile());

        report.AppendLine();
        report.Append("No ICAO DG1 found, but the secure channel works. The status words above map the card so a targeted read can be added.");
        return new Emrtd.Result(string.Empty, report.ToString());
    }

    private static (int Sw, byte[] Data) TryReadFile(ISecureMessaging sm, byte[] fid)
    {
        var sw = sm.TrySelectFile(fid);
        if (sw != 0x9000) return (sw, Array.Empty<byte>());
        try { return (sw, sm.ReadFile()); }
        catch (EmrtdException) { return (sw, Array.Empty<byte>()); }
    }

    // ----- key derivation and MAC ---------------------------------------------

    private static byte[] DeriveKey(byte[] secret, int counter, PaceParameters pace)
    {
        var input = Emrtd.Concat(secret, new byte[] { 0x00, 0x00, 0x00, (byte)counter });
        if (pace.Cipher == CipherAlg.TripleDes)
        {
            using var sha1 = SHA1.Create();
            var h = sha1.ComputeHash(input);
            var ka = h[..8];
            var kb = h[8..16];
            AdjustDesParity(ka);
            AdjustDesParity(kb);
            return Emrtd.Concat(ka, kb);
        }

        if (pace.KeyBytes == 16)
        {
            using var sha1 = SHA1.Create();
            return sha1.ComputeHash(input)[..16];
        }

        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(input)[..pace.KeyBytes];
    }

    private static void AdjustDesParity(byte[] key)
    {
        for (var i = 0; i < key.Length; i++)
        {
            var b = key[i];
            var ones = 0;
            for (var bit = 1; bit < 8; bit++) if ((b & (1 << bit)) != 0) ones++;
            key[i] = (byte)((b & 0xFE) | (ones % 2 == 0 ? 1 : 0));
        }
    }

    private static byte[] Mac(PaceParameters pace, byte[] key, byte[] data)
    {
        if (pace.Cipher == CipherAlg.TripleDes)
            return Emrtd.RetailMac(key, data);

        var mac = new CMac(new AesEngine(), 128);
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var full = new byte[mac.GetMacSize()];
        mac.DoFinal(full, 0);
        return full[..8];
    }

    // ----- crypto primitives --------------------------------------------------

    private static byte[] AesCbcNoPad(bool encrypt, byte[] key, byte[] iv, byte[] data)
    {
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        var output = new byte[cipher.GetOutputSize(data.Length)];
        var n = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output[..n];
    }

    private static byte[] DesEdeCbcNoPad(bool encrypt, byte[] key16, byte[] iv, byte[] data)
    {
        var key24 = Emrtd.Concat(key16, key16[..8]);
        var cipher = new BufferedBlockCipher(new CbcBlockCipher(new DesEdeEngine()));
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key24), iv));
        var output = new byte[cipher.GetOutputSize(data.Length)];
        var n = cipher.ProcessBytes(data, 0, data.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output[..n];
    }

    private static (BcBigInteger D, BcEcPoint Q) GenerateKeyPair(ECDomainParameters dp, SecureRandom rng)
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(dp, rng));
        var kp = gen.GenerateKeyPair();
        return (((ECPrivateKeyParameters)kp.Private).D, ((ECPublicKeyParameters)kp.Public).Q.Normalize());
    }

    // ----- TLV helpers --------------------------------------------------------

    private static byte[] EncodePublicKey(DerObjectIdentifier oid, BcEcPoint point)
    {
        // TR-03110 public-key data object for the authentication token: 7F49 { 06 OID, 86 point }.
        var body = Emrtd.Concat(
            Tlv(0x06, OidContentBytes(oid)),
            Tlv(0x86, point.GetEncoded(false)));
        return Emrtd.Concat(new byte[] { 0x7F, 0x49 }, LengthPrefix(body), body);
    }

    private static byte[] OidContentBytes(DerObjectIdentifier oid)
    {
        var encoded = oid.GetEncoded(); // 0x06 len content
        var (len, hdr) = ParseLength(encoded, 1);
        return encoded[(1 + hdr)..(1 + hdr + len)];
    }

    private static byte[] Tlv(byte tag, byte[] value) => Emrtd.Concat(new[] { tag }, LengthPrefix(value), value);

    private static byte[] LengthPrefix(byte[] value)
    {
        var len = value.Length;
        if (len < 0x80) return new[] { (byte)len };
        if (len < 0x100) return new byte[] { 0x81, (byte)len };
        return new byte[] { 0x82, (byte)(len >> 8), (byte)len };
    }

    /// <summary>Returns the value of the first data object with <paramref name="tag"/> (single-byte tag).</summary>
    private static byte[] TlvValue(byte[] data, byte tag)
    {
        var i = 0;
        while (i < data.Length)
        {
            var t = data[i++];
            var (len, hdr) = ParseLength(data, i);
            i += hdr;
            if (t == tag) return data[i..(i + len)];
            i += len;
        }
        throw new EmrtdException($"Expected data object {tag:X2} was not present in the card response.");
    }

    private static (int Len, int HeaderBytes) ParseLength(byte[] data, int p)
    {
        var b = data[p];
        if (b < 0x80) return (b, 1);
        if (b == 0x81) return (data[p + 1], 2);
        if (b == 0x82) return ((data[p + 1] << 8) | data[p + 2], 3);
        throw new EmrtdException("Unsupported TLV length encoding.");
    }

    private (byte[] Data, int Sw) Transmit(byte[] apdu)
    {
        var resp = _transceive(apdu);
        if (resp is null || resp.Length < 2) throw new EmrtdException("The card returned no response.");
        var sw = (resp[^2] << 8) | resp[^1];
        return (resp[..^2], sw);
    }
}

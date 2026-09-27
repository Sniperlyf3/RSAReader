namespace RSAReader.Research;

// Decodes the SecurityInfos SET carried by EF.CardAccess and EF.CardSecurity
// (ICAO 9303 Part 11, BSI TR-03110). The point is to learn which authentication
// protocols the chip advertises: PACE, Chip Authentication (clone detection),
// PACE-CAM, and especially Terminal Authentication. If Terminal Authentication is
// present, sensitive groups (the portrait) sit behind EAC and need DHA-issued CV
// certificates, so the map tells us whether the photo is reachable at all.
internal static class SecurityInfoDecoder
{
    // Longest prefix first so PACE-CAM and domain-parameter arcs win over the
    // shorter id-PACE / id-CA prefixes they extend.
    private static readonly (string Prefix, string Name)[] Protocols =
    {
        ("0.4.0.127.0.7.2.2.4.6", "PACE-CAM (Chip Authentication Mapping; contactless clone detection)"),
        ("0.4.0.127.0.7.2.2.4", "PACE"),
        ("0.4.0.127.0.7.2.2.3", "Chip Authentication"),
        ("0.4.0.127.0.7.2.2.2", "Terminal Authentication (EAC-protected data present)"),
        ("0.4.0.127.0.7.2.2.1", "Chip Authentication public key"),
        ("0.4.0.127.0.7.2.2.5", "Restricted Identification"),
        ("0.4.0.127.0.7.2.2.6", "Restricted Identification domain parameters"),
        ("0.4.0.127.0.7.2.2.8", "id-CI (Chip Identifier)"),
        ("0.4.0.127.0.7.3.2.1", "Card/Chip security object content"),
    };

    public static List<SecurityInfoObservation> Decode(string source, byte[] content)
    {
        var result = new List<SecurityInfoObservation>();
        IReadOnlyList<Asn1Node> nodes;
        try { nodes = Asn1Tree.Read(content); }
        catch (FormatException) { return result; }

        // EF.CardAccess is a SET OF SecurityInfo; some encodings wrap it in a SEQUENCE.
        var container = nodes.FirstOrDefault(n => n.Tag is 0x31 or 0x30);
        var infos = container is not null && container.Children.Count > 0 ? container.Children : nodes;
        foreach (var info in infos)
        {
            var oidNode = info.Child(0x06);
            if (oidNode is null) continue;
            string oid;
            try { oid = Asn1Tree.Oid(oidNode.Value); }
            catch (FormatException) { continue; }
            var name = Protocols.FirstOrDefault(p =>
                oid == p.Prefix || oid.StartsWith(p.Prefix + ".", StringComparison.Ordinal)).Name
                ?? "Unrecognized security info";
            // requiredData for these protocols is a small version/keyReference INTEGER.
            // Export only those bounded values, never any embedded key material.
            var integers = info.Children
                .Where(c => c.Tag == 0x02 && c.Value.Length is > 0 and <= 2)
                .Select(c => { var v = 0; foreach (var b in c.Value) v = (v << 8) | b; return v; })
                .ToList();
            var detail = integers.Count == 0 ? null : "integer parameters " + string.Join(", ", integers);
            result.Add(new SecurityInfoObservation(source, oid, name, detail));
        }
        return result;
    }

    // EF.CardSecurity is a CMS SignedData (RFC 5652). Pull the embedded signer
    // certificate(s) so their issuer chain and validity can be inspected through the
    // existing certificate path. The eContent is itself a SecurityInfos SET, decoded
    // separately. Returns DER blobs; parsing/validation happens elsewhere.
    public static List<byte[]> ExtractSignedDataCertificates(byte[] cms)
    {
        var result = new List<byte[]>();
        try
        {
            var top = Asn1Tree.Read(cms).FirstOrDefault(n => n.Tag == 0x30);
            var contentType = top?.Child(0x06);
            if (contentType is null || Asn1Tree.Oid(contentType.Value) != "1.2.840.113549.1.7.2")
                return result; // not a SignedData ContentInfo
            // ContentInfo.content [0] EXPLICIT -> SignedData SEQUENCE.
            var signedData = top!.Child(0xA0)?.Child(0x30);
            // SignedData.certificates [0] IMPLICIT SET OF Certificate.
            var certs = signedData?.Child(0xA0);
            if (certs is null) return result;
            foreach (var cert in certs.Children)
                if (cert.Tag == 0x30) result.Add(Der.Encode(cert));
        }
        catch (FormatException) { }
        return result;
    }

    // The eContent OCTET STRING inside SignedData holds the SecurityInfos SET for a
    // CardSecurity object. Returns it so the same SecurityInfo map applies.
    public static byte[]? ExtractEncapsulatedContent(byte[] cms)
    {
        try
        {
            var top = Asn1Tree.Read(cms).FirstOrDefault(n => n.Tag == 0x30);
            var signedData = top?.Child(0xA0)?.Child(0x30);
            // encapContentInfo SEQUENCE { eContentType OID, eContent [0] EXPLICIT OCTET STRING }.
            var encap = signedData?.Children.FirstOrDefault(n => n.Tag == 0x30 && n.Child(0x06) is not null);
            var eContent = encap?.Child(0xA0)?.Child(0x04);
            return eContent is { Value.Length: > 0 } ? eContent.Value : null;
        }
        catch (FormatException) { return null; }
    }
}

// Minimal DER re-encoder. Asn1Tree keeps each element's content bytes but not its
// original tag/length header, so this rebuilds them. DER length encoding is minimal,
// so re-encoding a node whose value came from valid DER reproduces the original bytes.
internal static class Der
{
    public static byte[] Encode(Asn1Node node)
    {
        var tag = EncodeTag(node.Tag);
        var len = EncodeLength(node.Value.Length);
        var result = new byte[tag.Length + len.Length + node.Value.Length];
        Buffer.BlockCopy(tag, 0, result, 0, tag.Length);
        Buffer.BlockCopy(len, 0, result, tag.Length, len.Length);
        Buffer.BlockCopy(node.Value, 0, result, tag.Length + len.Length, node.Value.Length);
        return result;
    }

    private static byte[] EncodeTag(int tag)
    {
        if (tag <= 0xFF) return [(byte)tag];
        var bytes = new List<byte>();
        while (tag > 0) { bytes.Insert(0, (byte)(tag & 0xFF)); tag >>= 8; }
        return bytes.ToArray();
    }

    private static byte[] EncodeLength(int len)
    {
        if (len < 0x80) return [(byte)len];
        if (len < 0x100) return [0x81, (byte)len];
        if (len < 0x10000) return [0x82, (byte)(len >> 8), (byte)len];
        return [0x83, (byte)(len >> 16), (byte)(len >> 8), (byte)len];
    }
}

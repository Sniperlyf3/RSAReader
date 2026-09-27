using RSAReader.Research;

var fixture = Pkcs15Report.FromJson(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "fixtures", "redacted-report.json")));
if (fixture.SchemaVersion != 1 || fixture.Files.Count != 2 || fixture.Objects.Count != 1)
    throw new Exception("Fixture schema failed to replay.");
var roundTrip = Pkcs15Report.FromJson(fixture.ToJson());
if (roundTrip.Compare(fixture).Contains("Added 1")) throw new Exception("Round-trip comparison changed objects.");
if (fixture.ToJson().Contains("SAMPLE PERSON")) throw new Exception("Identity appeared in redacted output.");

var collector = new Pkcs15Collector();
collector.Observe("PuKDF", [0x50, 0x02], 0x9000,
    Convert.FromHexString("301130080C0653616D706C6530050403010203"));
var report = collector.Analyze();
if (report.Objects.Count != 1 || report.Objects[0].Label != "Sample")
    throw new Exception("PKCS#15 directory record did not decode.");
var sensitive = new Pkcs15Collector();
sensitive.Observe("PuKDF", [0x50, 0x02], 0x9000,
    Convert.FromHexString("3016300F0C0D53414D504C4520504552534F4E30050403010203"));
if (sensitive.Analyze().ToJson().Contains("SAMPLE PERSON"))
    throw new Exception("Unrecognized PKCS#15 label leaked to export.");
var key = new Pkcs15Collector();
key.Observe("PuKDF", [0x50, 0x02], 0x9000,
    Convert.FromHexString("3019300A0C045465737403020640300B0402AABB03020520020103"));
var decodedKey = key.Analyze().Objects.Single();
if (decodedKey.KeyIdHash is null || decodedKey.Usage != "sign")
    throw new Exception("Key ID or usage was decoded from the wrong PKCS#15 attribute sequence.");
var ec = new Pkcs15Collector();
ec.Observe("PuKDF", [0x50, 0x02], 0x9000,
    Convert.FromHexString("A019300A0C045465737403020640300B0402AABB03020520020103"));
var decodedEc = ec.Analyze().Objects.Single();
if (decodedEc.Kind != "Public key (EC)" || decodedEc.KeyIdHash != decodedKey.KeyIdHash || decodedEc.Usage != "sign")
    throw new Exception("IMPLICIT context-tagged EC public-key attributes were not decoded.");
var auth = new Pkcs15Collector();
auth.Observe("AODF", [0x50, 0x06], 0x9000,
    Convert.FromHexString("A019300A0C045465737403020640300B0402AABB03020520020103"));
auth.Observe("PrKDF", [0x50, 0x01], 0x9000, []);
auth.Report.Findings.Add("PrKDF one-byte READ BINARY returned 6982; SELECT 9000 alone does not establish private-key availability.");
var authReport = auth.Analyze();
if (authReport.Objects.Single().Kind != "Biometric template authentication object" ||
    !authReport.Findings.Any(x => x.Contains("security condition not satisfied")))
    throw new Exception("Authentication metadata or PrKDF access status was misinterpreted.");
var pin = new Pkcs15Collector();
pin.Observe("AODF", [0x50, 0x06], 0x9000,
    Convert.FromHexString("302630060C045465737430040402AA00A1163014030206400A010102010502011002011080020081"));
var pinObject = pin.Analyze().Objects.Single();
if (pinObject.Kind != "PIN authentication object" ||
    pinObject.Usage != "ASCII numeric PIN; minimum 5, stored 16 bytes, maximum 16" ||
    pinObject.AuthReference != "PIN reference 129")
    throw new Exception("PIN metadata was not decoded without the PIN value.");
var oddPin = new Pkcs15Collector();
oddPin.Observe("AODF", [0x50, 0x06], 0x9000,
    Convert.FromHexString("302630060C045465737430040402AA00A11630140302003F0A010102010802011002011080020082"));
if (!oddPin.Analyze().Findings.Any(x => x.Contains("both unblocking-PIN and SO-PIN")))
    throw new Exception("Conflicting PIN role flags were not reported.");
var biometric = new Pkcs15Collector();
biometric.Observe("AODF", [0x50, 0x06], 0x9000,
    Convert.FromHexString("A020300030040402AA21A11630140302078006032B060130060A01000A0100020121"));
var bioObject = biometric.Analyze().Objects.Single();
if (bioObject.Usage != "template OID 1.3.6.1; left thumb fingerprint (0/0)" ||
    bioObject.AuthReference != "biometric reference 33")
    throw new Exception("Biometric template metadata was not decoded.");
var opaque = System.Text.Encoding.ASCII.GetBytes("Label with a non-TLV length");
var recovered = OpaqueFileRead.WholeFile((offset, length) => offset + length <= opaque.Length
    ? opaque.AsSpan(offset, length).ToArray() : []);
if (!recovered.SequenceEqual(opaque)) throw new Exception("Opaque EF read stopped at a false TLV length.");

// ----- Image signature scan ------------------------------------------------
var scanBlob = Convert.FromHexString("0000FFD8FF00005F2E00");
var scanHits = ImageScan.Scan(scanBlob);
if (!scanHits.Any(h => h.StartsWith("JPEG candidate at 2")) ||
    !scanHits.Any(h => h.Contains("5F2E candidate at 7")))
    throw new Exception("Image/biometric signature scan missed a known marker.");

// ----- SecurityInfo decoding (minimal DER built inline) --------------------
static byte[] Tlv(int tag, params byte[][] parts)
{
    var body = parts.SelectMany(p => p).ToArray();
    if (body.Length >= 0x80) throw new Exception("Test TLV bodies must be short-form.");
    return new[] { (byte)tag, (byte)body.Length }.Concat(body).ToArray();
}
var oidTa = Tlv(0x06, Convert.FromHexString("04007F0007020202"));       // 0.4.0.127.0.7.2.2.2
var oidCam = Tlv(0x06, Convert.FromHexString("04007F00070202040602"));  // 0.4.0.127.0.7.2.2.4.6.2
var taInfo = Tlv(0x30, oidTa, Tlv(0x02, [0x01]));
var camInfo = Tlv(0x30, oidCam);
var securityInfos = Tlv(0x31, taInfo, camInfo);
var decoded = SecurityInfoDecoder.Decode("EF.CardAccess", securityInfos);
if (decoded.Count != 2 ||
    !decoded.Any(s => s.Oid == "0.4.0.127.0.7.2.2.2" && s.Name.Contains("Terminal Authentication") && s.Detail == "integer parameters 1") ||
    !decoded.Any(s => s.Oid == "0.4.0.127.0.7.2.2.4.6.2" && s.Name.Contains("PACE-CAM")))
    throw new Exception("SecurityInfo protocol map did not decode as expected.");

// ----- CMS SignedData certificate extraction (DER re-encode round-trip) ----
var oidSignedData = Tlv(0x06, Convert.FromHexString("2A864886F70D010702"));
var encapMin = Tlv(0x30, Tlv(0x06, [0x2A]));
var innerCert = Tlv(0x30, Tlv(0x02, [0x07]));
var certsSet = Tlv(0xA0, innerCert);
var signedDataForCerts = Tlv(0x30, Tlv(0x02, [0x03]), Tlv(0x31), encapMin, certsSet, Tlv(0x31));
var cmsForCerts = Tlv(0x30, oidSignedData, Tlv(0xA0, signedDataForCerts));
var extractedCerts = SecurityInfoDecoder.ExtractSignedDataCertificates(cmsForCerts);
if (extractedCerts.Count != 1 || Convert.ToHexString(extractedCerts[0]) != "3003020107")
    throw new Exception("SignedData certificate extraction/DER re-encode failed.");

// ----- CMS eContent extraction (CardSecurity SecurityInfos) ----------------
var eSet = Tlv(0x31, taInfo);
var encapWithContent = Tlv(0x30, Tlv(0x06, [0x2A]), Tlv(0xA0, Tlv(0x04, eSet)));
var signedDataForEContent = Tlv(0x30, Tlv(0x02, [0x03]), Tlv(0x31), encapWithContent, Tlv(0x31));
var cmsForEContent = Tlv(0x30, oidSignedData, Tlv(0xA0, signedDataForEContent));
var eContent = SecurityInfoDecoder.ExtractEncapsulatedContent(cmsForEContent);
if (eContent is null || !eContent.SequenceEqual(eSet) ||
    !SecurityInfoDecoder.Decode("EF.CardSecurity", eContent).Any(s => s.Name.Contains("Terminal Authentication")))
    throw new Exception("CardSecurity eContent extraction failed.");

// ----- Enumeration observations survive the redacted round-trip ------------
var probe = new Pkcs15Collector();
probe.ObserveShortEf(0x1D, 0x9000, null, Convert.FromHexString("FFD8FFAABBCC"), "End of file or short read");
probe.ObserveShortEf(0x0A, 0x6982, null, [], "File exists but is protected");
probe.ObserveDiscoveredAid(Convert.FromHexString("A000000018"), 0x9000, Convert.FromHexString("6F03840100"), "first");
probe.ObserveSecurityInfos(decoded);
var probeBack = Pkcs15Report.FromJson(probe.Report.ToJson());
if (probeBack.ShortEfs.Count != 2 ||
    !probeBack.ShortEfs.Any(e => e.Sfi == 0x1D && e.Signatures.Any(s => s.StartsWith("JPEG"))) ||
    !probeBack.ShortEfs.Any(e => e.Sfi == 0x0A && e.SelectStatus == 0x6982))
    throw new Exception("Short EF observations did not round-trip.");
if (probeBack.DiscoveredAids.Count != 1 || probeBack.DiscoveredAids[0].DiscoveredDfName != "00")
    throw new Exception("Discovered AID DF name was not recorded.");
if (probeBack.SecurityInfos.Count != 2)
    throw new Exception("Security infos did not round-trip in the report.");

// ----- Short-EF content classification -------------------------------------
var classify = new Pkcs15Collector();
var knownFile = Convert.FromHexString("0102030405060708");
classify.Observe("EF.DIR", [0x2F, 0x00], 0x9000, knownFile); // mapped by file identifier
classify.ObserveShortEf(0x11, 0x9000, 8, knownFile, "Complete", "PKCS#15 application");
classify.ObserveShortEf(0x12, 0x9000, null, Convert.FromHexString("01020304"), "Truncated", "PKCS#15 application");
classify.ObserveShortEf(0x13, 0x9000, 3, Convert.FromHexString("FFFFFF"), "Complete", "PKCS#15 application");
classify.ObserveShortEf(0x14, 0x9000, 4, Convert.FromHexString("AABBCCDD"), "Complete", "PKCS#15 application");
classify.ObserveShortEf(0x15, 0x9000, 4, Convert.FromHexString("AABBCCDD"), "Complete", "PKCS#15 application");
var classified = classify.Analyze();
string? Verdict(int sfi) => classified.ShortEfs.First(e => e.Sfi == sfi).IdentityMatch;
if (Verdict(0x11) != "identical to already-mapped EF 2F00")
    throw new Exception($"SFI 11 identity wrong: {Verdict(0x11)}");
if (Verdict(0x12) != "prefix of already-mapped EF 2F00 (first 4 bytes)")
    throw new Exception($"SFI 12 identity wrong: {Verdict(0x12)}");
if (Verdict(0x13) != "padding only (no content)")
    throw new Exception($"SFI 13 identity wrong: {Verdict(0x13)}");
if (Verdict(0x14)?.StartsWith("distinct") != true)
    throw new Exception($"SFI 14 identity wrong: {Verdict(0x14)}");
if (Verdict(0x15) != "duplicate of SFI 14 [PKCS#15 application]")
    throw new Exception($"SFI 15 identity wrong: {Verdict(0x15)}");
if (!classified.Findings.Any(f => f.Contains("genuinely new/unmapped SFIs [14]")))
    throw new Exception("Classification summary did not isolate the genuinely new SFI.");
if (!classified.Findings.Any(f => f.Contains("Access rules for genuinely new SFIs were not retrieved")))
    throw new Exception("Missing access-rule limitation note for unmapped SFIs.");
// The verdict must survive the redacted export round-trip.
if (Pkcs15Report.FromJson(classified.ToJson()).ShortEfs.First(e => e.Sfi == 0x14).IdentityMatch?.StartsWith("distinct") != true)
    throw new Exception("Short-EF identity verdict did not round-trip.");

// ----- Pinned LAWtrust chain validation + AIA/CRL extraction ----------------
if (LawTrustAnchors.Roots().Count != 2 || LawTrustAnchors.Intermediates().Count != 7)
    throw new Exception("Pinned LAWtrust anchor bundle did not load the expected certificates.");
var chainProbe = new Pkcs15Collector();
using (var authCa01 = LawTrustAnchors.Intermediates()[1]) // LAWtrust AUTH CA01: has AIA + CRL, chains to a pinned root
    chainProbe.ObserveEmbeddedCertificate("test intermediate", authCa01.RawData);
var chainCert = chainProbe.Report.Certificates.Single();
if (!chainCert.ChainResult.StartsWith("Verified", StringComparison.Ordinal))
    throw new Exception($"Known LAWtrust CA did not verify against the pinned roots: {chainCert.ChainResult}");
if (!chainCert.AuthorityInfoAccess.Contains("caIssuers") || !chainCert.AuthorityInfoAccess.Contains("LTRootCA02.cer"))
    throw new Exception($"AIA caIssuers URL was not extracted: {chainCert.AuthorityInfoAccess}");
if (!chainCert.CrlDistributionPoints.Contains("crl.lawtrust.co.za"))
    throw new Exception($"CRL distribution point was not extracted: {chainCert.CrlDistributionPoints}");

// A certificate that is not from the LAWtrust PKI must not verify.
var stranger = new Pkcs15Collector();
using (var rsa = System.Security.Cryptography.RSA.Create(2048))
{
    var req = new System.Security.Cryptography.X509Certificates.CertificateRequest(
        "CN=Not LAWtrust", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
        System.Security.Cryptography.RSASignaturePadding.Pkcs1);
    using var selfSigned = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    stranger.ObserveEmbeddedCertificate("stranger", selfSigned.RawData);
}
if (!stranger.Report.Certificates.Single().ChainResult.StartsWith("Unverified", StringComparison.Ordinal))
    throw new Exception("A non-LAWtrust certificate was not rejected by the pinned chain check.");

Console.WriteLine("Research fixture replay and directory decoding passed.");

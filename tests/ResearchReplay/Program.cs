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
var biometric = new Pkcs15Collector();
biometric.Observe("AODF", [0x50, 0x06], 0x9000,
    Convert.FromHexString("A020300030040402AA21A11630140302078006032B060130060A01000A0100020121"));
var bioObject = biometric.Analyze().Objects.Single();
if (bioObject.Usage != "template OID 1.3.6.1; type 0/0" ||
    bioObject.AuthReference != "biometric reference 33")
    throw new Exception("Biometric template metadata was not decoded.");
var opaque = System.Text.Encoding.ASCII.GetBytes("Label with a non-TLV length");
var recovered = OpaqueFileRead.WholeFile((offset, length) => offset + length <= opaque.Length
    ? opaque.AsSpan(offset, length).ToArray() : []);
if (!recovered.SequenceEqual(opaque)) throw new Exception("Opaque EF read stopped at a false TLV length.");
Console.WriteLine("Research fixture replay and directory decoding passed.");

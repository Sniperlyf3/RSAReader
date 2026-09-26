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
Console.WriteLine("Research fixture replay and directory decoding passed.");

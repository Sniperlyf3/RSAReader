using RSAReader;
using RSAReader.Research;

var sent = 0;
byte[] Capture(byte[] apdu)
{
    sent++;
    // Fixed VERIFY reference 81; its only command data is the 8-byte SM MAC.
    if (apdu.Length != 16 || !apdu.AsSpan(0, 7).SequenceEqual(new byte[] { 0x0C, 0x20, 0x00, 0x81, 0x0A, 0x8E, 0x08 }) || apdu[^1] != 0)
        throw new Exception($"Unexpected VERIFY APDU: {Convert.ToHexString(apdu)}");
    return [0x69, 0x82]; // bare response must be rejected, not retried
}

var key = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
foreach (ISecureMessaging sm in new ISecureMessaging[]
{
    new AesSecureMessaging(Capture, key, key),
    new SecureMessaging(Capture, key, key, new byte[8])
})
{
    var before = sent;
    try { sm.QueryUserPinStatus(); throw new Exception("Bare response was accepted."); }
    catch (EmrtdException) { }
    if (sent != before + 1) throw new Exception("VERIFY was retried.");
}

// Synthetic PKCS#15 record with AD00 and User PIN reference 81.
var aodf = Convert.FromHexString("3016300630040402AD00A10C300A0A010180020081020101");
if (!PinStatusProbe.HasExpectedUserPin(aodf)) throw new Exception("Expected PIN metadata rejected.");
var other = (byte[])aodf.Clone();
other[^4] = 0x82;
if (PinStatusProbe.HasExpectedUserPin(other)) throw new Exception("Wrong reference accepted.");
if (!PinStatusProbe.Describe(0x63C3, 0).Contains("3 retries")) throw new Exception("Retry count lost.");
if (PinStatusProbe.Describe(0x9000, 0).Contains("retries remaining")) throw new Exception("9000 misreported count.");
if (PinStatusProbe.Describe(0x63C3, 1).Contains("3 retries")) throw new Exception("Response data accepted.");

Console.WriteLine("PIN status replay passed.");

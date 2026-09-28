namespace RSAReader.Research;

// ISO/IEC 7816-4:2005 section 7.5.6: absent verification data requests status.
// This experiment never supplies a PIN, retries VERIFY, or changes references.
internal static class PinStatusProbe
{
    public static string Run(ISecureMessaging sm)
    {
        var aid = Convert.FromHexString("E828BD080F0147656D20503135");
        var selected = sm.TrySelectApplication(aid);
        if (selected != 0x9000) return $"PIN status not queried: application SELECT {selected:X4}.";
        selected = sm.TrySelectFile([0x50, 0x06]);
        if (selected != 0x9000) return $"PIN status not queried: authentication directory SELECT {selected:X4}.";
        var directory = sm.ReadEntireFile();
        if (!HasExpectedUserPin(directory))
            return "PIN status not queried: expected User PIN object AD00 with reference 81 was not uniquely identified.";
        // Restore the application before addressing its PIN reference.
        selected = sm.TrySelectApplication(aid);
        if (selected != 0x9000) return $"PIN status not queried: application reselection {selected:X4}.";
        var (status, data) = sm.QueryUserPinStatus();
        return Describe(status, data.Length) + " No PIN value was submitted. Experiment finished; remove and retap before another operation.";
    }

    internal static bool HasExpectedUserPin(byte[] directory)
    {
        try
        {
            // The object identifier is the second top-level SEQUENCE (30 04 04 02 AD 00).
            // The first SEQUENCE contains the label, flags, and the separate AD82 auth ID.
            var matches = Asn1Tree.Read(directory).Where(n => n.Tag == 0x30 &&
                n.Children.Count >= 3 && n.Children[1].Tag == 0x30 &&
                n.Children[1].Child(0x04)?.Value is [0xAD, 0x00]).ToList();
            if (matches.Count != 1) return false;
            var attrs = matches[0].Child(0xA1)?.Child(0x30);
            return (attrs?.Child(0x80)?.Value is [0x00, 0x81] or [0x81]) &&
                attrs?.Child(0x0A)?.Value is [0x01];
        }
        catch (FormatException) { return false; }
    }

    internal static string Describe(int status, int dataLength)
    {
        var prefix = $"User PIN status (reference 81): {status:X4}. ";
        if (dataLength != 0) return prefix + "Unexpected response data; retry count unknown.";
        if ((status & 0xFFF0) == 0x63C0)
            return prefix + $"Card reports {status & 0x0F} retries remaining.";
        return prefix + (status switch
        {
            0x9000 => "Verification not required in the current state; retry count not reported.",
            0x6983 => "Authentication method blocked; retry count not reported.",
            0x6982 => "Security condition not satisfied; retry count unknown.",
            0x6985 => "Conditions of use not satisfied; retry count unknown.",
            0x6A88 => "PIN reference not found; retry count unknown.",
            0x6700 or 0x6A80 or 0x6A81 or 0x6A86 or 0x6D00 or 0x6E00 =>
                "Status query unsupported or rejected; retry count unknown.",
            _ => "Retry count unknown."
        });
    }
}

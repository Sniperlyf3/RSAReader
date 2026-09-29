namespace RSAReader.Research;

// ISO/IEC 7816-4:2005 section 7.5.6: absent verification data requests status.
// PIN submission is a separate, single-candidate operation with a fresh counter check.
internal static class PinStatusProbe
{
    private static readonly byte[] Aid = Convert.FromHexString("E828BD080F0147656D20503135");

    public static string Run(ISecureMessaging sm)
    {
        var selected = sm.TrySelectApplication(Aid);
        if (selected != 0x9000) return $"PIN status not queried: application SELECT {selected:X4}.";
        selected = sm.TrySelectFile([0x50, 0x06]);
        if (selected != 0x9000) return $"PIN status not queried: authentication directory SELECT {selected:X4}.";
        var directory = sm.ReadEntireFile();
        if (!HasExpectedUserPin(directory))
            return "PIN status not queried: expected User PIN object AD00 with reference 81 was not uniquely identified.";
        // Restore the application before addressing its PIN reference.
        selected = sm.TrySelectApplication(Aid);
        if (selected != 0x9000) return $"PIN status not queried: application reselection {selected:X4}.";
        var (status, data) = sm.QueryUserPinStatus();
        return Describe(status, data.Length) + " No PIN value was submitted. Experiment finished; remove and retap before another operation.";
    }

    public static string TryOneCandidate(ISecureMessaging sm, byte[] digits)
    {
        if (digits.Length is < 5 or > 16 || digits.Any(b => b is < 0x30 or > 0x39))
            return "PIN not submitted: enter 5–16 decimal digits.";
        var selected = sm.TrySelectApplication(Aid);
        if (selected != 0x9000) return $"PIN not submitted: application SELECT {selected:X4}.";
        selected = sm.TrySelectFile([0x50, 0x06]);
        if (selected != 0x9000) return $"PIN not submitted: authentication directory SELECT {selected:X4}.";
        var directory = sm.ReadEntireFile();
        if (!HasExpectedUserPinFormat(directory))
            return "PIN not submitted: card PIN format differs from the observed profile.";
        selected = sm.TrySelectApplication(Aid);
        if (selected != 0x9000) return $"PIN not submitted: application reselection {selected:X4}.";
        var (before, beforeData) = sm.QueryUserPinStatus();
        if (beforeData.Length != 0 || (before & 0xFFF0) != 0x63C0)
            return $"PIN not submitted: current retry count unavailable (status {before:X4}).";
        var remaining = before & 0x0F;
        if (remaining < 2) return $"PIN not submitted: {remaining} retry remains; this app stops before the last attempt.";

        var formatted = new byte[16];
        try
        {
            digits.CopyTo(formatted, 0); // The observed AODF requires right padding with 00.
            var (status, data) = sm.VerifyUserPin(formatted);
            if (data.Length != 0) return $"One PIN was submitted; card returned {status:X4} with unexpected data. Stop and retap.";
            if (status == 0x9000) return "User PIN accepted (9000). One PIN was submitted; remove and retap before further work.";
            if ((status & 0xFFF0) == 0x63C0)
                return $"User PIN rejected ({status:X4}); card reports {status & 0x0F} retries remaining. Stop and retap.";
            return $"One PIN was submitted; card returned {status:X4}. Retry count unknown; stop and retap.";
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(formatted); }
    }

    private static bool HasExpectedUserPinFormat(byte[] directory)
    {
        if (!HasExpectedUserPin(directory)) return false;
        try
        {
            var pin = Asn1Tree.Read(directory).Single(n => n.Tag == 0x30 && n.Children.Count >= 3 &&
                n.Children[1].Tag == 0x30 && n.Children[1].Child(0x04)?.Value is [0xAD, 0x00]);
            var attrs = pin.Child(0xA1)?.Child(0x30);
            var lengths = attrs?.Children.Where(n => n.Tag == 0x02).Select(n => n.Value).ToArray();
            // ASCII numeric, minimum 5, stored/max 16, needs padding, pad byte 00.
            return attrs?.Child(0x03)?.Value is [0x04, 0x0C, 0x10] &&
                lengths is [[0x05], [0x10], [0x10]] && attrs.Child(0x04)?.Value is [0x00];
        }
        catch (FormatException) { return false; }
        catch (InvalidOperationException) { return false; }
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

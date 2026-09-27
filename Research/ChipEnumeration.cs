using System.Text;

namespace RSAReader.Research;

// Read-only enumeration sweeps layered on top of the established PACE/AES channel.
// Nothing here writes, verifies a PIN, or runs an authentication command; every
// method records status words and bounded metadata and hides content bytes. The aim
// is to surface anything EF.DIR does not advertise — a chip-security object, an
// unlisted short EF, or an undisclosed applet — that might hold the portrait.
internal static class ChipEnumeration
{
    private const int SignatureCap = 0x1000; // enough to catch an image/biometric header

    // Sweep short file identifiers 1-30 in the current DF context. A READ BINARY with
    // the SFI in P1 selects and reads the EF in one command; 6A82 means no such file,
    // 6982 indicates an unsatisfied security status, not proof that an EF exists.
    public static void SweepShortEfs(ISecureMessaging sm, Pkcs15Collector collector, string context, StringBuilder report)
    {
        report.AppendLine();
        report.AppendLine($"Short EF (SFI) sweep — {context} context (values hidden):");
        for (var sfi = 1; sfi <= 30; sfi++)
        {
            var body = new List<byte>();
            var reads = new List<ReadObservation>();
            var initialStatus = 0xFFFF;
            var terminalStatus = 0xFFFF;
            var completion = "Incomplete: command limit reached";
            try
            {
                while (body.Count < SignatureCap && reads.Count < 512)
                {
                    var requested = Math.Min(0xC0, SignatureCap - body.Count);
                    while (true)
                    {
                        // Until data is returned, repeat the SFI selection. An empty
                        // warning does not establish that the current EF changed.
                        var (sw, part) = body.Count == 0
                            ? sm.ReadShortEf(sfi, 0, requested)
                            : sm.ReadAt(body.Count, requested);
                        if (reads.Count == 0) initialStatus = sw;
                        terminalStatus = sw;
                        reads.Add(new(body.Count, requested, sw, part.Length));
                        if (part.Length > requested)
                            throw new EmrtdException("READ BINARY exceeded requested length.");
                        if (sw is not (0x9000 or 0x6282))
                        {
                            completion = $"Incomplete: stopped at {sw:X4}; file size unknown";
                            goto Finished;
                        }
                        if (part.Length == 0)
                        {
                            if (requested > 1 && reads.Count < 512)
                            {
                                requested = Math.Max(1, requested / 2);
                                continue;
                            }
                            completion = requested == 1
                                ? $"Read boundary at offset {body.Count}, one-byte request returned {sw:X4}; file size unconfirmed"
                                : "Incomplete: command limit reached";
                            goto Finished;
                        }
                        body.AddRange(part);
                        // A short response or recovered smaller request may leave
                        // readable bytes. Continue from the actual returned length.
                        break;
                    }
                }
                if (body.Count >= SignatureCap)
                    completion = "Incomplete: 4 KiB capture limit reached";
            Finished:
                collector.ObserveShortEf(sfi, initialStatus, null, body.ToArray(), completion,
                    context, terminalStatus, reads);
                var signatures = ImageScan.Scan(body.ToArray());
                report.AppendLine($"• SFI {sfi:X2}: initial {initialStatus:X4}, terminal {terminalStatus:X4}, {body.Count} bytes hidden; {completion}" +
                    (signatures.Count == 0 ? "" : $"; {string.Join(", ", signatures)}"));
            }
            catch (EmrtdException ex)
            {
                collector.ObserveShortEf(sfi, initialStatus, null, body.ToArray(),
                    $"Incomplete: session failed: {ex.Message}", context, null, reads);
                report.AppendLine($"• SFI {sfi:X2}: session failed: {ex.Message}");
                throw; // MAC/transport failures invalidate the session; do not keep probing.
            }
        }
    }

    // EF.CardSecurity (FID 011D under the MF, short EF id 1D). If present it is a CMS
    // SignedData whose signer certificate yields a DHA chain and whose eContent lists
    // the same SecurityInfos as EF.CardAccess (including any Chip Authentication key).
    public static void ReadCardSecurity(ISecureMessaging sm, Pkcs15Collector collector, StringBuilder report)
    {
        report.AppendLine();
        report.AppendLine("EF.CardSecurity (011D / SFI 1D):");
        byte[] body = [];
        var status = sm.TrySelectPath([0x3F, 0x00, 0x01, 0x1D]).Status;
        if (status == 0x9000)
        {
            body = sm.ReadOpaqueFile();
        }
        else
        {
            try
            {
                var (sfiStatus, first) = sm.ReadShortEf(0x1D, 0, 0xC0);
                status = sfiStatus;
                if (sfiStatus is 0x9000 or 0x6282 && first.Length > 0)
                {
                    var acc = new List<byte>(first);
                    var chunk = first;
                    while (chunk.Length == 0xC0 && acc.Count < 0x8000)
                    {
                        var (sw, part) = sm.ReadAt(acc.Count, Math.Min(0xC0, 0x8000 - acc.Count));
                        if (sw is not (0x9000 or 0x6282) || part.Length == 0) break;
                        acc.AddRange(part);
                        chunk = part;
                    }
                    body = acc.ToArray();
                }
            }
            catch (EmrtdException ex) { report.AppendLine($"  SFI read failed: {ex.Message}"); }
        }

        collector.Observe("EF.CardSecurity", [0x01, 0x1D], status, body);
        report.AppendLine($"• 011D: SELECT/READ {status:X4}, {body.Length} bytes");
        if (body.Length == 0)
        {
            report.AppendLine("  Not present or not readable in this session (absence is not proven).");
            return;
        }
        var eContent = SecurityInfoDecoder.ExtractEncapsulatedContent(body);
        if (eContent is not null)
        {
            var infos = SecurityInfoDecoder.Decode("EF.CardSecurity", eContent);
            collector.ObserveSecurityInfos(infos);
            report.AppendLine($"  eContent SecurityInfos: {infos.Count}");
        }
        var certs = SecurityInfoDecoder.ExtractSignedDataCertificates(body);
        report.AppendLine($"  Embedded SignedData certificates: {certs.Count}");
        foreach (var der in certs) collector.ObserveEmbeddedCertificate("EF.CardSecurity signer", der);
        collector.Report.Findings.Add(eContent is not null ? "EF.CardSecurity CMS content was decoded but its signature, issuer chain and revocation status remain unverified." : "EF.CardSecurity returned bytes, but CMS SignedData content was not decoded; authenticity and even file format remain unverified.");
    }

    // Enumerate applets by partial DF name. SELECT P1=04, P2=00 returns the first
    // applet whose AID starts with the prefix; P2=02 walks to the next. Not every card
    // supports this; unsupported returns 6A82/6A86/6D00 rather than an empty applet list.
    public static void EnumerateAids(ISecureMessaging sm, Pkcs15Collector collector, StringBuilder report)
    {
        report.AppendLine();
        report.AppendLine("Partial-AID enumeration (SELECT P1=04, next occurrence):");
        foreach (var prefix in new[]
        {
            Convert.FromHexString("A000000018"), // Gemalto RID
            Convert.FromHexString("E828BD08"),   // prefix observed in EF.DIR AID
        })
        {
            try
            {
                var (status, fci) = sm.TrySelectApplicationByName(prefix, next: false);
                collector.ObserveDiscoveredAid(prefix, status, fci, "first");
                report.AppendLine($"• {Convert.ToHexString(prefix)} first: {status:X4} ({DescribeStatus(status)}), {fci.Length} FCI bytes");
                var count = 0;
                while (status == 0x9000 && count < 8)
                {
                    count++;
                    (status, fci) = sm.TrySelectApplicationByName(prefix, next: true);
                    collector.ObserveDiscoveredAid(prefix, status, fci, $"next #{count}");
                    report.AppendLine($"• {Convert.ToHexString(prefix)} next #{count}: {status:X4} ({DescribeStatus(status)}), {fci.Length} FCI bytes");
                }
            }
            catch (EmrtdException ex)
            {
                report.AppendLine($"• {Convert.ToHexString(prefix)}: enumeration failed: {ex.Message}");
            }
        }
        collector.Report.Findings.Add("Partial-AID matching is optional card behaviour. 6A82/6A86/6D00 mean the mode is unsupported here, not that undisclosed applets are absent.");
    }

    private static string DescribeStatus(int sw) => sw switch
    {
        0x9000 => "success",
        0x6282 => "end of file / partial",
        0x6982 => "security status not satisfied",
        0x6A82 => "file or application not found",
        0x6A83 => "record not found",
        0x6A86 => "incorrect P1/P2",
        0x6D00 => "instruction not supported",
        0x6999 => "applet selection failed",
        0xFFFF => "read failed",
        _ => "see status word",
    };
}

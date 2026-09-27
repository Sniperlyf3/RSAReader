# Portrait research: file audit and isolated application selection

## First experiment

1. Install the signed build, enter the CAN, and enable **Include decrypted responses** if you want to share readable file contents.
2. Remove the card and tap it again. Tap **Read chip data (PACE / CAN)** and keep it still until completion.
3. Open PKCS#15 research to copy the redacted report. `FileAudits` records selection status, FCI size, parsed prefix size, every read offset/status/length, nonpadding bytes after the prefix, and possible image signatures.
4. Use **Share raw trace file (sensitive)** for the full trace, or **Copy raw trace (sensitive)** for smaller captures. The on-screen preview is limited to 24,000 characters; export retains up to 4 MiB and explicitly marks truncation.

The raw trace includes wire TX/RX. Opting in before scanning also captures plaintext command headers/data and MAC-verified decrypted response bytes, with inner and outer status words. This is necessary to inspect PACE-protected contents. CAN and session keys are never logged. Raw data is not included in the redacted report or uploaded automatically. A shared trace file stays in app cache until Clear, a new scan, or the next MainPage creation. External copies and clipboard contents are not cleared by the app.

## Application experiments

Use the candidate picker (or enter a researched 5–16-byte AID), remove/retap the card, and tap **Probe selected application (fresh tap)**. Each experiment establishes PACE again. It records an MF/EF.DIR control before selection, selects exactly one candidate, then repeats the control. Application selection is no longer a batch at the end of a potentially changed session. An unavailable control path does not establish a broken secure channel. An unprotected or invalid-MAC response ends the experiment; retap before continuing.

Start with GemP15 as a control. The other built-in candidates are hypotheses, not claims about South African cards. The latest physical report returned 6A82 for ICAO LDS1, NDEF, PIV, and standard PKCS#15 in a shared session.

## What the audit establishes

The old reader stops at the first 00/FF record header. The audit separately reads known transparent EFs up to the FCI size, including padding. Tag 81 may include structural overhead, so it is an audit target, not a guaranteed payload length. Reads are capped at 32 KiB and 512 commands per file. Oversized reads returning empty 6282 are retried at smaller lengths; access denial stops the audit. A JPEG/JP2/face marker is only a candidate, not a decoded portrait. The original parsed directory prefix is retained separately; unexplained tail bytes are not silently interpreted as new objects.

Discovered paths preserve their parent components. Absolute paths use SELECT from MF, relative paths use SELECT from current DF, and short references restore the disclosed application first. Unsupported path-selection methods have an explicit MF/DF traversal fallback. No fallback discards path components. Audit paths and plaintext trace commands expose selection context.

## Enumeration sweeps

After the directed reads, a normal PACE/CAN scan now runs four read-only enumeration sweeps to widen coverage toward the portrait:

- **EF.CardAccess security-info map.** Lists every advertised `SecurityInfo` protocol OID (PACE, Chip Authentication, PACE-CAM, Terminal Authentication). Terminal Authentication would place the portrait behind EAC / DHA CV certificates; Chip Authentication or PACE-CAM would give clone detection.
- **SFI sweep.** `READ BINARY` with `P1 = 0x80 | SFI` for SFI 1–30, in both the master-file and PKCS#15 application contexts. `6A82` = no file, `6982` = protected file present. Readable headers are scanned for image/biometric signatures.
- **EF.CardSecurity (`011D` / SFI `1D`).** Parsed as CMS `SignedData`: the embedded signer certificate is inspected (fingerprints/extensions only) and the encapsulated `SecurityInfos` are decoded.
- **Partial-AID enumeration.** `SELECT` P1=`04` with a truncated AID (Gemalto RID `A000000018`, observed `E828BD08`), then P2=`02` for the next occurrence, to surface applets EF.DIR does not advertise.

These sweeps change the current selection and run last, so they cannot disturb the directed reads. They never write, verify a PIN, or authenticate. The redacted report exports protocol OIDs, discovered applet DF names, short-EF status words, TLV shape, and signature offsets — never content bytes. Signature markers detected: JPEG `FFD8FF`, JPEG2000 `FF4FFF51` and `0000000C6A50…`, ISO 19794-5 `FAC\0`, and biometric template tags `5F2E`/`7F2E`.

## Remaining physical work

We need a fresh card scan to learn whether directory tails contain only padding and whether the new path-selection methods work on this profile. Public Gemalto documentation suggests separate PKI/storage/biometric applications on some platform families; it does not identify this card's portrait AID. A trace from a reader that actually displays the chip portrait would be valuable. No photo has been located or decoded by this change, and no identity-verification integration is added.

### Short-EF read recovery

The SFI sweep retries empty `6282` or `9000` responses with progressively
smaller lengths at the same offset, down to one byte. Before the first bytes
arrive, retries retain the SFI in READ BINARY. Subsequent reads advance by the
actual returned length, including after short responses. This recovers tails
from cards that reject a request extending beyond the file.

Each capture exports its DF context, initial and terminal status, and individual
read offsets, requested lengths, statuses and returned lengths. A one-byte empty
response establishes an observed read boundary only; the file size remains
unconfirmed. Other errors and the 4 KiB / 512-command limits are explicitly
reported as incomplete. TLV parse failures are retained as metadata, without
exporting content. Failed context selection skips that sweep, and session
failures stop probing. No card content from diagnostic traces is stored in source.

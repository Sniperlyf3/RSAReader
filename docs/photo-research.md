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

## Remaining physical work

We need a fresh card scan to learn whether directory tails contain only padding and whether the new path-selection methods work on this profile. Public Gemalto documentation suggests separate PKI/storage/biometric applications on some platform families; it does not identify this card's portrait AID. A trace from a reader that actually displays the chip portrait would be valuable. No photo has been located or decoded by this change, and no identity-verification integration is added.

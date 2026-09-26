# RSAReader

An Android .NET MAUI reference app for inspecting the NFC interface of South African Smart ID cards. The card application and file layout are not documented publicly enough to assume an eMRTD layout, so this project records the observable ISO-DEP/APDU behavior without pretending the card format is known.

## Build and install

Install the .NET 9 SDK, MAUI Android workload (`dotnet workload install maui-android`), and Android SDK. Then run:

```sh
dotnet restore RSAReader.csproj -r android-arm64
dotnet publish RSAReader.csproj -f net9.0-android -c Release -r android-arm64
```

The release build targets ARM64 phones. Full trimming and R8 shrink the managed and Java code; AOT is disabled to keep the APK small. The signed release APK is about 9.3 MB. Pull requests validate the release build without uploading an APK. Pushes to `main` and manual workflow runs upload only the verified signed `RSAReader-arm64.apk` as the `RSAReader-arm64-signed` artifact.

### Signing for in-place updates

Android requires the package name and signing certificate to stay the same, and the new APK's version code must be higher. The CI workflow uses a dedicated keystore and assigns a version code of `10000 + GITHUB_RUN_NUMBER`. The keystore and its password belong in the repository's **Actions secrets**, not an Actions cache: caches are readable by pull requests and can expire.

Generate one signing key with alias `rsareader` (the command prompts for its password), back up both the keystore and its password, then store them as the repository secrets `RSA_READER_KEYSTORE_B64` and `RSA_READER_SIGNING_PASSWORD`:

```sh
keytool -genkeypair -storetype PKCS12 -keystore rsareader.p12 \
  -alias rsareader -keyalg RSA -keysize 3072 -validity 36500
```

Use the same password for the keystore and key. Put that password in a private text file. With an authenticated GitHub CLI, the helper uploads both secrets without printing either value:

```sh
./scripts/upload-signing-secrets.sh /path/to/rsareader.p12 /path/to/password.txt
```

The key must be created only once. If it is replaced or lost, Android will reject updates signed with the new key. The earlier CI Debug APKs were signed with temporary runner keys, so moving from one of those APKs to this release key requires one uninstall. Subsequent releases signed with this key install as updates.

## What it does

- Scans NFC-A and NFC-B tags while the app is open.
- Lists Android-reported tag technologies, ISO-DEP support, max transceive size, and the available ISO-DEP historical or higher-layer bytes.
- Provides a manual short-APDU probe. It sends no command automatically and accepts only `SELECT` (`A4`), `READ BINARY` (`B0`, `B1`), `GET DATA` (`CA`), `GET CHALLENGE` (`84`), and `GET RESPONSE` (`C0`) instruction bytes. Commands are not written to storage. `SELECT` and `GET CHALLENGE` can change transient card/session state.
- Keeps the ISO-DEP connection open between taps while the same card remains in the field. This preserves selection state for a follow-up manual command; scanning another card or leaving the page resets it.
- Offers a tap-to-run probe of four known application identifiers (ICAO travel document, NFC Forum Type 4 NDEF, PKCS#15, and a common GlobalPlatform card-manager AID). The probe shows status words and response lengths, never payload bytes. These identifiers are candidates, not a claimed South African ID card profile.
- Displays APDU response bytes and status words on screen. Responses can contain personal information, so do not share screenshots or logs without checking them first.
- Reads the machine-readable-zone data group (DG1) using ICAO 9303 Basic Access Control (BAC). The cardholder enters the document/ID number, date of birth, and expiry date printed on their own card; those values derive the access key, so the chip only unlocks for someone physically holding the card. This is authenticated access, not an authentication bypass. Data read from the chip is shown on screen only and is not saved.
- Reads DG1 using PACE (Password Authenticated Connection Establishment, ICAO 9303 Part 11 / BSI TR-03110) with the Card Access Number (CAN) as the password. The app reads the unauthenticated EF.CardAccess to learn the card's PACE profile, runs the ECDH Generic Mapping exchange, and establishes an AES secure channel. As with BAC, the password is a value printed on the card the holder presents; this is authenticated access, not a bypass. Data is shown on screen only and is not saved.
- Validates the Luhn checksum of a manually entered 13-digit South African ID number and displays the limited fields encoded in the number. This is not an identity check.

The BAC implementation (`Emrtd.cs`, `SecureMessaging.cs`) was verified against the ICAO Doc 9303 Part 11 Appendix D worked example: key derivation, mutual authentication, session-key agreement, and the secure-messaging SELECT/READ BINARY commands all reproduce the specification's test vectors.

The PACE implementation (`Pace.cs`, `AesSecureMessaging.cs`) uses [BouncyCastle](https://www.bouncycastle.org/) for the elliptic-curve arithmetic, AES-CMAC, and ASN.1 parsing. It currently supports the ECDH Generic Mapping variants (`id-PACE-ECDH-GM-AES-CBC-CMAC-128/192/256` and `-3DES-CBC-CBC`) over the standardized NIST and brainpool curves. The protocol flow (generic mapping, ephemeral key agreement, and the mutual authentication-token exchange) was validated with a reference simulation of both card and terminal, and the CAN-based flow has now succeeded against one physical South African Smart ID card. It has not yet been run against a full published test vector. A card that offers only PACE Integrated Mapping or Chip Authentication Mapping will not unlock with this implementation.

### PKCS#15 research mode

A physical card scan has now established that CAN-based PACE works and that EF.DIR advertises a Gemalto PKCS#15 application (`E828BD080F0147656D20503135`). Its ODF references authentication, private-key, public-key, certificate and data-object directories. This is an observed file layout for one card, not a claim about all issuance batches. The app shows the full local scan for the cardholder and offers a separate **PKCS#15 research** page with directory records, certificate extensions, public-key fingerprints, and explicit uncertainty. It never sends a signing, authentication, PIN-verification, or write APDU in research mode.

The research page copies a versioned, redacted JSON report. It omits certificate subjects and serials, names, ID numbers, CAN, data-object values, raw certificates and wire APDUs. Fingerprints and hashed key IDs remain stable across reports so scans can be compared; treat them as linkable pseudonyms. A prior report can be opened for in-app comparison. Reports are kept in memory unless the user copies them. The old raw APDU copy action has been removed; raw wire data and the unredacted PACE screen should still be handled as sensitive.

On the observed card, a one-byte `READ BINARY` of selected PrKDF returned `6982`, the standard “security condition not satisfied” status. PACE/CAN alone therefore does not grant this read. AODF contains two PIN entries and two context-tagged biometric-template entries; their presence does not identify which condition protects PrKDF. Research mode decodes their type tags only and does not read biometric templates, verify PINs, or attempt authentication operations.

The current decoder walks bounded ASN.1 TLVs and extracts PKCS#15 object labels, key IDs, usage/access bits, and referenced file paths, including the context-tagged EC public-key entry. It inspects X.509 key usage, EKU, basic constraints, key identifiers and policy OIDs without confusing policy qualifiers for policies. Opaque data-object EFs are read with adaptive lengths because treating their first bytes as a TLV header truncated the observed default-key-container value. It does not yet decode every optional PKCS#15 attribute, read PuKDF key values, or validate a Home Affairs CA chain. A certificate's presence is not independent authenticity proof. In particular, a `9000` SELECT followed by a failed or empty PrKDF read cannot establish that there are no private keys. A future key comparison must parse the public-key value referenced by PuKDF and compare its canonical SubjectPublicKeyInfo to the matching certificate; directory IDs alone are insufficient.

Synthetic redacted replay fixtures live in `tests/ResearchReplay`. Run them with `dotnet run --project tests/ResearchReplay/ResearchReplay.csproj`. They exercise report import/export and directory parsing without distributing a cardholder's data. A real capture can be compared through the research page, but the redacted export cannot replay cryptographic parsing of the original certificate; that would require a separately consented, carefully scrubbed fixture.

One observed card certificate has policy OID `2.16.840.1.114028.10.2.1`, which also appears in [LAWtrust's certificate-practice statement](https://www.lawtrust.co.za/wp-content/uploads/2023/11/LT_ISP_IS_CPS_LT2048CA2_V009-2023-09-01.pdf). This is a lead for issuer-chain research, not evidence that the card certificate chains to LAWtrust: the issuing CA certificate, signature path and trust anchor still need independent verification.

NFC is optional for installation; the ID-number decoder remains available on devices without NFC.

## Protocol research status

The public South African Government description says the Smart ID chip contains biographic data and fingerprint biometrics, but does not specify the card application identifier, file identifiers, access-control procedure, or data encoding ([Smart ID card overview](https://www.gov.za/about-government/smart-identity-document-id-card-roll-out)). ISO-DEP only establishes the transport used to exchange APDUs. ICAO Doc 9303 defines an LDS for electronic machine-readable travel documents; that does not establish that the South African ID card uses that LDS ([ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303)).

One observed card returned `6999` with no data for both `SELECT` of master-file ID `3F00` and `SELECT` of the ICAO LDS AID. Oracle's Java Card API names `6999` “applet selection failed”, but that does not establish the card's operating system or why selection failed ([Oracle status-word reference](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/framework/ISO7816.html)). A [Government Printing Works annual report](https://nationalgovernment.co.za/entity_annual/153/2014-government-printing-works-annual-report.pdf) names Gemalto as the original supplier of the blank contactless cards. We have not found a public SA Smart ID AID, file map, or access policy. The probe narrows the possibilities without claiming that a rejected AID implies inaccessible data.

The next useful evidence is anonymized captures from a card the researcher owns or is authorized to inspect: tag technologies and ATS/ATTRIB bytes, each command APDU, response status words, and redacted response payloads. Do not publish identity numbers, names, photographs, biometrics, access keys, or unredacted card dumps. No authentication bypass or write command is implemented.

## Launch troubleshooting

The Debug APK uploaded by the original CI workflow crashed on launch when installed by itself. On an Android 35 emulator, logcat reported `No assemblies found ... Assuming this is part of Fast Deployment`. The project sets `EmbedAssembliesIntoApk=true`, and CI now distributes a self-contained Release APK. If a future build still exits, capture the first fatal exception from `adb logcat` (`adb logcat -c`, launch RSAReader, then `adb logcat -d -b crash`), along with the Android version.

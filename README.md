# RSAReader

An Android .NET MAUI reference app for inspecting the NFC interface of South African Smart ID cards. The card application and file layout are not documented publicly enough to assume an eMRTD layout, so this project records the observable ISO-DEP/APDU behavior without pretending the card format is known.

## Build

Install the .NET 9 SDK, MAUI Android workload (`dotnet workload install maui-android`), and Android SDK. Then run:

```sh
dotnet restore RSAReader.csproj
dotnet build RSAReader.csproj -f net9.0-android
```

GitHub Actions builds a Debug APK on pushes and pull requests and uploads it as the `RSAReader-apk` workflow artifact.

## What it does

- Scans NFC-A and NFC-B tags while the app is open.
- Lists Android-reported tag technologies, ISO-DEP support, max transceive size, and the available ISO-DEP historical or higher-layer bytes.
- Provides a manual short-APDU probe. It sends no command automatically and accepts only `SELECT` (`A4`), `READ BINARY` (`B0`, `B1`), `GET DATA` (`CA`), `GET CHALLENGE` (`84`), and `GET RESPONSE` (`C0`) instruction bytes. Commands are not written to storage. `SELECT` and `GET CHALLENGE` can change transient card/session state.
- Displays APDU response bytes and status words on screen. Responses can contain personal information, so do not share screenshots or logs without checking them first.
- Validates the Luhn checksum of a manually entered 13-digit South African ID number and displays the limited fields encoded in the number. This is not an identity check.

NFC is optional for installation; the ID-number decoder remains available on devices without NFC.

## Protocol research status

The public South African Government description says the Smart ID chip contains biographic data and fingerprint biometrics, but does not specify the card application identifier, file identifiers, access-control procedure, or data encoding ([Smart ID card overview](https://www.gov.za/about-government/smart-identity-document-id-card-roll-out)). ISO-DEP only establishes the transport used to exchange APDUs. ICAO Doc 9303 defines an LDS for electronic machine-readable travel documents; that does not establish that the South African ID card uses that LDS ([ICAO Doc 9303](https://www.icao.int/publications/doc-series/doc-9303)).

The next useful evidence is anonymized captures from a card the researcher owns or is authorized to inspect: tag technologies and ATS/ATTRIB bytes, each command APDU, response status words, and redacted response payloads. Do not publish identity numbers, names, photographs, biometrics, access keys, or unredacted card dumps. No authentication bypass or write command is implemented.

## Launch troubleshooting

The Debug APK uploaded by the original CI workflow crashed on launch when installed by itself. On an Android 35 emulator, logcat reported `No assemblies found ... Assuming this is part of Fast Deployment`. The project sets `EmbedAssembliesIntoApk=true` so the uploaded Debug APK contains its managed code and can be installed directly. If a future build still exits, capture the first fatal exception from `adb logcat` (`adb logcat -c`, launch RSAReader, then `adb logcat -d -b crash`), along with the Android version.

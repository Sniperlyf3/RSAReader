# RSAReader

Android .NET MAUI prototype for inspecting the NFC interface exposed by a South African Smart ID card.

## Build

Install the .NET 9 SDK, the MAUI Android workload (`dotnet workload install maui-android`), and the Android SDK. Then run:

```bash
dotnet restore
dotnet build -f net9.0-android
```

GitHub Actions also builds a Debug APK on every push and pull request and uploads it as the `RSAReader-apk` workflow artifact.

## Current capabilities

- Detects NFC-A/NFC-B tags.
- Lists Android-reported NFC technologies.
- Reports whether ISO-DEP is available.
- Validates a manually entered South African ID number with its Luhn checksum.
- Displays information encoded directly in the ID number.

The current version does not attempt to bypass authentication or extract protected biometric data. The next research step is ISO-DEP/APDU protocol characterization using a personally owned test card.

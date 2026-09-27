# LAWtrust trust anchors and certificate validation

LAWtrust (LAW Trusted Third Party Services) operates the PKI behind the South
African smart ID card's on-chip certificate. To turn "a certificate is present on
the chip" into "the certificate was issued by the expected PKI", the app pins
LAWtrust's published CA certificates and builds an **offline** chain against them.

## What is pinned

Downloaded from the public repository at <https://www.lawtrust.co.za/repository/>
and embedded (base64 DER) in `Research/LawTrustAnchors.cs`:

**Roots (custom trust anchors)**

| Root | Subject | Notes |
|---|---|---|
| RootCA01 | `LAWtrust Root Certification Authority 2048` | RSA 2048, self-signed, 2012–2032 |
| RootCA02 | `LAWtrust Root CA2 (4096)` | RSA 4096, self-signed |

**Issuing CAs (chain-building material / ExtraStore)**

AATL CA01, AUTH CA01, AUTH CA02, Secure CA01, Signing CA01, AeSign CA1, AeSign CA2.
All seven verify to one of the two pinned roots.

## Why these

The card certificate's policy OID `2.16.840.1.114028.10.2.1` is on the Entrust arc
(`2.16.840.1.114028`), which LAWtrust uses. On this repository that exact policy OID
appears only on **AeSign CA1**, **AeSign CA2**, and **AATL CA01** — all chaining to
`LAWtrust Root Certification Authority 2048`. The other CAs use LAWtrust's own arc
(`1.3.6.1.4.1.54383.*`). Pinning both roots plus all seven issuing CAs lets any
LAWtrust-issued leaf chain offline, while still reporting which anchor it reached.

## How validation works

`Pkcs15Collector.BuildChainResult` runs an `X509Chain` with:

- `TrustMode = CustomRootTrust` and the two roots in `CustomTrustStore`;
- the seven issuing CAs in `ExtraStore`;
- `DisableCertificateDownloads = true` (no network; deterministic);
- `RevocationMode = NoCheck` (revocation is reported separately, not asserted here);
- `IgnoreNotTimeValid` (so an expired pinned CA still lets the structure be checked).

The result is one of:

- **Verified** — the leaf chains to a pinned LAWtrust root. This confirms the issuing
  PKI and binds the subject (name and ID number) carried in the certificate.
- **Chains to pinned … but chain flagged** — reached a pinned root but a status flag
  was raised.
- **Unverified** — did not chain to a pinned root. The issuing CA may be a LAWtrust
  sub-CA that is not published in the repository; the certificate's **AIA caIssuers**
  URL (now extracted) usually points straight to that issuer certificate.

## What this does and does not prove

- ✅ The on-chip certificate was issued under LAWtrust's PKI.
- ✅ The name and ID number **inside the certificate** are the values LAWtrust bound
  at issuance (subject to revocation).
- ❌ Not revocation: CRL/OCSP endpoints are extracted and reported, not checked here.
- ❌ Not clone detection: a certificate can be copied. Only Chip Authentication /
  PACE-CAM would bind the certificate to this physical chip.
- ❌ Not the portrait or live population-register status: those are DHA data, outside
  LAWtrust's PKI. Validating them needs DHA's own verification channel.

## Regenerating the bundle

```sh
# fetch the .cer files listed on the repository page, normalise to PEM, then:
for f in RootCA01 RootCA02 AATL_CA01 AUTH_CA01 AUTH_CA02 SECURE_CA01 SIGNING_CA01 AESIGN_CA1 AESIGN_CA2; do
  openssl x509 -in "$f.pem" -outform DER | base64 -w0   # paste into Research/LawTrustAnchors.cs
done
```

Only the certificates' presence is trust-bearing; they are public CA certificates,
not secrets. Verify any refresh with `openssl verify -CAfile roots.pem <intermediate>.pem`.

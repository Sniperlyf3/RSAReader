# LAWtrust trust anchors and certificate validation

LAWtrust publishes a CA hierarchy relevant to South African smart ID certificate
research. The app pins selected certificates from that repository and can build an
**offline** chain when the card certificate and every required issuer certificate
are available. A policy OID or matching issuer name alone does not establish that
a card certificate chains to LAWtrust.

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

The card certificate's policy OID `2.16.840.1.114028.10.2.1` also appears on
**AeSign CA1**, **AeSign CA2**, and **AATL CA01** in this repository. That overlap is
a research lead, not proof of a certificate path. The bundle contains two roots
and seven issuing CAs; a card certificate issued by a different intermediate still
needs that intermediate certificate before an offline path can be built.

### Result for the observed card certificates

The trace supplied for the card shows both cardholder certificates naming
`Home Affairs National ID Issuing CA3` as issuer. That issuer certificate is not
among the two roots or seven issuing CAs pinned here. The trace's AIA metadata
exposes an OCSP responder, but no `caIssuers` certificate URL. Therefore the
current bundle cannot validate either certificate's issuer signature or build its
chain. The trace predates the LAWtrust chain checker, and it does not contain a
complete redacted export with a checker result, so there is no on-card `Verified`
result to report. `Unverified` with this bundle means the chain could not be built;
it does not prove the card certificate is invalid or unrelated to LAWtrust.

To complete the check, the DHA CA3 issuer certificate (and any parent certificates
between it and a pinned root) must be obtained from an authoritative source and
added as chain-building material, then the checker must be run against the exact
card certificates. The official [LAWtrust repository](https://www.lawtrust.co.za/repository/)
lists the pinned LAWtrust hierarchy but does not list DHA CA3.

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
- **Unverified** — did not chain to a pinned root. This can mean the issuer or
  another intermediate is missing; it is not by itself proof that the certificate
  is invalid or outside LAWtrust's PKI. Check **AIA caIssuers** when present. The
  observed card certificates expose OCSP but no `caIssuers` URL.

## What this does and does not prove

- ✅ For a result explicitly marked **Verified**, the certificate chains to a
  pinned LAWtrust root under the supplied chain-building material.
- ✅ Such a result supports that the pinned PKI issued the certificate; it does not
  establish live registry status or validate the portrait.
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

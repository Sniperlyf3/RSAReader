#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 KEYSTORE.p12 PASSWORD_FILE" >&2
  exit 2
fi

keystore=$1
password_file=$2
test -s "$keystore"
test -s "$password_file"
command -v gh >/dev/null || { echo "Install and authenticate GitHub CLI first." >&2; exit 1; }
gh auth status >/dev/null

# gh encrypts these values before sending them to repository Actions secrets.
base64 -w0 "$keystore" | gh secret set RSA_READER_KEYSTORE_B64 --repo Sniperlyf3/RSAReader
gh secret set RSA_READER_SIGNING_PASSWORD --repo Sniperlyf3/RSAReader < "$password_file"
echo "Signing secrets stored for Sniperlyf3/RSAReader. Keep a separate backup of both files."

#!/bin/bash
set -euo pipefail
FIXTURES="$RUNNER_TEMP/p12-import-fixtures"
mkdir -p "$FIXTURES"
chmod 700 "$FIXTURES"
OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -keyout "$FIXTURES/key.pem" -out "$FIXTURES/cert.pem" -subj '/CN=Synthetic P12 Test/OU=TESTTEAM01' -days 2 2>/dev/null
"$OPENSSL" pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -in "$FIXTURES/cert.pem" -inkey "$FIXTURES/key.pem" -out "$FIXTURES/valid.p12" -passout pass:test-password
"$OPENSSL" pkcs12 -export -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -in "$FIXTURES/cert.pem" -inkey "$FIXTURES/key.pem" -out "$FIXTURES/empty.pfx" -passout pass:
"$OPENSSL" pkcs12 -export -legacy -nokeys -in "$FIXTURES/cert.pem" -out "$FIXTURES/cert-only.p12" -passout pass:test-password
"$OPENSSL" x509 -in "$FIXTURES/cert.pem" -outform DER -out "$FIXTURES/cert.der"
swiftc ios-app/P12Importer.swift ios-app/SigningKeychain.swift tests/main.swift -o "$FIXTURES/test-import"
"$FIXTURES/test-import" "$FIXTURES"
rm -rf "$FIXTURES"

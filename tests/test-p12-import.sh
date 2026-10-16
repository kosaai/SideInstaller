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
# Exercise Security.framework on iOS, not the different macOS PKCS12 parser.
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
xcrun swiftc -swift-version 5 -sdk "$SDK" -target arm64-apple-ios17.4-simulator ios-app/P12Importer.swift ios-app/SigningKeychain.swift tests/main.swift -o "$FIXTURES/test-import"
codesign --force --sign - "$FIXTURES/test-import"
DEVICE=$(xcrun simctl list devices available -j | python3 -c 'import sys,json; ds=[d for group in json.load(sys.stdin)["devices"].values() for d in group if d.get("isAvailable") and "iPhone" in d["name"]]; print(next((d["udid"] for d in ds if d["state"] == "Booted"), ds[0]["udid"]))')
xcrun simctl bootstatus "$DEVICE" -b
xcrun simctl spawn "$DEVICE" "$FIXTURES/test-import" "$FIXTURES"
rm -rf "$FIXTURES"

# Imported provisioning profiles

Tools → Certificates exposes **Import P12 / PFX** and **Import Provisioning
Profile**. The latter uses Files with multiple selection. Well-formed profiles
remain visible locally even when expired, missing this device, or mismatched to
the imported certificate; their exact validation error is shown and signing is
blocked. No device UDID is guessed: pairing/connection supplies it.

The Rust parser verifies the CMS payload digest and RSA signature, follows the
embedded issuer chain to the bundled Apple Root CA, parses the enclosed plist,
and checks required fields/types, UUID, team/application identifier consistency,
dates, devices, and developer certificate DER. Local raw `.mobileprovision`
files and a UUID index live in private Application Support, not the Keychain.
The public certificate DER of the imported P12 is retained locally for offline
status checks; its private key continues to use the existing Keychain bridge.
No profile import/removal operation accepts a developer session or calls Apple.

Before portal mutation the signer discovers the main app and recursively nested
extensions and validates the complete imported-target plan. Exact Bundle IDs
take priority over authorized wildcard profiles. Original IDs are kept when
imported profiles address them; otherwise the existing team-suffixed IDs are
used. Multiple renewals are ordered by validity/expiration. An invalid imported
match blocks signing, rather than silently generating a replacement profile.
Only missing targets enter the existing Apple registration/profile flow. Each
target embeds its own profile and gets its own entitlements; the main profile is
never copied into an extension.

The original Mach-O's XML entitlements are read before signatures are removed
(including fat binaries). Unsupported DER-only or malformed entitlements fail
closed. Identity fields are bound to the selected profile/team and standard
keychain identity groups are rebound to the new app identifier. Requested
capabilities, including app groups, push, iCloud and other developer keys, must
be allowed by the profile. Profile entitlements are the signing basis. The
increased-memory option and LiveContainer shared keychain groups are also
validated; no ungranted entitlement is added to an imported-profile signature.

## Automated checks

`cargo test --locked -p isideload --lib` includes tests for valid fields, signed
CMS parsing, modified/truncated/untrusted CMS, expiration, team mismatch, missing
device/unknown UDID, exact DER mismatch with identical certificate subject,
Main + Extension mapping, multiple imports/renewals, UUID persistence/removal,
automatic Bundle ID matching, imported-target priority, partial/empty fallback,
invalid-import blocking, entitlement mismatch/wildcard arrays, malformed Mach-O,
and the existing five P12 identity/Keychain-storage regressions.

`bash tests/test-p12-import.sh` retains the existing six native iOS Simulator
PKCS12/Keychain tests. CI also runs Swift syntax lint, iOS Swift typecheck,
Rust clippy, the Rust release build, and both iOS application/LiveActivity builds.
All fixtures are synthetic and generated at runtime; no real profile, P12,
private key or password is committed.

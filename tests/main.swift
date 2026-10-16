import Foundation
import Security

setbuf(stdout, nil)

func require(_ condition: @autoclosure () -> Bool, _ name: String) {
    guard condition() else { fatalError("FAIL: " + name) }
    print("PASS: " + name)
}
func expectError(_ expected: P12Importer.ImportError, _ name: String, _ work: () throws -> Void) {
    do { try work(); fatalError("FAIL: " + name + " did not reject input") }
    catch let error as P12Importer.ImportError {
        require(error.errorDescription == expected.errorDescription, name)
    } catch { fatalError("Unexpected error in " + name) }
}
let root = URL(fileURLWithPath: CommandLine.arguments[1])
// Only synthetic fixtures: record platform status to diagnose cross-version
// Security.framework differences without logging any archive/key/password.
for (name, password) in [("valid.p12", "test-password"), ("empty.pfx", ""), ("cert-only.p12", "test-password")] {
    let bytes = try Data(contentsOf: root.appendingPathComponent(name))
    var result: CFArray?
    let status = SecPKCS12Import(bytes as CFData, [kSecImportExportPassphrase: password] as CFDictionary, &result)
    print("Native fixture status:", name, status)
}
var valid = try P12Importer.decode(Data(contentsOf: root.appendingPathComponent("valid.p12")), password: "test-password")
require(!valid.certificate.isEmpty && !valid.privateKey.isEmpty, "valid P12 includes certificate and private key")
require(valid.sha1.count == 40 && valid.sha256.count == 64, "certificate fingerprints")
var empty = try P12Importer.decode(Data(contentsOf: root.appendingPathComponent("empty.pfx")), password: "")
require(!empty.privateKey.isEmpty, "empty-password PFX")
expectError(.password, "wrong password") {
    _ = try P12Importer.decode(Data(contentsOf: root.appendingPathComponent("valid.p12")), password: "wrong")
}
expectError(.missingKey, "P12 without private key") {
    _ = try P12Importer.decode(Data(contentsOf: root.appendingPathComponent("cert-only.p12")), password: "test-password")
}
let cert = SecCertificateCreateWithData(nil, valid.certificate as CFData)!
var error: Unmanaged<CFError>?
let otherKey = SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, &error)!
expectError(.mismatch, "certificate/private-key mismatch") {
    try P12Importer.validatePair(certificate: cert, key: otherKey)
}
valid.clearKey(); empty.clearKey()
print("All native PKCS12 import tests passed")

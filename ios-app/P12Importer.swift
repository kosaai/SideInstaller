import Foundation
import Security
import CryptoKit

/// PKCS#12 decoding is delegated to Apple's Security.framework. No P12 or
/// password is persisted; the key is exported only in memory for the existing
/// RSA-based Rust signer, then stored through the Keychain-backed abstraction.
enum P12Importer {
    enum ImportError: LocalizedError {
        case password, missingKey, invalid, mismatch, unsupportedKey, expired
        var errorDescription: String? {
            switch self {
            case .password: return "Incorrect P12 password."
            case .missingKey: return "The selected P12 does not contain the private key required for signing."
            case .invalid: return "The selected file is not a valid P12/PFX signing identity."
            case .mismatch: return "The private key does not match the selected certificate."
            case .unsupportedKey: return "This signing engine requires an RSA development certificate."
            case .expired: return "The selected certificate has expired."
            }
        }
    }

    struct ImportedIdentity {
        let certificate: Data
        var privateKey: Data
        let commonName: String
        let sha1: String
        let sha256: String
        mutating func clearKey() { privateKey.resetBytes(in: 0..<privateKey.count) }
    }

    static func decode(_ data: Data, password: String) throws -> ImportedIdentity {
        var options: [String: Any] = [kSecImportExportPassphrase as String: password]
        #if os(macOS)
        // Tests must not leave fixture keys in the runner's login Keychain.
        if #available(macOS 15.0, *) { options[kSecImportToMemoryOnly as String] = true }
        #endif
        var result: CFArray?
        let status = SecPKCS12Import(data as CFData, options as CFDictionary, &result)
        if status == errSecAuthFailed { throw ImportError.password }
        guard status == errSecSuccess else { throw ImportError.invalid }
        let items = result as? [[String: Any]] ?? []
        let identities = items.compactMap { $0[kSecImportItemIdentity as String] }
        guard !identities.isEmpty else { throw ImportError.missingKey }
        // Never silently choose a different identity from a multi-key archive.
        guard identities.count == 1, CFGetTypeID(identities[0] as CFTypeRef) == SecIdentityGetTypeID() else {
            throw ImportError.invalid
        }
        let identity = identities[0] as! SecIdentity
        var certificate: SecCertificate?
        var key: SecKey?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
            throw ImportError.invalid
        }
        guard SecIdentityCopyPrivateKey(identity, &key) == errSecSuccess, let key else {
            throw ImportError.missingKey
        }
        try validatePair(certificate: certificate, key: key)
        var error: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(key, &error) else {
            throw ImportError.missingKey
        }
        let certData = SecCertificateCopyData(certificate) as Data
        var name: CFString?
        SecCertificateCopyCommonName(certificate, &name)
        return ImportedIdentity(certificate: certData, privateKey: external as Data,
            commonName: (name as String?) ?? "Signing certificate",
            sha1: Insecure.SHA1.hash(data: certData).map { String(format: "%02X", $0) }.joined(),
            sha256: SHA256.hash(data: certData).map { String(format: "%02X", $0) }.joined())
    }

    static func validatePair(certificate: SecCertificate, key: SecKey) throws {
        guard let publicKey = SecCertificateCopyKey(certificate),
              SecKeyIsAlgorithmSupported(key, .sign, .rsaSignatureMessagePKCS1v15SHA256) else {
            throw ImportError.unsupportedKey
        }
        let challenge = Data(UUID().uuidString.utf8)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, challenge as CFData, &error),
              SecKeyVerifySignature(publicKey, .rsaSignatureMessagePKCS1v15SHA256, challenge as CFData, signature, &error) else {
            throw ImportError.mismatch
        }
    }
}

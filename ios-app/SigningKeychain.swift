import Foundation
import Security

/// The Rust signing engine still uses its existing <Apple-ID hash>/key slot.
/// Only its backing store changes: device-only Keychain, never Documents.
enum SigningKeychain {
    static let service = "SideInstaller.SigningPrivateKey"

    private static func query(_ name: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: name,
         kSecAttrSynchronizable as String: false]
    }

    // Called synchronously from Rust background queues. No Swift actor hops,
    // no persistent references across FFI, and no secret strings in diagnostics.
    static func read(_ name: UnsafePointer<CChar>?, _ output: UnsafeMutablePointer<UInt8>?,
                     _ capacity: Int, _ length: UnsafeMutablePointer<Int>?) -> Int32 {
        guard let name, let output, let length else { return -1 }
        var request = query(String(cString: name))
        request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(request as CFDictionary, &result)
        if status == errSecItemNotFound { length.pointee = 0; return 1 }
        guard status == errSecSuccess, var bytes = result as? Data,
              bytes.count <= capacity else { return -1 }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        length.pointee = bytes.count
        bytes.copyBytes(to: output, count: bytes.count)
        return 0
    }

    static func write(_ name: UnsafePointer<CChar>?, _ input: UnsafePointer<UInt8>?, _ length: Int) -> Int32 {
        guard let name else { return -1 }
        let request = query(String(cString: name))
        if length == 0 {
            let status = SecItemDelete(request as CFDictionary)
            return status == errSecSuccess || status == errSecItemNotFound ? 0 : -1
        }
        guard let input, length > 0, length <= 16384 else { return -1 }
        var bytes = Data(bytes: input, count: length)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let attributes: [String: Any] = [
            kSecValueData as String: bytes,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var addition = request
        attributes.forEach { addition[$0.key] = $0.value }
        var status = SecItemAdd(addition as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(request as CFDictionary, attributes as CFDictionary)
        }
        return status == errSecSuccess ? 0 : -1
    }
}

import Foundation
import SideInstallerFFI

struct ImportedProvisioningProfile: Decodable, Identifiable {
    let name: String
    let uuid: String
    let teamID: String
    let bundleID: String
    let applicationIdentifier: String
    let creation: String
    let expiration: String
    let deviceValid: Bool
    let certificateMatch: Bool
    let ready: Bool
    let issues: [String]
    var id: String { uuid }
    var expiresAt: Date? { ISO8601DateFormatter().date(from: expiration) }
    enum CodingKeys: String, CodingKey {
        case name, uuid, creation, expiration, ready, issues
        case teamID = "team_id", bundleID = "bundle_id", applicationIdentifier = "application_identifier"
        case deviceValid = "device_valid", certificateMatch = "certificate_match"
    }
}

/// Raw mobileprovision files stay in private Application Support, outside the
/// signing-key Keychain. All parsing and file operations run off the UI thread.
final class ImportedProfilesManager: ObservableObject {
    @Published private(set) var profiles: [ImportedProvisioningProfile] = []
    @Published private(set) var isWorking = false
    @Published var lastError: String?
    @Published var showImporter = false
    private let queue = DispatchQueue(label: "sideinstaller.profiles")

    @MainActor
    func refresh() { perform(action: "list") }

    @MainActor
    func remove(_ profile: ImportedProvisioningProfile) { perform(action: "remove", uuid: profile.uuid) }

    @MainActor
    func importFiles(_ urls: [URL]) {
        guard !isWorking, !Engine.shared.isRunning else { return }
        isWorking = true
        let email = Engine.shared.normalizedAppleID
        let udid = Engine.shared.deviceUDID ?? ""
        queue.async {
            var errors: [String] = []
            for url in urls {
                do {
                    guard url.pathExtension.lowercased() == "mobileprovision" else {
                        throw EngineError.message("Select a .mobileprovision file.")
                    }
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
                    guard size > 0, size <= 4 * 1024 * 1024 else { throw EngineError.message("Invalid provisioning profile file size.") }
                    let data = try Data(contentsOf: url)
                    _ = try self.call(action: "import", email: email, udid: udid, data: data)
                } catch { errors.append("\(url.lastPathComponent): \(error.localizedDescription)") }
            }
            do {
                let items = try self.call(action: "list", email: email, udid: udid)
                // Keep well-formed profiles visible even when not ready. The
                // signer independently revalidates them and blocks their use.
                let issues = items.flatMap(\.issues)
                let message = Array(Set(errors + issues)).sorted().joined(separator: "\n")
                DispatchQueue.main.async {
                    self.profiles = items
                    self.lastError = message.isEmpty ? nil : message
                    self.isWorking = false
                }
            } catch {
                DispatchQueue.main.async { self.lastError = error.localizedDescription; self.isWorking = false }
            }
        }
    }

    @MainActor
    private func perform(action: String, uuid: String = "") {
        guard !isWorking, !Engine.shared.isRunning else { return }
        isWorking = true
        let email = Engine.shared.normalizedAppleID
        let udid = Engine.shared.deviceUDID ?? ""
        queue.async {
            do {
                let items = try self.call(action: action, email: email, udid: udid, uuid: uuid)
                DispatchQueue.main.async { self.profiles = items; self.isWorking = false }
            } catch {
                DispatchQueue.main.async { self.lastError = error.localizedDescription; self.isWorking = false }
            }
        }
    }

    private func call(action: String, email: String, udid: String, uuid: String = "", data: Data = Data()) throws -> [ImportedProvisioningProfile] {
        var json: UnsafeMutablePointer<CChar>?
        var error: UnsafeMutablePointer<CChar>?
        let rc = data.withUnsafeBytes { bytes in
            si_profiles(PrivateStore.isideload.path, email, udid, action, uuid,
                        bytes.bindMemory(to: UInt8.self).baseAddress, bytes.count, &json, &error)
        }
        defer { json.map { si_string_free($0) }; error.map { si_string_free($0) } }
        guard rc == 0 else { throw EngineError.message(error.map { String(cString: $0) } ?? "Could not process provisioning profiles.") }
        return try JSONDecoder().decode([ImportedProvisioningProfile].self, from: Data((json.map { String(cString: $0) } ?? "[]").utf8))
    }
}

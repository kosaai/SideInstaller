import SwiftUI
import UniformTypeIdentifiers

struct ImportedProfilesView: View {
    @ObservedObject var manager: ImportedProfilesManager
    let disabled: Bool
    @State private var pendingRemoval: ImportedProvisioningProfile?

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Imported Provisioning Profiles").font(.headline)
            Text("Profiles stay on this device. Each app and extension uses its own matching profile. Entitlements are checked against the selected IPA before signing.")
                .font(.caption).foregroundStyle(.secondary)
            if manager.profiles.isEmpty {
                Text("No imported profiles. Apple provisioning remains available when no matching profile is imported.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            ForEach(manager.profiles) { profile in
                PanelCard {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(profile.name).font(.subheadline.weight(.semibold))
                        Text("Bundle ID: \(profile.bundleID)").textSelection(.enabled)
                        Text("Team ID: \(profile.teamID)")
                        if let date = profile.expiresAt {
                            Text("Expires: \(date.formatted(date: .abbreviated, time: .shortened))")
                        } else { Text("Expires: \(profile.expiration)") }
                        Text("Device: \(profile.deviceValid ? "Valid" : "Missing")")
                        Text("Certificate: \(profile.certificateMatch ? "Match" : "Mismatch")")
                        Text("Ready: \(profile.ready ? "✅" : "❌")")
                            .foregroundStyle(profile.ready ? .green : .orange)
                        ForEach(profile.issues, id: \.self) { issue in
                            Text(issue).foregroundStyle(.orange)
                        }
                        DisclosureGroup("Profile details") {
                            Text("UUID: \(profile.uuid)").textSelection(.enabled)
                            Text("Created: \(profile.creation)")
                            Button("Remove Local Profile", role: .destructive) { pendingRemoval = profile }
                                .buttonStyle(.bordered).disabled(disabled || manager.isWorking)
                        }
                    }
                    .font(.caption)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
        }
        .fileImporter(isPresented: $manager.showImporter,
                      allowedContentTypes: [UTType(filenameExtension: "mobileprovision") ?? .data],
                      allowsMultipleSelection: true) { result in
            switch result {
            case .success(let urls): manager.importFiles(urls)
            case .failure(let error):
                if (error as NSError).code != NSUserCancelledError { manager.lastError = "Could not open provisioning profiles." }
            }
        }
        .alert("Remove Local Profile?", isPresented: Binding(
            get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })) {
                Button("Remove Local Profile", role: .destructive) {
                    if let profile = pendingRemoval { manager.remove(profile) }
                    pendingRemoval = nil
                }
                Button("Cancel", role: .cancel) { pendingRemoval = nil }
            } message: { Text("This deletes only the local file. It does not change any App ID, certificate, or profile on Apple.") }
    }
}

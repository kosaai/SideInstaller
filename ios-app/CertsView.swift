import SwiftUI

/// Existing Apple certificates and their local signing-key availability.
struct CertsView: View {
    /// Observed so labels redraw when the language changes.
    @EnvironmentObject private var loc: Localizer
    @ObservedObject var manager: CertManager

    @State private var showSettings = false
    @State private var pendingRemoval: DevCert?

    var body: some View {
        ScrollView {
            VStack(spacing: 18) {
                header.cascadeItem(0)
                Button { manager.showP12Importer = true } label: {
                    Label("Import P12 / PFX", systemImage: "square.and.arrow.down")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(manager.isWorking || Engine.shared.isRunning)
                loadButton.cascadeItem(1)
                if let summary = manager.importSummary {
                    PanelCard {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Certificate imported", systemImage: "checkmark.seal.fill")
                                .foregroundStyle(.green)
                            Text(summary).font(.caption).textSelection(.enabled)
                        }
                    }
                }
                // Errors show as a popup, which `RootView` lays over the app.
                certList
            }
            .padding(20)
            .animation(.smooth(duration: 0.35), value: manager.certs)
            .animation(.smooth(duration: 0.3), value: manager.isWorking)
            .animation(.smooth(duration: 0.35), value: manager.teamSummary)
        }
        .background(AppBackground())
        .toolbar { settingsToolbarItem(isPresented: $showSettings) }
        .sheet(isPresented: $showSettings) { SettingsView() }
        .onAppear { manager.autoLoad() }
        .alert("Remove Local Key?", isPresented: Binding(
            get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } })) {
                Button("Remove Local Key", role: .destructive) {
                    if let cert = pendingRemoval { manager.removeLocalKey(cert) }
                    pendingRemoval = nil
                }
                Button("Cancel", role: .cancel) { pendingRemoval = nil }
            } message: {
                Text("This removes only the private key stored on this device. The certificate on Apple and apps already signed with it are not revoked. You can import its P12/PFX again.")
            }
    }

    // MARK: Header

    private var header: some View {
        BrandHeader(icon: "checkmark.seal.fill", image: "CertsLogo", title: L("Certificates")) {
            if let team = manager.teamSummary {
                StatusPill(text: team, systemImage: "person.2.fill", color: .green)
                    .transition(.opacity.combined(with: .scale(scale: 0.85, anchor: .top)))
            }
        }
    }

    // MARK: Primary action

    private var loadButton: some View {
        Button {
            manager.loadCerts()
        } label: {
            HStack(spacing: 10) {
                if manager.isWorking {
                    ProgressView().tint(.white)
                    Text(manager.isSignedIn ? L("Refreshing") : L("Signing in"))
                } else {
                    Image(systemName: manager.hasLoaded ? "arrow.clockwise" : "list.bullet.rectangle.fill")
                        .contentTransition(.symbolEffect(.replace))
                    Text(manager.hasLoaded ? L("Refresh") : L("Load certificates"))
                }
            }
        }
        .buttonStyle(PrimaryButtonStyle())
        .disabled(manager.isWorking || manager.revokingID != nil)
    }

    // MARK: Certificate list

    @ViewBuilder
    private var certList: some View {
        if manager.hasLoaded && manager.certs.isEmpty && !manager.isWorking {
            emptyState.transition(.cardAppear)
        } else if !manager.certs.isEmpty {
            VStack(spacing: 14) {
                HStack {
                    // Count only; Apple doesn't report the account's limit.
                    Text(L("%d certificate(s)", manager.certs.count))
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                .cascadeItem(2)
                ForEach(Array(manager.certs.enumerated()), id: \.element.id) { idx, cert in
                    certRow(cert).cascadeItem(3 + idx)
                }
            }
        }
    }

    private var emptyState: some View {
        PanelCard {
            VStack(spacing: 8) {
                Image(systemName: "checkmark.seal")
                    .font(.largeTitle)
                    .foregroundStyle(Theme.brand)
                Text(L("No certificates"))
                    .font(.headline)
                Text(L("This Apple ID has no development certificates."))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    private func certRow(_ cert: DevCert) -> some View {
        let ready = cert.hasPrivateKey && !cert.isExpired
        return PanelCard {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "seal.fill")
                        .font(.title3)
                        .foregroundStyle(cert.isExpired ? Theme.gradient(.orange) : Theme.brand)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(cert.displayName)
                            .font(.subheadline.weight(.semibold))
                        if let machine = cert.machineLabel {
                            Label(machine, systemImage: "desktopcomputer")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if cert.isExpired {
                        Text(L("Expired"))
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(.orange)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4)
                            .background(Capsule().fill(Color.orange.opacity(0.16)))
                    }
                }

                if cert.expiresAt != nil || !cert.serialNumber.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        if let expiry = cert.expiresAt {
                            Label(L("Expires %@", expiry.formatted(
                                       Date.FormatStyle(date: .abbreviated, time: .omitted)
                                           .locale(Localizer.locale))),
                                  systemImage: "calendar")
                        }
                        if !cert.serialNumber.isEmpty {
                            Label(cert.serialNumber, systemImage: "number")
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Label("Apple Certificate: Found", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Label(cert.hasPrivateKey ? "Private Key: Available" : "Private Key: Missing",
                          systemImage: cert.hasPrivateKey ? "key.fill" : "key.slash")
                    Label(ready ? "Ready for signing" : "Signing: Not Ready",
                          systemImage: ready ? "checkmark.seal.fill" : "exclamationmark.circle")
                        .foregroundStyle(ready ? .green : .orange)
                }
                .font(.caption)
                if cert.hasPrivateKey {
                    DisclosureGroup("Certificate details") {
                        Button("Remove Local Key", role: .destructive) { pendingRemoval = cert }
                            .font(.caption)
                            .buttonStyle(.bordered)
                            .padding(.top, 8)
                            .disabled(manager.isWorking || Engine.shared.isRunning)
                    }
                    .font(.caption)
                }
            }
        }
    }
}

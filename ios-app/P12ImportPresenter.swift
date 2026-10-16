import SwiftUI
import UniformTypeIdentifiers

/// One picker/password dialog shared by Tools and the error-7460 action.
struct P12ImportPresenter: ViewModifier {
    @ObservedObject var manager: CertManager
    @State private var selectedURL: URL?
    @State private var password = ""
    @State private var askPassword = false

    func body(content: Content) -> some View {
        content
            .fileImporter(isPresented: $manager.showP12Importer,
                          allowedContentTypes: [UTType(filenameExtension: "p12") ?? .data,
                                                UTType(filenameExtension: "pfx") ?? .data],
                          allowsMultipleSelection: false) { result in
                switch result {
                case .success(let urls):
                    guard let url = urls.first else { return }
                    guard ["p12", "pfx"].contains(url.pathExtension.lowercased()) else {
                        manager.lastError = "Select a .p12 or .pfx certificate file."
                        return
                    }
                    selectedURL = url
                    password = ""
                    DispatchQueue.main.async { askPassword = true }
                case .failure(let error):
                    if (error as NSError).code != NSUserCancelledError {
                        manager.lastError = "Could not open the certificate file."
                    }
                }
            }
            .alert("P12 / PFX Password", isPresented: $askPassword) {
                SecureField("Password (may be empty)", text: $password)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("Import") {
                    guard let url = selectedURL else { password = ""; return }
                    manager.importP12(from: url, password: password)
                    password = ""
                    selectedURL = nil
                }
                Button("Cancel", role: .cancel) { password = ""; selectedURL = nil }
            } message: {
                Text("Enter the certificate's password, or leave it empty if the file has no password. The password is not saved.")
            }
    }
}

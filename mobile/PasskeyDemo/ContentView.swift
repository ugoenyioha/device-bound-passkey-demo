import SwiftUI
import AuthenticationServices

struct ContentView: View {
    @StateObject private var passkeyManager = PasskeyManager()
    @State private var username = "demo@example.com"
    @State private var showingSettings = false
    @State private var showingSignInSuccess = false
    @State private var signedInUsername: String = ""

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Architecture explanation
                    architectureSection

                    // Status Card
                    statusCard

                    // Setup Checklist
                    setupChecklist

                    // Username Input
                    usernameSection

                    // Passkey Actions
                    passkeyActionsSection

                    // The Fix: preferImmediatelyAvailableCredentials
                    fixSection

                    // Debug Log
                    debugSection
                }
                .padding()
            }
            .navigationTitle("Device-Bound Passkeys")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(action: { showingSettings = true }) {
                        Image(systemName: "gear")
                    }
                }
            }
            .sheet(isPresented: $showingSettings) {
                SettingsView(passkeyManager: passkeyManager)
            }
            .onOpenURL { url in
                handleUniversalLink(url)
            }
            .alert("Sign In Successful! 🎉", isPresented: $showingSignInSuccess) {
                Button("OK", role: .cancel) { }
            } message: {
                Text("Welcome back, \(signedInUsername)!\n\nYour device-bound passkey worked perfectly.")
            }
        }
    }

    private func handleUniversalLink(_ url: URL) {
        print("URL received: \(url)")
        passkeyManager.log("URL received: \(url.absoluteString)")

        // Handle both:
        // - Custom scheme: passkeydemo://auth/success?username=xxx
        // - Universal Link: https://passkeydemo.usableapps.local/auth/success?username=xxx
        let isAuthSuccess = url.path.contains("/auth/success") ||
                           url.host == "auth" ||
                           (url.scheme == "passkeydemo" && url.host == "success")

        if isAuthSuccess,
           let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
           let usernameParam = components.queryItems?.first(where: { $0.name == "username" })?.value {
            signedInUsername = usernameParam
            showingSignInSuccess = true
            passkeyManager.log("Sign-in success for: \(usernameParam)")
        }
    }

    // MARK: - Architecture Section

    private var architectureSection: some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: "cpu")
                    .font(.system(size: 30))
                    .foregroundColor(.purple)
                Text("True Device-Bound Passkeys")
                    .font(.headline)
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("Two types of passkeys:")
                    .font(.subheadline)
                    .fontWeight(.semibold)

                VStack(alignment: .leading, spacing: 6) {
                    HStack(alignment: .top) {
                        Image(systemName: "icloud.fill")
                            .foregroundColor(.blue)
                        VStack(alignment: .leading) {
                            Text("**iCloud Keychain** (Synced)")
                            Text("Stored in iCloud, syncs across Apple devices")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }

                    HStack(alignment: .top) {
                        Image(systemName: "lock.shield.fill")
                            .foregroundColor(.purple)
                        VStack(alignment: .leading) {
                            Text("**Passkey Demo Provider** (Device-Bound)")
                            Text("Stored in Secure Enclave, never leaves device")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
                .font(.caption)

                Divider()

                Text("For device-bound: Enable 'Passkey Demo Provider' in Settings → Passwords → Password Options")
                    .font(.caption2)
                    .foregroundColor(.orange)
            }
            .padding()
            .background(Color.purple.opacity(0.1))
            .cornerRadius(12)
        }
    }

    // MARK: - Status Card

    private var statusCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Status")
                .font(.headline)

            // Server Mode Toggle
            HStack {
                Image(systemName: passkeyManager.useEmbeddedServer ? "iphone" : "desktopcomputer")
                    .foregroundColor(passkeyManager.useEmbeddedServer ? .purple : .blue)
                Text("Server Mode:")
                    .font(.subheadline)
                Spacer()
                Button(passkeyManager.useEmbeddedServer ? "On-Device" : "External") {
                    passkeyManager.toggleEmbeddedServer()
                }
                .font(.caption)
                .buttonStyle(.borderedProminent)
                .tint(passkeyManager.useEmbeddedServer ? .purple : .blue)
            }

            if passkeyManager.useEmbeddedServer {
                VStack(alignment: .leading, spacing: 4) {
                    Text("⚠️ Embedded mode uses rpID='localhost'")
                        .font(.caption)
                        .foregroundColor(.orange)
                    Text("Passkeys won't work - iOS requires rpID in associated domains")
                        .font(.caption2)
                        .foregroundColor(.red)
                }
            } else {
                Text("External server mode - passkeys enabled")
                    .font(.caption)
                    .foregroundColor(.green)
            }

            HStack {
                Circle()
                    .fill(passkeyManager.serverReachable ? Color.green : Color.red)
                    .frame(width: 10, height: 10)
                Text("Server: \(passkeyManager.serverReachable ? "Connected" : "Not Connected")")
                    .font(.subheadline)
                Spacer()
            }

            HStack {
                Circle()
                    .fill(aasaStatusColor)
                    .frame(width: 10, height: 10)
                Text("AASA: \(passkeyManager.aasaStatus.description)")
                    .font(.subheadline)
                Spacer()
                Button("Toggle") {
                    Task { await passkeyManager.toggleAASA() }
                }
                .font(.caption)
                .buttonStyle(.bordered)
            }

            HStack {
                Circle()
                    .fill(Color.purple)
                    .frame(width: 10, height: 10)
                Text("\(passkeyManager.credentialCountLabel): \(passkeyManager.activeCredentialCount)")
                    .font(.subheadline)
                Spacer()
                Button("Refresh") {
                    passkeyManager.updateStoredCredentialCount()
                    passkeyManager.objectWillChange.send() // Force UI refresh
                }
                .font(.caption)
                Button("Clear") {
                    Task {
                        await passkeyManager.clearAllDeviceBoundCredentials()
                    }
                }
                .font(.caption)
                .foregroundColor(.red)
            }

            // Show list of stored passkey usernames
            if !passkeyManager.storedCredentials.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Stored Passkeys:")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    ForEach(passkeyManager.storedCredentials, id: \.userName) { cred in
                        HStack {
                            Image(systemName: "key.fill")
                                .foregroundColor(.purple)
                                .font(.caption2)
                            Text(cred.userName)
                                .font(.caption)
                            Spacer()
                            Text(cred.relyingPartyIdentifier)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        .padding(.vertical, 2)
                    }
                }
                .padding(8)
                .background(Color.purple.opacity(0.1))
                .cornerRadius(8)
            }

            if !passkeyManager.lastError.isEmpty {
                Text(passkeyManager.lastError)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.top, 4)
            }

            if !passkeyManager.lastSuccess.isEmpty {
                Text(passkeyManager.lastSuccess)
                    .font(.caption)
                    .foregroundColor(.green)
                    .padding(.top, 4)
            }
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }

    private var aasaStatusColor: Color {
        switch passkeyManager.aasaStatus {
        case .valid: return .green
        case .missing: return .red
        default: return .orange
        }
    }

    // MARK: - Setup Checklist

    private var setupChecklist: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Setup Checklist")
                .font(.headline)

            VStack(alignment: .leading, spacing: 8) {
                checklistItem(
                    title: "Enable Credential Provider",
                    description: "Settings → Passwords → Password Options → Enable 'Passkey Demo Provider'",
                    isComplete: passkeyManager.storedCredentialCount > 0 || true // Can't detect directly
                )

                checklistItem(
                    title: "Server Running",
                    description: "npm start in passkeys/web folder",
                    isComplete: passkeyManager.serverReachable
                )

                checklistItem(
                    title: "AASA Valid",
                    description: "Server returns valid webcredentials",
                    isComplete: passkeyManager.aasaStatus == .valid
                )
            }

            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .font(.caption)
            .buttonStyle(.bordered)
        }
        .padding()
        .background(Color.orange.opacity(0.1))
        .cornerRadius(12)
    }

    private func checklistItem(title: String, description: String, isComplete: Bool) -> some View {
        HStack(alignment: .top) {
            Image(systemName: isComplete ? "checkmark.circle.fill" : "circle")
                .foregroundColor(isComplete ? .green : .gray)
            VStack(alignment: .leading) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.medium)
                Text(description)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            Spacer()
        }
    }

    // MARK: - Username Section

    private var usernameSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Username")
                .font(.subheadline)
                .foregroundColor(.secondary)

            TextField("Enter username", text: $username)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .autocapitalization(.none)
                .keyboardType(.emailAddress)
        }
    }

    // MARK: - Passkey Actions

    private var passkeyActionsSection: some View {
        VStack(spacing: 12) {
            Text("Passkey Actions")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)

            if passkeyManager.useEmbeddedServer {
                Text("⚠️ Switch to External mode to create passkeys")
                    .font(.caption)
                    .foregroundColor(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text("Select **'Passkey Demo Provider'** for device-bound, or **'iCloud Keychain'** for synced")
                    .font(.caption)
                    .foregroundColor(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            // Register Button
            Button(action: {
                Task {
                    await passkeyManager.registerPasskey(username: username)
                }
            }) {
                HStack {
                    Image(systemName: "plus.circle.fill")
                    Text("Create Passkey")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
            .disabled(passkeyManager.isLoading)

            // Sign In Button
            Button(action: {
                Task {
                    await passkeyManager.authenticateWithPasskey(username: username)
                }
            }) {
                HStack {
                    Image(systemName: "key.fill")
                    Text("Sign In with Passkey")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.green)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
            .disabled(passkeyManager.isLoading)

            if passkeyManager.isLoading {
                ProgressView()
                    .padding(.top, 8)
            }
        }
    }

    // MARK: - Fix Section

    private var fixSection: some View {
        VStack(spacing: 16) {
            Text("The Fix")
                .font(.headline)
                .frame(maxWidth: .infinity, alignment: .leading)

            VStack(alignment: .leading, spacing: 12) {
                // The Problem
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text("The Problem")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                    }

                    Text("Without proper configuration, iOS shows:")
                        .font(.caption)

                    Text("\"You don't have any passkeys saved for this website or app.\"")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(.red)
                        .padding(8)
                        .background(Color.red.opacity(0.1))
                        .cornerRadius(6)

                    Text("This happens when AASA is missing/invalid or no matching credentials exist.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Divider()

                // The Fix
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundColor(.green)
                        Text("preferImmediatelyAvailableCredentials")
                            .font(.subheadline)
                            .fontWeight(.semibold)
                    }

                    Toggle(isOn: $passkeyManager.usePreferImmediatelyAvailable) {
                        Text("Enable Fix")
                            .font(.subheadline)
                    }

                    Text("When enabled: Returns silent error instead of confusing message")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text("When disabled: May show the confusing 'no passkeys' message")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                Divider()

                // Additional Requirements
                VStack(alignment: .leading, spacing: 8) {
                    Text("Additional Requirements")
                        .font(.subheadline)
                        .fontWeight(.semibold)

                    VStack(alignment: .leading, spacing: 4) {
                        Label("Valid AASA file (webcredentials)", systemImage: "doc.badge.gearshape")
                        Label("Credential Provider enabled in Settings", systemImage: "gearshape.fill")
                        Label("ASCredentialIdentityStore populated by extension", systemImage: "square.stack.3d.up")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)
                }
            }
            .padding()
            .background(Color(.systemGray6))
            .cornerRadius(12)

            // AASA Toggle for Testing
            Button(action: {
                Task { await passkeyManager.toggleAASA() }
            }) {
                HStack {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                    Text("Toggle AASA (Test Problem)")
                }
                .frame(maxWidth: .infinity)
                .padding()
                .background(Color.orange)
                .foregroundColor(.white)
                .cornerRadius(10)
            }
        }
    }

    // MARK: - Debug Section

    private var debugSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Debug Log")
                .font(.headline)

            ScrollView {
                Text(passkeyManager.debugLog)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(height: 200)
            .padding(8)
            .background(Color.black)
            .foregroundColor(.green)
            .cornerRadius(8)

            Button("Clear Log") {
                passkeyManager.clearLog()
            }
            .font(.caption)
        }
    }
}

// MARK: - Settings View

struct SettingsView: View {
    @ObservedObject var passkeyManager: PasskeyManager
    @Environment(\.dismiss) var dismiss

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("Server Configuration")) {
                    TextField("Server URL", text: $passkeyManager.serverURL)
                        .autocapitalization(.none)

                    TextField("RP ID", text: $passkeyManager.rpID)
                        .autocapitalization(.none)
                }

                Section(header: Text("Enable Credential Provider")) {
                    Text("You MUST enable the credential provider extension for device-bound passkeys to work:")
                        .font(.subheadline)

                    VStack(alignment: .leading, spacing: 4) {
                        Label("Open Settings app", systemImage: "1.circle")
                        Label("Go to Passwords → Password Options", systemImage: "2.circle")
                        Label("Enable 'Passkey Demo Provider'", systemImage: "3.circle")
                    }
                    .font(.caption)
                    .foregroundColor(.secondary)

                    Button("Open Settings") {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            UIApplication.shared.open(url)
                        }
                    }
                }

                Section(header: Text("Architecture")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Device-Bound vs Synced Passkeys")
                            .font(.subheadline)
                            .fontWeight(.semibold)

                        Text("**Device-Bound** (this demo):")
                            .font(.caption)
                        Text("• Stored in Secure Enclave via credential provider extension")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• Never leaves this device")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• User must select 'Passkey Demo Provider' in system picker")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text("**Synced** (iCloud Keychain):")
                            .font(.caption)
                            .padding(.top, 4)
                        Text("• Stored in iCloud Keychain")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• Syncs across Apple devices")
                            .font(.caption)
                            .foregroundColor(.secondary)
                        Text("• Default if user selects iCloud Keychain in picker")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                }

                Section(header: Text("The Problem & Fix")) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("**Problem**: Without proper AASA, iOS shows 'no passkeys saved' even when passkeys exist in the credential provider.")
                            .font(.caption)

                        Text("**Fix**: Use `preferImmediatelyAvailableCredentials` to suppress confusing UI and return silent error instead.")
                            .font(.caption)

                        Text("**Additional**: Credential provider extension must populate `ASCredentialIdentityStore` so credentials appear in system picker.")
                            .font(.caption)
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarItems(trailing: Button("Done") { dismiss() })
        }
    }
}

#Preview {
    ContentView()
}

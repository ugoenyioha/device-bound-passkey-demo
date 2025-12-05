import Foundation
import AuthenticationServices
import SwiftUI

/**
 * PasskeyManager - Device-Bound Passkey Demo
 *
 * ARCHITECTURE (Option B - True Device-Bound):
 * This manager coordinates between the app and server, but DOES NOT directly
 * create or manage passkeys. Instead:
 *
 * 1. REGISTRATION: Triggers system credential picker → user chooses provider
 *    - If user selects "Passkey Demo Provider" → device-bound (Secure Enclave)
 *    - If user selects "iCloud Keychain" → synced (NOT device-bound)
 *
 * 2. AUTHENTICATION: Triggers system credential picker → shows all available credentials
 *    - Credentials from ASCredentialIdentityStore (populated by extension) appear
 *    - User selects which credential to use
 *
 * KEY INSIGHT: The main app cannot force device-bound storage. It can only
 * trigger the system UI and let the user choose. The credential provider
 * extension handles the actual device-bound storage in Secure Enclave.
 */

// MARK: - AASA Status

enum AASAStatus: CustomStringConvertible, Equatable {
    case unknown
    case valid
    case missing
    case error(String)

    var description: String {
        switch self {
        case .unknown: return "Unknown"
        case .valid: return "Valid"
        case .missing: return "Missing (will cause UX issues)"
        case .error(let msg): return "Error: \(msg)"
        }
    }

    static func == (lhs: AASAStatus, rhs: AASAStatus) -> Bool {
        switch (lhs, rhs) {
        case (.unknown, .unknown), (.valid, .valid), (.missing, .missing):
            return true
        case (.error(let l), .error(let r)):
            return l == r
        default:
            return false
        }
    }
}

// MARK: - PasskeyManager

@MainActor
class PasskeyManager: NSObject, ObservableObject {
    // Published properties
    // For device testing, use stable domain (passkeydemo.usableapps.local)
    @Published var serverURL = "https://passkeydemo.usableapps.local"
    @Published var rpID = "passkeydemo.usableapps.local"
    @Published var isLoading = false
    @Published var lastError = ""
    @Published var lastSuccess = ""
    @Published var debugLog = ""
    @Published var serverReachable = false
    @Published var aasaStatus: AASAStatus = .unknown

    // Embedded server mode - runs WebAuthn server on the device itself
    // NOTE: Embedded server uses rpID="localhost" which won't work with iOS passkeys
    // because iOS requires rpID to match an associated domain. Use external server for passkeys.
    @Published var useEmbeddedServer = false  // Default to external server for passkey support
    @Published var embeddedServer: EmbeddedWebServer?

    // Demo Controls - These explain the fixes, not toggle behavior
    // FIX #1: preferImmediatelyAvailableCredentials - suppress "no passkeys" UI
    @Published var usePreferImmediatelyAvailable = true

    // Device-bound credential count (from extension's shared store)
    @Published var storedCredentialCount = 0

    // Device-bound credentials list (usernames and details)
    @Published var storedCredentials: [StoredPasskeyCredentialInfo] = []

    // System credential identity count
    @Published var systemIdentityCount = 0

    // Active credential count - shows correct count based on server mode
    var activeCredentialCount: Int {
        if useEmbeddedServer, let server = embeddedServer {
            return server.credentialCount
        }
        return storedCredentialCount
    }

    // Label for credential count based on server mode
    var credentialCountLabel: String {
        if useEmbeddedServer {
            return "Server credentials"
        }
        return "Device-bound credentials"
    }

    // Private
    private var currentChallenge: Data?
    private var currentChallengeId: String?
    private var pendingUsername: String?
    private var isRegistering = false

    // Continuation for async/await bridge
    private var authContinuation: CheckedContinuation<ASAuthorization, Error>?

    // Shared data with credential provider extension
    private let sharedDefaults = UserDefaults(suiteName: "group.com.demo.PasskeyDemo")

    // Computed property for actual server URL
    var activeServerURL: String {
        if useEmbeddedServer, let server = embeddedServer, server.isRunning {
            return "http://localhost:\(server.port)"
        }
        return serverURL
    }

    override init() {
        super.init()

        // Initialize embedded server (but don't start it by default)
        embeddedServer = EmbeddedWebServer()

        Task {
            // Only start embedded server if explicitly enabled
            // NOTE: Embedded server won't work for passkeys due to rpID/associated domain requirements
            if useEmbeddedServer {
                embeddedServer?.start()
                try? await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
            }

            await checkServerConnection()
            await checkAASAStatus()
            updateStoredCredentialCount()
            await updateSystemIdentityCount()
        }
    }

    // Toggle embedded server mode
    func toggleEmbeddedServer() {
        useEmbeddedServer.toggle()

        if useEmbeddedServer {
            embeddedServer?.start()
            log("Switched to EMBEDDED server mode (on-device)")
        } else {
            embeddedServer?.stop()
            log("Switched to EXTERNAL server mode (\(serverURL))")
        }

        Task {
            try? await Task.sleep(nanoseconds: 500_000_000)
            await checkServerConnection()
            await checkAASAStatus()
        }
    }

    // MARK: - Logging

    func log(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        debugLog = "[\(timestamp)] \(message)\n" + debugLog
        print("[PasskeyManager] \(message)")
    }

    func clearLog() {
        debugLog = ""
    }

    // MARK: - Credential Counts

    /// Count from extension's shared UserDefaults store
    func updateStoredCredentialCount() {
        if let data = sharedDefaults?.data(forKey: "storedPasskeys"),
           let credentials = try? JSONDecoder().decode([StoredPasskeyCredentialInfo].self, from: data) {
            storedCredentialCount = credentials.count
            storedCredentials = credentials
            let usernames = credentials.map { $0.userName }.joined(separator: ", ")
            log("Extension store: \(storedCredentialCount) device-bound credentials")
            if !credentials.isEmpty {
                log("Users: \(usernames)")
            }
        } else {
            storedCredentialCount = 0
            storedCredentials = []
            log("Extension store: empty")
        }
    }

    /// Count from system ASCredentialIdentityStore
    func updateSystemIdentityCount() async {
        let state = await ASCredentialIdentityStore.shared.state()
        if state.isEnabled {
            log("System identity store: enabled")
            // Note: We can't directly count identities, but we know it's working
            systemIdentityCount = storedCredentialCount // Assume sync with extension
        } else {
            log("System identity store: DISABLED - enable extension in Settings")
            systemIdentityCount = 0
        }
    }

    /// Clear all device-bound credentials (UserDefaults + system identity store + keychain)
    func clearAllDeviceBoundCredentials() async {
        log("=== CLEARING ALL DEVICE-BOUND CREDENTIALS ===")

        // 1. Get all credentials to find keychain tags
        let credentials = getAllStoredCredentials()
        log("Found \(credentials.count) credentials to clear")

        // 2. Delete private keys from Keychain
        for cred in credentials {
            if let tag = cred.privateKeyTag {
                deletePrivateKey(tag: tag)
            }
        }

        // 3. Clear UserDefaults
        sharedDefaults?.removeObject(forKey: "storedPasskeys")
        log("Cleared UserDefaults")

        // 4. Clear system identity store
        ASCredentialIdentityStore.shared.removeAllCredentialIdentities { success, error in
            if let error = error {
                print("[PasskeyManager] Failed to clear identity store: \(error)")
            } else if success {
                print("[PasskeyManager] System identity store cleared")
            }
        }
        log("Cleared system identity store")

        // 5. Update counts and clear the displayed list
        storedCredentialCount = 0
        systemIdentityCount = 0
        storedCredentials = []  // Clear the displayed list
        objectWillChange.send()

        log("=== CREDENTIALS CLEARED ===")
    }

    private func getAllStoredCredentials() -> [StoredPasskeyCredentialInfo] {
        guard let data = sharedDefaults?.data(forKey: "storedPasskeys"),
              let credentials = try? JSONDecoder().decode([StoredPasskeyCredentialInfo].self, from: data) else {
            return []
        }
        return credentials
    }

    private func deletePrivateKey(tag: String) {
        // Delete from regular keychain
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess {
            log("Deleted key with tag: \(tag.prefix(30))...")
        }

        // Delete Secure Enclave key data
        let seQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.demo.passkey.secureenclave",
            kSecAttrAccount as String: tag
        ]
        SecItemDelete(seQuery as CFDictionary)
    }

    // MARK: - Server Connection

    func checkServerConnection() async {
        do {
            let url = URL(string: "\(activeServerURL)/health")!
            let (_, response) = try await URLSession.shared.data(from: url)
            serverReachable = (response as? HTTPURLResponse)?.statusCode == 200
            let mode = useEmbeddedServer ? "embedded" : "external"
            log("Server connection (\(mode)): \(serverReachable ? "OK" : "Failed")")
        } catch {
            serverReachable = false
            log("Server connection error: \(error.localizedDescription)")
        }
    }

    // MARK: - AASA Check

    func checkAASAStatus() async {
        do {
            let url = URL(string: "\(activeServerURL)/.well-known/apple-app-site-association")!
            let (data, response) = try await URLSession.shared.data(from: url)

            if let httpResponse = response as? HTTPURLResponse {
                if httpResponse.statusCode == 200 {
                    if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                       let _ = json["webcredentials"] as? [String: Any] {
                        aasaStatus = .valid
                        log("AASA: Valid - webcredentials found")
                    } else {
                        aasaStatus = .error("Invalid format")
                        log("AASA: Invalid format")
                    }
                } else if httpResponse.statusCode == 404 {
                    aasaStatus = .missing
                    log("AASA: Missing (404) - this causes the 'no passkeys saved' message!")
                } else {
                    aasaStatus = .error("HTTP \(httpResponse.statusCode)")
                    log("AASA: HTTP error \(httpResponse.statusCode)")
                }
            }
        } catch {
            aasaStatus = .error(error.localizedDescription)
            log("AASA check error: \(error.localizedDescription)")
        }
    }

    func toggleAASA() async {
        do {
            let url = URL(string: "\(activeServerURL)/api/debug/toggle-aasa")!
            var request = URLRequest(url: url)
            request.httpMethod = "POST"

            let (data, _) = try await URLSession.shared.data(for: request)
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let message = json["message"] as? String {
                log("AASA toggle: \(message)")
            }

            await checkAASAStatus()
        } catch {
            log("Toggle AASA error: \(error.localizedDescription)")
        }
    }

    // MARK: - Passkey Registration
    //
    // FLOW:
    // 1. Get challenge from server
    // 2. Trigger ASAuthorizationController
    // 3. System shows credential picker (iCloud Keychain, Security Keys, Third-party providers)
    // 4. User selects provider - if they select "Passkey Demo Provider", extension creates device-bound key
    // 5. Result sent to server for verification

    func registerPasskey(username: String) async {
        isLoading = true
        lastError = ""
        lastSuccess = ""
        pendingUsername = username
        isRegistering = true

        log("=== REGISTRATION FLOW ===")
        log("Username: \(username)")
        log("IMPORTANT: Select 'Passkey Demo Provider' in the system picker for DEVICE-BOUND passkey")
        log("If you select 'iCloud Keychain', the passkey will SYNC (not device-bound)")

        do {
            // Step 1: Get registration options from server
            log("Step 1: Getting registration options from \(activeServerURL)...")
            let options = try await getRegistrationOptions(username: username)
            log("Got challenge from server: \(options.challenge.prefix(20))...")
            log("RP ID: \(options.rp.id), User ID: \(options.user.id.prefix(20))...")

            // Step 2: Trigger system credential picker
            // User must select which provider to use
            log("Step 2: Triggering system credential picker...")
            let credential = try await createPasskeyWithSystemPicker(options: options)
            log("Got credential from system: \(credential.credentialID.base64URLEncodedString().prefix(20))...")

            // Step 3: Verify with server
            log("Step 3: Verifying registration with server...")
            try await verifyRegistration(username: username, credential: credential)
            log("Registration verified by server!")

            // Note: ASCredentialIdentityStore is populated by the EXTENSION, not here
            // The extension's DeviceBoundPasskeyStore.saveCredential() calls updateIdentityStore()

            lastSuccess = "Passkey created for \(username)!"
            log("=== REGISTRATION COMPLETE ===")

            // Force UI update
            updateStoredCredentialCount()
            objectWillChange.send()
            await updateSystemIdentityCount()

            // Log final credential count
            log("Active credential count: \(activeCredentialCount)")

        } catch {
            log("Registration FAILED: \(error.localizedDescription)")
            handleAuthError(error)
        }

        isLoading = false
        isRegistering = false
    }

    private func getRegistrationOptions(username: String) async throws -> RegistrationOptions {
        let url = URL(string: "\(activeServerURL)/api/register/options")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(["username": username])

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(RegistrationOptions.self, from: data)
    }

    // MARK: - System Credential Picker for Registration

    private func createPasskeyWithSystemPicker(options: RegistrationOptions) async throws -> ASAuthorizationPlatformPublicKeyCredentialRegistration {
        log("Triggering system credential picker...")
        log("Available providers will be shown based on user's Settings")

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)

        let challenge = Data(base64URLEncoded: options.challenge)!
        let userID = Data(base64URLEncoded: options.user.id)!

        let request = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: options.user.name,
            userID: userID
        )

        currentChallenge = challenge

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self

        let authorization = try await withCheckedThrowingContinuation { continuation in
            self.authContinuation = continuation
            // Don't use preferImmediatelyAvailableCredentials for registration
            // We WANT the system picker to appear so user can choose provider
            controller.performRequests()
        }

        // Debug: Log what credential type we received
        log("Received authorization credential type: \(type(of: authorization.credential))")

        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration else {
            log("ERROR: Credential cast failed! Received: \(type(of: authorization.credential))")
            throw PasskeyError.invalidResponse
        }

        log("Successfully cast to ASAuthorizationPlatformPublicKeyCredentialRegistration")
        return credential
    }

    // MARK: - Registration Verification

    private func verifyRegistration(username: String, credential: ASAuthorizationPlatformPublicKeyCredentialRegistration) async throws {
        let url = URL(string: "\(activeServerURL)/api/register/verify")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let credentialResponse = CredentialResponse(
            id: credential.credentialID.base64URLEncodedString(),
            rawId: credential.credentialID.base64URLEncodedString(),
            type: "public-key",
            response: CredentialResponseData(
                clientDataJSON: credential.rawClientDataJSON.base64URLEncodedString(),
                attestationObject: credential.rawAttestationObject?.base64URLEncodedString() ?? "",
                authenticatorData: nil,
                signature: nil,
                userHandle: nil,
                transports: ["internal"]
            ),
            clientExtensionResults: [:]
        )

        let payload: [String: Any] = [
            "username": username,
            "credential": try credentialResponse.toDictionary()
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let (data, _) = try await URLSession.shared.data(for: request)

        if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
           let verified = json["verified"] as? Bool, verified {
            log("Server verified registration")
        } else {
            throw PasskeyError.verificationFailed
        }
    }

    // MARK: - Passkey Authentication
    //
    // FLOW:
    // 1. Get challenge from server (optionally with allowedCredentials hints)
    // 2. Trigger ASAuthorizationController
    // 3. System shows available credentials from ALL sources:
    //    - iCloud Keychain (synced passkeys)
    //    - ASCredentialIdentityStore (populated by our extension with device-bound passkeys)
    //    - Security keys
    // 4. User selects credential
    // 5. If from our extension → extension signs with Secure Enclave key
    // 6. Result sent to server

    func authenticateWithPasskey(username: String?) async {
        isLoading = true
        lastError = ""
        lastSuccess = ""
        pendingUsername = username
        isRegistering = false

        log("=== AUTHENTICATION FLOW ===")
        log("Username: \(username ?? "discoverable (any passkey)")")
        log("Credentials will be shown from ALL sources (iCloud + extensions)")

        do {
            // Step 1: Get authentication options from server
            let (options, challengeId) = try await getAuthenticationOptions(username: username)
            currentChallengeId = challengeId

            // Log allowedCredentials info
            if let creds = options.allowCredentials, !creds.isEmpty {
                log("Server provided \(creds.count) allowedCredentials hints")
            } else {
                log("No allowedCredentials - showing all available credentials")
            }

            // Step 2: Get passkey assertion via system picker
            let credential = try await getPasskeyAssertionWithSystemPicker(options: options)
            log("Got credential assertion")

            // Step 3: Verify with server
            let authenticatedUser = try await verifyAuthentication(
                credential: credential,
                challengeId: challengeId
            )
            lastSuccess = "Signed in as: \(authenticatedUser)"
            log("Authentication verified!")

        } catch {
            handleAuthError(error)
        }

        isLoading = false
    }

    private func getAuthenticationOptions(username: String?) async throws -> (AuthenticationOptions, String) {
        let url = URL(string: "\(activeServerURL)/api/authenticate/options")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [:]
        if let username = username {
            body["username"] = username
        }
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, _) = try await URLSession.shared.data(for: request)

        var json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let challengeId = json["_challengeId"] as? String ?? ""
        json.removeValue(forKey: "_challengeId")

        let optionsData = try JSONSerialization.data(withJSONObject: json)
        let options = try JSONDecoder().decode(AuthenticationOptions.self, from: optionsData)

        return (options, challengeId)
    }

    private func getPasskeyAssertionWithSystemPicker(options: AuthenticationOptions) async throws -> ASAuthorizationPlatformPublicKeyCredentialAssertion {
        log("Triggering system credential picker for authentication...")

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: rpID)

        let challenge = Data(base64URLEncoded: options.challenge)!
        let request = provider.createCredentialAssertionRequest(challenge: challenge)

        // Apply allowedCredentials hints if available
        if let allowCredentials = options.allowCredentials, !allowCredentials.isEmpty {
            request.allowedCredentials = allowCredentials.compactMap { cred in
                guard let credId = Data(base64URLEncoded: cred.id) else { return nil }
                return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credId)
            }
            log("Applied \(allowCredentials.count) allowedCredentials hints")
        }

        currentChallenge = challenge

        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = self

        // FIX #1: preferImmediatelyAvailableCredentials
        // This suppresses the confusing "no passkeys saved" message
        // If no credentials are available, returns silent error instead
        let authorization: ASAuthorization
        if usePreferImmediatelyAvailable {
            log("FIX #1: Using preferImmediatelyAvailableCredentials")
            log("→ If no credentials found, will return silent error instead of confusing UI")
            authorization = try await withCheckedThrowingContinuation { continuation in
                self.authContinuation = continuation
                controller.performRequests(options: .preferImmediatelyAvailableCredentials)
            }
        } else {
            log("FIX #1 DISABLED: May show 'no passkeys saved' message")
            authorization = try await withCheckedThrowingContinuation { continuation in
                self.authContinuation = continuation
                controller.performRequests()
            }
        }
        guard let credential = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion else {
            throw PasskeyError.invalidResponse
        }
        return credential
    }

    // MARK: - Authentication Verification

    private func verifyAuthentication(credential: ASAuthorizationPlatformPublicKeyCredentialAssertion, challengeId: String) async throws -> String {
        let url = URL(string: "\(activeServerURL)/api/authenticate/verify")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let credentialResponse = CredentialResponse(
            id: credential.credentialID.base64URLEncodedString(),
            rawId: credential.credentialID.base64URLEncodedString(),
            type: "public-key",
            response: CredentialResponseData(
                clientDataJSON: credential.rawClientDataJSON.base64URLEncodedString(),
                attestationObject: nil,
                authenticatorData: credential.rawAuthenticatorData.base64URLEncodedString(),
                signature: credential.signature.base64URLEncodedString(),
                userHandle: credential.userID.base64URLEncodedString(),
                transports: nil
            ),
            clientExtensionResults: [:]
        )

        let payload: [String: Any] = [
            "credential": try credentialResponse.toDictionary(),
            "challengeId": challengeId
        ]

        request.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let (data, _) = try await URLSession.shared.data(for: request)

        if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
           let verified = json["verified"] as? Bool, verified,
           let username = json["username"] as? String {
            return username
        } else {
            throw PasskeyError.verificationFailed
        }
    }

    // MARK: - Error Handling

    private func handleAuthError(_ error: Error) {
        if let authError = error as? ASAuthorizationError {
            switch authError.code {
            case .canceled:
                lastError = "User canceled"
                log("User canceled the request")
            case .invalidResponse:
                lastError = "Invalid response from authenticator"
                log("Invalid response - check server configuration")
            case .notHandled:
                lastError = "Request not handled"
                log("Not handled - check AASA configuration!")
            case .failed:
                lastError = "Authentication failed"
                log("Failed - check credentials exist")
            case .notInteractive:
                // This is the "no passkeys saved" scenario when using preferImmediatelyAvailableCredentials
                lastError = "No credentials available"
                log("No credentials found (silent error from preferImmediatelyAvailableCredentials)")
                log("→ This is BETTER than showing 'no passkeys saved' message!")
                log("→ Create a passkey first, or check Settings > Passwords > Password Options")
            @unknown default:
                lastError = "Unknown error: \(authError.code.rawValue)"
                log("Unknown error code: \(authError.code.rawValue)")
            }
        } else {
            lastError = error.localizedDescription
            log("Error: \(error.localizedDescription)")
        }
    }
}

// MARK: - ASAuthorizationControllerDelegate

extension PasskeyManager: ASAuthorizationControllerDelegate {
    nonisolated func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        Task { @MainActor in
            // Log which type of credential was returned
            if let _ = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialRegistration {
                log("Registration completed via system picker")
            } else if let _ = authorization.credential as? ASAuthorizationPlatformPublicKeyCredentialAssertion {
                log("Authentication completed via system picker")
            }

            authContinuation?.resume(returning: authorization)
            authContinuation = nil
        }
    }

    nonisolated func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        Task { @MainActor in
            authContinuation?.resume(throwing: error)
            authContinuation = nil
        }
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding

extension PasskeyManager: ASAuthorizationControllerPresentationContextProviding {
    nonisolated func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return MainActor.assumeIsolated {
            guard let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
                  let window = scene.windows.first else {
                fatalError("No window available")
            }
            return window
        }
    }
}

// MARK: - Error Types

enum PasskeyError: LocalizedError {
    case verificationFailed
    case invalidResponse
    case noCredentials

    var errorDescription: String? {
        switch self {
        case .verificationFailed: return "Server verification failed"
        case .invalidResponse: return "Invalid response from server"
        case .noCredentials: return "No credentials available"
        }
    }
}

// MARK: - Data Models

struct RegistrationOptions: Codable {
    let challenge: String
    let user: WebAuthnUser
    let rp: WebAuthnRP
    let pubKeyCredParams: [PubKeyCredParam]
    let timeout: Int?
    let authenticatorSelection: AuthenticatorSelection?
    let excludeCredentials: [CredentialDescriptor]?
}

struct WebAuthnUser: Codable {
    let id: String
    let name: String
    let displayName: String
}

struct WebAuthnRP: Codable {
    let id: String
    let name: String
}

struct PubKeyCredParam: Codable {
    let type: String
    let alg: Int
}

struct AuthenticatorSelection: Codable {
    let authenticatorAttachment: String?
    let residentKey: String?
    let userVerification: String?
}

struct CredentialDescriptor: Codable {
    let id: String
    let type: String
    let transports: [String]?
}

struct AuthenticationOptions: Codable {
    let challenge: String
    let timeout: Int?
    let rpId: String?
    let allowCredentials: [CredentialDescriptor]?
    let userVerification: String?
}

struct CredentialResponse: Codable {
    let id: String
    let rawId: String
    let type: String
    let response: CredentialResponseData
    let clientExtensionResults: [String: String]

    func toDictionary() throws -> [String: Any] {
        let data = try JSONEncoder().encode(self)
        return try JSONSerialization.jsonObject(with: data) as! [String: Any]
    }
}

struct CredentialResponseData: Codable {
    let clientDataJSON: String
    let attestationObject: String?
    let authenticatorData: String?
    let signature: String?
    let userHandle: String?
    let transports: [String]?
}

// Info struct for reading extension's stored credentials
struct StoredPasskeyCredentialInfo: Codable {
    let credentialID: Data
    let relyingPartyIdentifier: String
    let userName: String
    let userHandle: Data?
    let privateKeyTag: String?
    let publicKey: Data?
    let createdAt: Date?
    var signCounter: UInt32?

    // Flexible init for decoding partial data
    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        credentialID = try container.decode(Data.self, forKey: .credentialID)
        relyingPartyIdentifier = try container.decode(String.self, forKey: .relyingPartyIdentifier)
        userName = try container.decode(String.self, forKey: .userName)
        userHandle = try container.decodeIfPresent(Data.self, forKey: .userHandle)
        privateKeyTag = try container.decodeIfPresent(String.self, forKey: .privateKeyTag)
        publicKey = try container.decodeIfPresent(Data.self, forKey: .publicKey)
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt)
        signCounter = try container.decodeIfPresent(UInt32.self, forKey: .signCounter)
    }
}

// MARK: - Data Extensions

extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        while base64.count % 4 != 0 {
            base64.append("=")
        }

        self.init(base64Encoded: base64)
    }

    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

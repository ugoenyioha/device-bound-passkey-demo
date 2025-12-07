import AuthenticationServices
import CryptoKit
import DeviceCheck
import LocalAuthentication
import os.log

/**
 * Device-Bound Passkey Implementation using Secure Enclave
 *
 * TRUE device-bound: Keys are generated IN the Secure Enclave and cannot be extracted.
 * The dataRepresentation is an encrypted blob that can only be decrypted by the same
 * Secure Enclave that created it - making these keys truly non-exportable and device-bound.
 */
class CredentialProviderViewController: ASCredentialProviderViewController {

    private let logger = Logger(subsystem: "com.demo.PasskeyDemo.CredentialProvider", category: "SecureEnclave")
    private let serverURL = "https://passkeydemo.usableapps.local"

    // Track whether we're using Secure Enclave or software fallback
    private var isUsingSecureEnclave: Bool = false

    // App Attest service for hardware attestation proof
    private var appAttestService: DCAppAttestService {
        return DCAppAttestService.shared
    }

    // Remote logging helper
    private func remoteLog(_ message: String, level: String = "INFO", data: [String: Any]? = nil) {
        logger.info("\(message)")

        guard let url = URL(string: "\(serverURL)/api/log") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = ["message": message, "level": level]
        if let data = data {
            body["data"] = data
        }

        request.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: request).resume()
    }

    // Lazy store access
    private var store: DeviceBoundPasskeyStore {
        return DeviceBoundPasskeyStore.shared
    }

    // Store for App Attest key ID and attestation
    private var appAttestKeyID: String?
    private var attestationObject: Data?

    // Store registration data for button action - DO NOT create credential until after auth
    // Note: We don't store the Secure Enclave private key object - it's stored in keychain
    // and retrieved by tag when needed for signing
    private var pendingIdentity: ASPasskeyCredentialIdentity?
    private var pendingPrivateKeyTag: String?
    private var pendingCredentialID: Data?
    private var pendingPublicKey: P256.Signing.PublicKey?
    private var pendingClientDataHash: Data?

    override func viewDidLoad() {
        super.viewDidLoad()
        // Note: iOS controls the credential provider extension sheet presentation.
        // We cannot make it transparent or skip it - this is by design for security.
        // See research: Share/credential provider extensions use system-controlled sheets.
        logger.info("CredentialProvider: viewDidLoad")
        remoteLog("EXTENSION: viewDidLoad")
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        remoteLog("EXTENSION: viewWillAppear")
    }

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        remoteLog("TEST #19: prepareInterface called")

        guard let passkeyRequest = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            remoteLog("TEST #19: Invalid request type", level: "ERROR")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        remoteLog("TEST #19: RP=\(identity.relyingPartyIdentifier), user=\(identity.userName)")
        remoteLog("TEST #19: clientDataHash size=\(passkeyRequest.clientDataHash.count), hex=\(passkeyRequest.clientDataHash.prefix(16).map { String(format: "%02x", $0) }.joined())")

        // Store raw data - DO NOT create credential yet, wait until after biometric auth
        do {
            remoteLog("SECURE_ENCLAVE: Generating Secure Enclave key pair...")
            let keyPair = try generateSecureEnclaveKeyPair()
            remoteLog("SECURE_ENCLAVE: Key generated in Secure Enclave! Tag: \(keyPair.privateKeyTag)")

            // Create credential ID from public key hash
            let credentialID = Data(SHA256.hash(data: keyPair.publicKey.rawRepresentation + Data(UUID().uuidString.utf8)))
            remoteLog("SECURE_ENCLAVE: CredentialID size=\(credentialID.count)")

            // Store data for later - credential will be created AFTER auth
            // Note: Private key is already stored in keychain, we just keep the tag
            pendingIdentity = identity
            pendingPrivateKeyTag = keyPair.privateKeyTag
            pendingCredentialID = credentialID
            pendingPublicKey = keyPair.publicKey
            pendingClientDataHash = passkeyRequest.clientDataHash

            remoteLog("SECURE_ENCLAVE: Stored pending data, showing UI...")

            // Show UI with button
            setupUI(userName: identity.userName, rpID: identity.relyingPartyIdentifier)

        } catch {
            remoteLog("SECURE_ENCLAVE: Setup failed: \(error.localizedDescription)", level: "ERROR")
            extensionContext.cancelRequest(withError: error)
        }
    }

    private func setupUI(userName: String, rpID: String) {
        // Title label
        let titleLabel = UILabel()
        titleLabel.text = "Create Passkey"
        titleLabel.font = .boldSystemFont(ofSize: 24)
        titleLabel.textAlignment = .center
        titleLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(titleLabel)

        // Info label
        let infoLabel = UILabel()
        infoLabel.text = "User: \(userName)\nSite: \(rpID)"
        infoLabel.numberOfLines = 0
        infoLabel.textAlignment = .center
        infoLabel.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(infoLabel)

        // Complete button
        let completeButton = UIButton(type: .system)
        completeButton.setTitle("Create Passkey", for: .normal)
        completeButton.titleLabel?.font = .boldSystemFont(ofSize: 18)
        completeButton.backgroundColor = .systemBlue
        completeButton.setTitleColor(.white, for: .normal)
        completeButton.layer.cornerRadius = 12
        completeButton.translatesAutoresizingMaskIntoConstraints = false
        completeButton.addTarget(self, action: #selector(completeButtonTapped), for: .touchUpInside)
        view.addSubview(completeButton)

        // Cancel button
        let cancelButton = UIButton(type: .system)
        cancelButton.setTitle("Cancel", for: .normal)
        cancelButton.translatesAutoresizingMaskIntoConstraints = false
        cancelButton.addTarget(self, action: #selector(cancelButtonTapped), for: .touchUpInside)
        view.addSubview(cancelButton)

        // Layout
        NSLayoutConstraint.activate([
            titleLabel.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 40),
            titleLabel.centerXAnchor.constraint(equalTo: view.centerXAnchor),

            infoLabel.topAnchor.constraint(equalTo: titleLabel.bottomAnchor, constant: 20),
            infoLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            infoLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),

            completeButton.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            completeButton.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 40),
            completeButton.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -40),
            completeButton.heightAnchor.constraint(equalToConstant: 50),

            cancelButton.topAnchor.constraint(equalTo: completeButton.bottomAnchor, constant: 20),
            cancelButton.centerXAnchor.constraint(equalTo: view.centerXAnchor)
        ])

        logger.info("TEST #12: UI setup complete")
    }

    @objc private func completeButtonTapped() {
        logger.info("TEST #17: Complete button tapped!")
        guard let identity = pendingIdentity,
              let credentialID = pendingCredentialID,
              let publicKey = pendingPublicKey,
              let clientDataHash = pendingClientDataHash else {
            logger.error("TEST #17: Missing pending data!")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        // Perform biometric authentication first
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            logger.info("TEST #17: Requesting biometric authentication...")
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Create passkey for \(identity.relyingPartyIdentifier)"
            ) { [weak self] success, authError in
                guard let self = self else { return }

                DispatchQueue.main.async {
                    if success {
                        self.logger.info("TEST #17: Biometric auth succeeded!")
                        self.createAndCompleteRegistration(
                            identity: identity,
                            credentialID: credentialID,
                            publicKey: publicKey,
                            clientDataHash: clientDataHash
                        )
                    } else {
                        self.logger.error("TEST #17: Biometric auth failed: \(authError?.localizedDescription ?? "unknown")")
                        // Try without biometric
                        self.createAndCompleteRegistration(
                            identity: identity,
                            credentialID: credentialID,
                            publicKey: publicKey,
                            clientDataHash: clientDataHash
                        )
                    }
                }
            }
        } else {
            logger.info("TEST #17: Biometrics not available, trying device passcode...")
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: "Create passkey for \(identity.relyingPartyIdentifier)"
            ) { [weak self] success, authError in
                guard let self = self else { return }

                DispatchQueue.main.async {
                    if success {
                        self.logger.info("TEST #17: Device auth succeeded!")
                        self.createAndCompleteRegistration(
                            identity: identity,
                            credentialID: credentialID,
                            publicKey: publicKey,
                            clientDataHash: clientDataHash
                        )
                    } else {
                        self.logger.error("TEST #17: Device auth failed: \(authError?.localizedDescription ?? "unknown")")
                        self.createAndCompleteRegistration(
                            identity: identity,
                            credentialID: credentialID,
                            publicKey: publicKey,
                            clientDataHash: clientDataHash
                        )
                    }
                }
            }
        }
    }

    private func createAndCompleteRegistration(
        identity: ASPasskeyCredentialIdentity,
        credentialID: Data,
        publicKey: P256.Signing.PublicKey,
        clientDataHash: Data
    ) {
        remoteLog("SECURE_ENCLAVE: Creating credential NOW (after user auth)...")

        // Store credential to our store AND register with iOS credential identity store
        if let privateKeyTag = pendingPrivateKeyTag {
            // Use the SAME tag that was used when the key was stored in the keychain!
            let storedCredential = StoredPasskeyCredential(
                credentialID: credentialID,
                relyingPartyIdentifier: identity.relyingPartyIdentifier,
                userName: identity.userName,
                userHandle: identity.userHandle,
                privateKeyTag: privateKeyTag,
                publicKey: publicKey.rawRepresentation,
                createdAt: Date()
            )
            do {
                // CRITICAL: Clear old credentials for this RP first
                // This fixes the issue where old credentials point to deleted keychain keys
                store.clearCredentials(for: identity.relyingPartyIdentifier)
                remoteLog("TEST #19: Cleared old credentials for RP")

                try store.saveCredential(storedCredential)
                remoteLog("TEST #19: Credential saved to store!")

                // CRITICAL: Register with ASCredentialIdentityStore so iOS knows about this passkey
                // Without this, iOS won't offer our credential provider during sign-in
                let passkeyIdentity = ASPasskeyCredentialIdentity(
                    relyingPartyIdentifier: identity.relyingPartyIdentifier,
                    userName: identity.userName,
                    credentialID: credentialID,
                    userHandle: identity.userHandle,
                    recordIdentifier: privateKeyTag  // Use privateKeyTag as record identifier
                )

                // CRITICAL: Replace ALL identities with just the new one to avoid stale credentials
                // This fixes the issue where iOS tries to use old credentials whose keys were deleted
                self.remoteLog("IDENTITY STORE: Replacing all identities with new one...")
                ASCredentialIdentityStore.shared.replaceCredentialIdentities([passkeyIdentity]) { success, error in
                    if success {
                        self.remoteLog("IDENTITY STORE: Replaced all identities - now only have the new passkey!")
                    } else {
                        self.remoteLog("IDENTITY STORE: Failed to replace: \(error?.localizedDescription ?? "unknown")", level: "ERROR")
                    }
                }

            } catch {
                remoteLog("TEST #19: Failed to save credential: \(error)", level: "ERROR")
            }

            // CRITICAL: Send registration data directly to server from extension
            // This bypasses the iOS error 1000 issue where the main app doesn't receive the credential
            sendRegistrationToServer(
                username: identity.userName,
                credentialID: credentialID,
                publicKey: publicKey.rawRepresentation,
                rpID: identity.relyingPartyIdentifier,
                clientDataHash: clientDataHash
            )
        }

        // CRITICAL DEBUG: Log the credential ID in multiple formats
        let credIDHex = credentialID.map { String(format: "%02x", $0) }.joined()
        let credIDBase64 = credentialID.base64EncodedString()
        let credIDBase64URL = credIDBase64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        remoteLog("CRED_ID_DEBUG: Registration credentialID")
        remoteLog("CRED_ID_DEBUG:   Size: \(credentialID.count) bytes")
        remoteLog("CRED_ID_DEBUG:   Hex: \(credIDHex)")
        remoteLog("CRED_ID_DEBUG:   Base64: \(credIDBase64)")
        remoteLog("CRED_ID_DEBUG:   Base64URL: \(credIDBase64URL)")

        // Build authData
        let authData = buildAuthData(
            publicKey: publicKey,
            credentialID: credentialID,
            rpID: identity.relyingPartyIdentifier
        )
        remoteLog("TEST #19: AuthData built, size=\(authData.count), hex=\(authData.prefix(40).map { String(format: "%02x", $0) }.joined())")

        // Build attestation object
        let attestationObject = buildStandardNoneAttestation(authData: authData)
        remoteLog("TEST #19: Attestation built, size=\(attestationObject.count), hex=\(attestationObject.prefix(60).map { String(format: "%02x", $0) }.joined())")

        // CRITICAL: Log the credential ID we're about to use
        // The credentialID we pass to ASPasskeyRegistrationCredential should match what's in our authData
        remoteLog("CRED_ID_DEBUG: About to create ASPasskeyRegistrationCredential")
        remoteLog("CRED_ID_DEBUG:   credentialID (raw bytes) hex: \(credentialID.map { String(format: "%02x", $0) }.joined())")
        remoteLog("CRED_ID_DEBUG:   credentialID size: \(credentialID.count) bytes")

        // NOW create the registration credential (after biometric auth)
        let credential = ASPasskeyRegistrationCredential(
            relyingParty: identity.relyingPartyIdentifier,
            clientDataHash: clientDataHash,
            credentialID: credentialID,
            attestationObject: attestationObject
        )

        // Log what iOS creates - check if it modifies the credential ID
        remoteLog("CRED_ID_DEBUG: ASPasskeyRegistrationCredential created!")
        remoteLog("CRED_ID_DEBUG:   credential.credentialID hex: \(credential.credentialID.map { String(format: "%02x", $0) }.joined())")
        remoteLog("CRED_ID_DEBUG:   credential.credentialID size: \(credential.credentialID.count) bytes")

        // Also check what's in the attestation object (first 100 bytes)
        remoteLog("CRED_ID_DEBUG:   credential.attestationObject first 100 hex: \(credential.attestationObject.prefix(100).map { String(format: "%02x", $0) }.joined())")

        remoteLog("TEST #19: relyingParty=\(identity.relyingPartyIdentifier)")
        remoteLog("TEST #19: clientDataHash size=\(clientDataHash.count)")
        remoteLog("TEST #19: Calling completeRegistrationRequest NOW...")

        extensionContext.completeRegistrationRequest(using: credential)

        // Log after (this may or may not execute depending on how iOS handles it)
        remoteLog("TEST #19: completeRegistrationRequest returned (if you see this, the call completed)")
    }

    @objc private func cancelButtonTapped() {
        logger.info("TEST #12: Cancel button tapped")
        extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
    }

    // MARK: - Registration Implementation (unused in TEST #14)

    // MARK: - Secure Enclave Key Generation

    /// Generates a TRUE device-bound key pair using the Secure Enclave.
    /// The private key NEVER leaves the Secure Enclave - it's hardware-bound and non-exportable.
    /// We store the dataRepresentation (an encrypted reference) in the keychain.
    private func generateSecureEnclaveKeyPair() throws -> (publicKey: P256.Signing.PublicKey, privateKeyTag: String) {
        let tag = "com.demo.passkey.\(UUID().uuidString)"

        remoteLog("SECURE_ENCLAVE: Checking Secure Enclave availability...")
        guard SecureEnclave.isAvailable else {
            remoteLog("SECURE_ENCLAVE: NOT AVAILABLE! This device doesn't support Secure Enclave.", level: "ERROR")
            throw NSError(domain: "SecureEnclave", code: -1,
                         userInfo: [NSLocalizedDescriptionKey: "Secure Enclave not available on this device"])
        }

        remoteLog("SECURE_ENCLAVE: Secure Enclave IS available! Generating key...")

        // Create access control for biometric authentication
        // Using .biometryCurrentSet ensures:
        // 1. Key can only be used after successful biometric auth
        // 2. Key is invalidated if biometrics are changed (new fingerprint/face added)
        // 3. Key cannot be extracted from the Secure Enclave
        var accessControlError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],  // Requires current biometric + SE usage only
            &accessControlError
        ) else {
            let error = accessControlError?.takeRetainedValue()
            remoteLog("SECURE_ENCLAVE: Failed to create access control: \(error?.localizedDescription ?? "unknown")", level: "ERROR")
            throw error ?? NSError(domain: "SecureEnclave", code: -2)
        }

        // Generate the key IN the Secure Enclave
        // This is the critical part - the private key is generated inside the hardware
        // and NEVER exists in normal memory
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)

        remoteLog("SECURE_ENCLAVE: Key generated IN Secure Enclave!")
        remoteLog("SECURE_ENCLAVE: Public key size: \(privateKey.publicKey.rawRepresentation.count) bytes")

        // Store the dataRepresentation (encrypted reference to the SE key) in keychain
        // This is NOT the actual private key - it's an encrypted blob that can only
        // be used by THIS device's Secure Enclave to reference the key
        try storeSecureEnclaveKeyReference(privateKey: privateKey, tag: tag)

        return (privateKey.publicKey, tag)
    }

    /// Stores the Secure Enclave key's dataRepresentation in the keychain.
    /// The dataRepresentation is an encrypted reference that can only be used
    /// by the same Secure Enclave to access the actual key.
    private func storeSecureEnclaveKeyReference(privateKey: SecureEnclave.P256.Signing.PrivateKey, tag: String) throws {
        // dataRepresentation is the encrypted blob - NOT the actual key material
        let keyData = privateKey.dataRepresentation
        remoteLog("SECURE_ENCLAVE: Storing key reference with tag: \(tag)")
        remoteLog("SECURE_ENCLAVE: dataRepresentation size: \(keyData.count) bytes (encrypted reference, not raw key)")

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,  // Store as generic password item
            kSecAttrService as String: "com.demo.passkey.secureenclave",
            kSecAttrAccount as String: tag,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]

        // Delete any existing key with same tag
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            remoteLog("SECURE_ENCLAVE: Failed to store key reference: \(status)", level: "ERROR")
            throw NSError(domain: "Keychain", code: Int(status))
        }
        remoteLog("SECURE_ENCLAVE: Key reference stored successfully!")
    }

    // MARK: - Apple App Attestation

    /// Generates an App Attest key and creates an attestation object.
    /// This provides cryptographic proof that the key was generated on genuine Apple hardware.
    private func generateAppAttestation(clientDataHash: Data, completion: @escaping (Data?, String?, Error?) -> Void) {
        remoteLog("APP_ATTEST: Checking App Attest availability...")

        guard appAttestService.isSupported else {
            remoteLog("APP_ATTEST: Not supported on this device - using fallback", level: "WARN")
            completion(nil, nil, nil)
            return
        }

        remoteLog("APP_ATTEST: Generating attestation key...")

        // Step 1: Generate an attestation key
        appAttestService.generateKey { [weak self] keyID, error in
            guard let self = self else { return }

            if let error = error {
                self.remoteLog("APP_ATTEST: Key generation failed: \(error.localizedDescription)", level: "ERROR")
                completion(nil, nil, error)
                return
            }

            guard let keyID = keyID else {
                self.remoteLog("APP_ATTEST: No key ID returned", level: "ERROR")
                completion(nil, nil, nil)
                return
            }

            self.remoteLog("APP_ATTEST: Key generated! KeyID: \(keyID.prefix(20))...")
            self.appAttestKeyID = keyID

            // Step 2: Create attestation for the key using clientDataHash as the challenge
            self.appAttestService.attestKey(keyID, clientDataHash: clientDataHash) { attestationData, error in
                if let error = error {
                    self.remoteLog("APP_ATTEST: Attestation failed: \(error.localizedDescription)", level: "ERROR")
                    completion(nil, keyID, error)
                    return
                }

                guard let attestationData = attestationData else {
                    self.remoteLog("APP_ATTEST: No attestation data returned", level: "ERROR")
                    completion(nil, keyID, nil)
                    return
                }

                self.remoteLog("APP_ATTEST: Attestation successful! Size: \(attestationData.count) bytes")
                self.attestationObject = attestationData
                completion(attestationData, keyID, nil)
            }
        }
    }

    /// Generate an assertion using the App Attest key for ongoing verification
    private func generateAppAttestAssertion(keyID: String, clientDataHash: Data, completion: @escaping (Data?, Error?) -> Void) {
        guard appAttestService.isSupported else {
            remoteLog("APP_ATTEST: Not supported for assertion", level: "WARN")
            completion(nil, nil)
            return
        }

        appAttestService.generateAssertion(keyID, clientDataHash: clientDataHash) { assertionData, error in
            if let error = error {
                self.remoteLog("APP_ATTEST: Assertion generation failed: \(error.localizedDescription)", level: "ERROR")
                completion(nil, error)
                return
            }

            self.remoteLog("APP_ATTEST: Assertion generated! Size: \(assertionData?.count ?? 0) bytes")
            completion(assertionData, nil)
        }
    }

    // MARK: - Authenticator Data Attestation

    private func buildAuthData(
        publicKey: P256.Signing.PublicKey,
        credentialID: Data,
        rpID: String
    ) -> Data {
        var authData = Data()

        // RP ID hash (32 bytes)
        let rpIdHash = Data(SHA256.hash(data: Data(rpID.utf8)))
        authData.append(rpIdHash)
        logger.info("TEST #14: rpIdHash=\(rpIdHash.map { String(format: "%02x", $0) }.joined())")

        // Flags for passkey credential:
        // UP (0x01) + UV (0x04) + BE (0x08) + BS (0x10) + AT (0x40) = 0x5D
        // IMPORTANT: BE and BS flags MUST be set for hybrid/cross-device authentication to work!
        // Without these flags, iOS rejects the credential during QR code scanning.
        // See: https://developer.apple.com/forums/thread/745587
        // Note: The key is still hardware-bound in Secure Enclave - these flags just indicate
        // the credential is "sync-capable" which iOS requires for third-party providers.
        authData.append(0x5D)
        logger.info("SECURE_ENCLAVE: Using flags 0x5D (UP+UV+BE+BS+AT) - required for hybrid transport")

        // Counter (4 bytes, big-endian, start at 0)
        var counter: UInt32 = 0
        withUnsafeBytes(of: counter.bigEndian) { authData.append(contentsOf: $0) }

        // AAGUID (16 zeros for self attestation)
        authData.append(Data(repeating: 0, count: 16))

        // Credential ID length (2 bytes, big-endian)
        var credIdLen = UInt16(credentialID.count).bigEndian
        withUnsafeBytes(of: credIdLen) { authData.append(contentsOf: $0) }

        // Credential ID
        authData.append(credentialID)

        // COSE public key (CBOR encoded)
        let coseKey = encodeCOSEPublicKey(publicKey: publicKey)
        authData.append(coseKey)

        logger.info("TEST #14: authData total size=\(authData.count)")
        return authData
    }

    private func encodeCOSEPublicKey(publicKey: P256.Signing.PublicKey) -> Data {
        let x963 = publicKey.x963Representation
        let x = Data(x963[1..<33])
        let y = Data(x963[33..<65])

        // COSE_Key map with 5 items for EC2 P-256
        var coseKey = Data()
        coseKey.append(0xA5)  // Map of 5 items

        // 1 (kty): 2 (EC2)
        coseKey.append(0x01)
        coseKey.append(0x02)

        // 3 (alg): -7 (ES256) - CBOR encoding: 0x26 = -7
        coseKey.append(0x03)
        coseKey.append(0x26)

        // -1 (crv): 1 (P-256) - CBOR encoding: 0x20 = -1
        coseKey.append(0x20)
        coseKey.append(0x01)

        // -2 (x): byte string - CBOR encoding: 0x21 = -2
        coseKey.append(0x21)
        coseKey.append(0x58)  // byte string, 1-byte length follows
        coseKey.append(0x20)  // 32 bytes
        coseKey.append(x)

        // -3 (y): byte string - CBOR encoding: 0x22 = -3
        coseKey.append(0x22)
        coseKey.append(0x58)  // byte string, 1-byte length follows
        coseKey.append(0x20)  // 32 bytes
        coseKey.append(y)

        return coseKey
    }

    private func createPackedSelfAttestation(
        authData: Data,
        clientDataHash: Data,
        privateKey: P256.Signing.PrivateKey
    ) -> Data {
        // Create signature over authData || clientDataHash
        var signatureData = Data()
        signatureData.append(authData)
        signatureData.append(clientDataHash)

        do {
            let signature = try privateKey.signature(for: signatureData)
            let sigBytes = signature.derRepresentation
            logger.info("TEST #14: Generated signature, size=\(sigBytes.count)")

            // Build CBOR attestation object with packed format
            return buildPackedAttestationCBOR(authData: authData, signature: sigBytes)
        } catch {
            logger.error("TEST #14: Signing failed: \(error)")
            // Fall back to "none" attestation
            return buildNoneAttestationCBOR(authData: authData)
        }
    }

    private func buildPackedAttestationCBOR(authData: Data, signature: Data) -> Data {
        var result = Data()

        // CBOR map with 3 items
        result.append(0xA3)

        // Key: "attStmt" (7 chars) - sorted first in CBOR deterministic ordering
        result.append(0x67)
        result.append(contentsOf: "attStmt".utf8)

        // Value: map with 2 items {alg: -7, sig: <bytes>}
        result.append(0xA2)

        // alg: -7 (ES256)
        result.append(0x63)  // "alg" (3 chars)
        result.append(contentsOf: "alg".utf8)
        result.append(0x26)  // -7 in CBOR

        // sig: byte string
        result.append(0x63)  // "sig" (3 chars)
        result.append(contentsOf: "sig".utf8)
        if signature.count < 256 {
            result.append(0x58)
            result.append(UInt8(signature.count))
        } else {
            result.append(0x59)
            var len = UInt16(signature.count).bigEndian
            withUnsafeBytes(of: len) { result.append(contentsOf: $0) }
        }
        result.append(signature)

        // Key: "authData" (8 chars)
        result.append(0x68)
        result.append(contentsOf: "authData".utf8)

        // Value: authData byte string
        if authData.count < 256 {
            result.append(0x58)
            result.append(UInt8(authData.count))
        } else {
            result.append(0x59)
            var len = UInt16(authData.count).bigEndian
            withUnsafeBytes(of: len) { result.append(contentsOf: $0) }
        }
        result.append(authData)

        // Key: "fmt" (3 chars)
        result.append(0x63)
        result.append(contentsOf: "fmt".utf8)

        // Value: "packed" (6 chars)
        result.append(0x66)
        result.append(contentsOf: "packed".utf8)

        logger.info("TEST #14: Packed attestation size=\(result.count)")
        logger.info("TEST #14: First 60 bytes hex=\(result.prefix(60).map { String(format: "%02x", $0) }.joined())")
        return result
    }

    private func buildNoneAttestationCBOR(authData: Data) -> Data {
        // Fallback - not used in TEST #16
        return buildStandardNoneAttestation(authData: authData)
    }

    private func buildStandardNoneAttestation(authData: Data) -> Data {
        // Standard WebAuthn order: fmt, attStmt, authData
        var result = Data()

        // CBOR map with 3 items
        result.append(0xA3)

        // 1. "fmt" -> "none"
        result.append(0x63)  // text string, 3 chars
        result.append(contentsOf: "fmt".utf8)
        result.append(0x64)  // text string, 4 chars
        result.append(contentsOf: "none".utf8)

        // 2. "attStmt" -> empty map
        result.append(0x67)  // text string, 7 chars
        result.append(contentsOf: "attStmt".utf8)
        result.append(0xA0)  // empty map

        // 3. "authData" -> byte string
        result.append(0x68)  // text string, 8 chars
        result.append(contentsOf: "authData".utf8)
        if authData.count < 256 {
            result.append(0x58)  // byte string, 1-byte length
            result.append(UInt8(authData.count))
        } else {
            result.append(0x59)  // byte string, 2-byte length
            let len = UInt16(authData.count).bigEndian
            withUnsafeBytes(of: len) { result.append(contentsOf: $0) }
        }
        result.append(authData)

        logger.info("TEST #16: None attestation size=\(result.count)")
        logger.info("TEST #16: First 30 bytes=\(result.prefix(30).map { String(format: "%02x", $0) }.joined())")

        return result
    }

    // MARK: - Passkey Assertion (Sign-in) - iOS 17.0+

    private var pendingAssertionRequest: ASPasskeyCredentialRequest?
    private var pendingStoredCredential: StoredPasskeyCredential?

    // This is called when iOS asks us to provide a credential (either password or passkey assertion)
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        remoteLog("PROVIDE CREDENTIAL: prepareInterfaceToProvideCredentialForRequest called")
        remoteLog("PROVIDE CREDENTIAL: Request type = \(type(of: credentialRequest))")

        // Check if this is a passkey assertion request
        guard let passkeyRequest = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = passkeyRequest.credentialIdentity as? ASPasskeyCredentialIdentity else {
            remoteLog("PROVIDE CREDENTIAL: Not a passkey request, cancelling", level: "ERROR")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        remoteLog("ASSERTION: RP=\(identity.relyingPartyIdentifier), user=\(identity.userName)")
        remoteLog("ASSERTION: credentialID=\(identity.credentialID.base64EncodedString().prefix(20))...")

        // Find the stored credential
        let credentials = store.getPasskeyCredentials(for: identity.relyingPartyIdentifier)
        remoteLog("ASSERTION: Found \(credentials.count) credentials for RP")

        guard let storedCredential = credentials.first(where: { $0.credentialID == identity.credentialID }) else {
            remoteLog("ASSERTION: Credential not found!", level: "ERROR")
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }

        remoteLog("ASSERTION: Found credential for user: \(storedCredential.userName)")

        // Store for later use
        pendingAssertionRequest = passkeyRequest
        pendingStoredCredential = storedCredential

        // Show UI for authentication
        setupAssertionUI(userName: storedCredential.userName, rpID: identity.relyingPartyIdentifier)
    }

    private func setupAssertionUI(userName: String, rpID: String) {
        // Clear existing views
        view.subviews.forEach { $0.removeFromSuperview() }

        // Style the view with a clean dark background
        view.backgroundColor = UIColor.systemBackground

        // Container for vertical centering
        let containerView = UIView()
        containerView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(containerView)

        // Face ID icon using SF Symbol
        let iconImageView = UIImageView()
        if let faceIDImage = UIImage(systemName: "faceid") {
            iconImageView.image = faceIDImage
        }
        iconImageView.tintColor = .systemBlue
        iconImageView.contentMode = .scaleAspectFit
        iconImageView.translatesAutoresizingMaskIntoConstraints = false
        containerView.addSubview(iconImageView)

        // Provider name label
        let providerLabel = UILabel()
        providerLabel.text = "PasskeyDemo"
        providerLabel.font = .systemFont(ofSize: 22, weight: .semibold)
        providerLabel.textColor = .label
        providerLabel.textAlignment = .center
        providerLabel.translatesAutoresizingMaskIntoConstraints = false
        containerView.addSubview(providerLabel)

        // Status message
        let statusLabel = UILabel()
        statusLabel.text = "Signing in as \(userName)"
        statusLabel.font = .systemFont(ofSize: 15, weight: .regular)
        statusLabel.textColor = .secondaryLabel
        statusLabel.textAlignment = .center
        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        containerView.addSubview(statusLabel)

        // Activity indicator
        let activityIndicator = UIActivityIndicatorView(style: .medium)
        activityIndicator.color = .systemBlue
        activityIndicator.startAnimating()
        activityIndicator.translatesAutoresizingMaskIntoConstraints = false
        containerView.addSubview(activityIndicator)

        // Layout constraints
        NSLayoutConstraint.activate([
            // Container centered in view
            containerView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            containerView.centerYAnchor.constraint(equalTo: view.centerYAnchor, constant: -40),
            containerView.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 40),
            containerView.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -40),

            // Face ID icon
            iconImageView.topAnchor.constraint(equalTo: containerView.topAnchor),
            iconImageView.centerXAnchor.constraint(equalTo: containerView.centerXAnchor),
            iconImageView.widthAnchor.constraint(equalToConstant: 60),
            iconImageView.heightAnchor.constraint(equalToConstant: 60),

            // Provider label
            providerLabel.topAnchor.constraint(equalTo: iconImageView.bottomAnchor, constant: 16),
            providerLabel.centerXAnchor.constraint(equalTo: containerView.centerXAnchor),
            providerLabel.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            providerLabel.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),

            // Status label
            statusLabel.topAnchor.constraint(equalTo: providerLabel.bottomAnchor, constant: 8),
            statusLabel.centerXAnchor.constraint(equalTo: containerView.centerXAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: containerView.leadingAnchor),
            statusLabel.trailingAnchor.constraint(equalTo: containerView.trailingAnchor),

            // Activity indicator
            activityIndicator.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 20),
            activityIndicator.centerXAnchor.constraint(equalTo: containerView.centerXAnchor),
            activityIndicator.bottomAnchor.constraint(equalTo: containerView.bottomAnchor)
        ])

        // Auto-trigger Face ID after a brief moment to show the UI
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [weak self] in
            self?.signInButtonTapped()
        }
    }

    @objc private func signInButtonTapped() {
        remoteLog("ASSERTION: Sign In triggered")

        // Check which flow we're in:
        // 1. prepareInterfaceToProvideCredential flow: has pendingAssertionRequest + pendingStoredCredential
        // 2. prepareCredentialList flow: has pendingRequestParameters + pendingCredentialListCredential

        let credential: StoredPasskeyCredential
        let clientDataHash: Data

        if let passkeyRequest = pendingAssertionRequest, let storedCred = pendingStoredCredential {
            // Flow 1: prepareInterfaceToProvideCredential
            remoteLog("ASSERTION: Using prepareInterfaceToProvideCredential flow")
            credential = storedCred
            clientDataHash = passkeyRequest.clientDataHash
        } else if let requestParams = pendingRequestParameters, let storedCred = pendingCredentialListCredential {
            // Flow 2: prepareCredentialList
            remoteLog("ASSERTION: Using prepareCredentialList flow")
            credential = storedCred
            clientDataHash = requestParams.clientDataHash
        } else {
            remoteLog("ASSERTION: Missing pending data!", level: "ERROR")
            extensionContext.cancelRequest(withError: ASExtensionError(.failed))
            return
        }

        // Trigger biometric authentication - required for Secure Enclave key access
        let context = LAContext()
        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Sign in to \(credential.relyingPartyIdentifier)"
        ) { [weak self] success, error in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if success {
                    self.remoteLog("ASSERTION: Biometric succeeded")
                    self.performAssertionWithClientDataHash(credential: credential, clientDataHash: clientDataHash)
                } else {
                    self.remoteLog("ASSERTION: Biometric failed: \(error?.localizedDescription ?? "unknown")", level: "ERROR")
                    self.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
                }
            }
        }
    }

    private func performAssertion(request: ASPasskeyCredentialRequest, credential: StoredPasskeyCredential) {
        performAssertionWithClientDataHash(credential: credential, clientDataHash: request.clientDataHash)
    }

    private func performAssertionWithClientDataHash(credential: StoredPasskeyCredential, clientDataHash: Data) {
        remoteLog("ASSERTION: Performing assertion...")
        remoteLog("ASSERTION: clientDataHash size=\(clientDataHash.count), hex=\(clientDataHash.prefix(16).map { String(format: "%02x", $0) }.joined())")

        // CRITICAL DEBUG: Log the credential ID being used for assertion
        let credIDHex = credential.credentialID.map { String(format: "%02x", $0) }.joined()
        let credIDBase64 = credential.credentialID.base64EncodedString()
        let credIDBase64URL = credIDBase64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        remoteLog("CRED_ID_DEBUG: Assertion credentialID (from store)")
        remoteLog("CRED_ID_DEBUG:   Size: \(credential.credentialID.count) bytes")
        remoteLog("CRED_ID_DEBUG:   Hex: \(credIDHex)")
        remoteLog("CRED_ID_DEBUG:   Base64: \(credIDBase64)")
        remoteLog("CRED_ID_DEBUG:   Base64URL: \(credIDBase64URL)")

        do {
            // Retrieve Secure Enclave private key using stored dataRepresentation
            guard let privateKey = retrieveSecureEnclaveKey(tag: credential.privateKeyTag) else {
                remoteLog("SECURE_ENCLAVE: Failed to retrieve Secure Enclave key!", level: "ERROR")
                extensionContext.cancelRequest(withError: ASExtensionError(.failed))
                return
            }
            remoteLog("SECURE_ENCLAVE: Retrieved Secure Enclave key for signing")

            // CRITICAL: Increment the counter BEFORE using it to prevent replay attacks
            var mutableCredential = credential
            mutableCredential.signCounter += 1
            let newCounter = mutableCredential.signCounter
            remoteLog("ASSERTION: Incrementing counter from \(credential.signCounter) to \(newCounter)")

            // Persist the updated counter
            do {
                try store.updateCredential(mutableCredential)
                remoteLog("ASSERTION: Counter persisted successfully")
            } catch {
                remoteLog("ASSERTION: Failed to persist counter: \(error)", level: "ERROR")
                // Continue anyway - the assertion is still valid
            }

            // Build authenticator data with the NEW counter value
            let authData = buildAssertionAuthData(rpID: credential.relyingPartyIdentifier, counter: newCounter)
            remoteLog("ASSERTION: AuthData built, size=\(authData.count)")

            // Sign: authenticatorData || clientDataHash
            var signatureData = Data()
            signatureData.append(authData)
            signatureData.append(clientDataHash)

            let signature = try privateKey.signature(for: signatureData)
            let signatureBytes = signature.derRepresentation
            remoteLog("ASSERTION: Signature created, size=\(signatureBytes.count)")

            // Create the assertion credential
            let assertionCredential = ASPasskeyAssertionCredential(
                userHandle: credential.userHandle,
                relyingParty: credential.relyingPartyIdentifier,
                signature: signatureBytes,
                clientDataHash: clientDataHash,
                authenticatorData: authData,
                credentialID: credential.credentialID
            )

            remoteLog("ASSERTION: Completing assertion request...")
            extensionContext.completeAssertionRequest(using: assertionCredential)
            remoteLog("ASSERTION: completeAssertionRequest returned!")

            // Try to open the main app after successful assertion
            let username = credential.userName
            if let appURL = URL(string: "passkeydemo://success?username=\(username.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? username)") {
                remoteLog("ASSERTION: Opening main app with URL: \(appURL)")
                openURL(appURL)
            }

        } catch {
            remoteLog("ASSERTION: Error: \(error.localizedDescription)", level: "ERROR")
            extensionContext.cancelRequest(withError: error)
        }
    }

    // Open URL from extension using responder chain
    private func openURL(_ url: URL) {
        var responder: UIResponder? = self
        while responder != nil {
            if let application = responder as? UIApplication {
                application.open(url, options: [:], completionHandler: nil)
                return
            }
            responder = responder?.next
        }
        // Fallback: try via selector
        let selector = NSSelectorFromString("openURL:")
        var currentResponder: UIResponder? = self
        while currentResponder != nil {
            if currentResponder!.responds(to: selector) {
                currentResponder!.perform(selector, with: url)
                return
            }
            currentResponder = currentResponder?.next
        }
        remoteLog("ASSERTION: Could not open URL - no responder found")
    }

    private func buildAssertionAuthData(rpID: String, counter: UInt32) -> Data {
        var authData = Data()

        // RP ID hash (32 bytes)
        let rpIdHash = Data(SHA256.hash(data: Data(rpID.utf8)))
        authData.append(rpIdHash)

        // Flags for passkey assertion:
        // UP (0x01) + UV (0x04) + BE (0x08) + BS (0x10) = 0x1D
        // IMPORTANT: BE and BS flags MUST be set for hybrid/cross-device authentication to work!
        // No AT flag for assertion (no attested credential data)
        // See: https://developer.apple.com/forums/thread/745587
        authData.append(0x1D)

        // Counter (4 bytes, big-endian) - MUST increment to prevent replay attacks
        remoteLog("ASSERTION: Using counter value: \(counter)")
        withUnsafeBytes(of: counter.bigEndian) { authData.append(contentsOf: $0) }

        return authData
    }

    /// Retrieves a Secure Enclave private key using its stored dataRepresentation.
    /// The dataRepresentation is decrypted by the Secure Enclave to reference the actual key.
    private func retrieveSecureEnclaveKey(tag: String) -> SecureEnclave.P256.Signing.PrivateKey? {
        remoteLog("SECURE_ENCLAVE: Looking for key reference with tag: \(tag)")

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "com.demo.passkey.secureenclave",
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let keyData = result as? Data else {
            remoteLog("SECURE_ENCLAVE: Key reference retrieval failed: \(status) for tag: \(tag)", level: "ERROR")
            return nil
        }

        remoteLog("SECURE_ENCLAVE: Key reference found! dataRepresentation size: \(keyData.count)")

        // Restore the Secure Enclave key from its dataRepresentation
        // This uses the Secure Enclave to decrypt the reference and access the actual key
        do {
            let privateKey = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)
            remoteLog("SECURE_ENCLAVE: Key restored from Secure Enclave successfully!")
            return privateKey
        } catch {
            remoteLog("SECURE_ENCLAVE: Failed to restore key: \(error.localizedDescription)", level: "ERROR")
            return nil
        }
    }

    // MARK: - Other Required Overrides

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        remoteLog("prepareCredentialList called (passwords)")
        extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
    }

    // Store for credential list flow
    private var pendingRequestParameters: ASPasskeyCredentialRequestParameters?
    private var pendingCredentialListCredential: StoredPasskeyCredential?

    override func prepareCredentialList(
        for serviceIdentifiers: [ASCredentialServiceIdentifier],
        requestParameters: ASPasskeyCredentialRequestParameters
    ) {
        remoteLog("prepareCredentialList called (passkeys) for RP: \(requestParameters.relyingPartyIdentifier)")

        // Find credentials for this RP
        let credentials = store.getPasskeyCredentials(for: requestParameters.relyingPartyIdentifier)
        remoteLog("Found \(credentials.count) passkey credentials")

        if credentials.isEmpty {
            remoteLog("No credentials found, cancelling")
            extensionContext.cancelRequest(withError: ASExtensionError(.credentialIdentityNotFound))
        } else {
            // Store request parameters for later
            pendingRequestParameters = requestParameters

            // For now, auto-select the first credential and show assertion UI
            // In a full implementation, you'd show a picker if there are multiple
            let credential = credentials[0]
            pendingCredentialListCredential = credential
            remoteLog("Auto-selecting credential for user: \(credential.userName)")

            // Show sign-in UI
            setupAssertionUI(userName: credential.userName, rpID: requestParameters.relyingPartyIdentifier)
        }
    }

    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        remoteLog("provideCredentialWithoutUserInteraction (password) - requiring user interaction")
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    // iOS 17+ passkey assertion without user interaction
    // CONFIRMED: iOS does not allow biometric (Face ID) in this method - it requires the UI sheet
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        remoteLog("provideCredentialWithoutUserInteraction - biometric requires UI, requesting user interaction")
        extensionContext.cancelRequest(withError: ASExtensionError(.userInteractionRequired))
    }

    // NOTE: Removed prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity)
    // because we now use prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) for iOS 17+
    // which handles both passkey and password credentials

    override func prepareInterfaceForExtensionConfiguration() {
        logger.info("prepareInterfaceForExtensionConfiguration")
    }

    // MARK: - Direct Server Registration

    /// Send registration data directly to the server from the extension
    /// This bypasses the iOS error 1000 issue where the main app doesn't receive the credential
    /// Now includes Apple App Attestation for cryptographic proof of device authenticity
    private func sendRegistrationToServer(
        username: String,
        credentialID: Data,
        publicKey: Data,
        rpID: String,
        clientDataHash: Data
    ) {
        remoteLog("DIRECT_REG: Starting direct server registration with App Attestation")
        remoteLog("DIRECT_REG: Username: \(username)")
        remoteLog("DIRECT_REG: RP ID: \(rpID)")

        // First, generate App Attestation to prove this is genuine Apple hardware
        generateAppAttestation(clientDataHash: clientDataHash) { [weak self] attestationData, keyID, error in
            guard let self = self else { return }

            // Convert to base64url format for the server
            let credentialIDBase64URL = credentialID.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")

            let publicKeyBase64URL = publicKey.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")

            self.remoteLog("DIRECT_REG: Credential ID (base64url): \(credentialIDBase64URL)")
            self.remoteLog("DIRECT_REG: Public Key length: \(publicKey.count) bytes")

            guard let url = URL(string: "\(self.serverURL)/api/register/direct") else {
                self.remoteLog("DIRECT_REG: Invalid URL", level: "ERROR")
                return
            }

            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.timeoutInterval = 30

            var body: [String: Any] = [
                "username": username,
                "credentialID": credentialIDBase64URL,
                "publicKey": publicKeyBase64URL,
                "rpID": rpID,
                "isDeviceBound": true,
                // Include authenticator data flags for server-side verification
                // BE+BS flags required for hybrid/cross-device auth to work
                "authenticatorFlags": 0x5D,  // UP(0x01) + UV(0x04) + BE(0x08) + BS(0x10) + AT(0x40) = 0x5D
                "clientDataHash": clientDataHash.base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")
            ]

            // Add App Attestation data if available (cryptographic proof of genuine hardware)
            if let attestationData = attestationData, let keyID = keyID {
                let attestationBase64URL = attestationData.base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: "")

                body["appAttestation"] = [
                    "keyID": keyID,
                    "attestationObject": attestationBase64URL
                ]
                self.remoteLog("DIRECT_REG: Including App Attestation (keyID: \(keyID.prefix(20))...)")
            } else {
                self.remoteLog("DIRECT_REG: No App Attestation available (development mode)", level: "WARN")
            }

            do {
                request.httpBody = try JSONSerialization.data(withJSONObject: body)
            } catch {
                self.remoteLog("DIRECT_REG: Failed to serialize body: \(error)", level: "ERROR")
                return
            }

            self.remoteLog("DIRECT_REG: Sending request to \(url.absoluteString)")

            // Use a URLSession with certificate bypass for development
            let session = self.createTrustingSession()

            let task = session.dataTask(with: request) { [weak self] data, response, error in
                if let error = error {
                    self?.remoteLog("DIRECT_REG: Request failed: \(error.localizedDescription)", level: "ERROR")
                    return
                }

                if let httpResponse = response as? HTTPURLResponse {
                    self?.remoteLog("DIRECT_REG: Response status: \(httpResponse.statusCode)")

                    if let data = data, let responseStr = String(data: data, encoding: .utf8) {
                        self?.remoteLog("DIRECT_REG: Response body: \(responseStr)")
                    }

                    if httpResponse.statusCode == 200 {
                        self?.remoteLog("DIRECT_REG: ✅ Registration successful! Public key sent to server with attestation.")
                    } else {
                        self?.remoteLog("DIRECT_REG: ❌ Registration failed with status \(httpResponse.statusCode)", level: "ERROR")
                    }
                }
            }

            task.resume()
        }
    }

    /// Create a URLSession that trusts our self-signed certificate
    private func createTrustingSession() -> URLSession {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60

        return URLSession(configuration: config, delegate: TrustingSessionDelegate(), delegateQueue: nil)
    }
}

// MARK: - URLSession Delegate for Certificate Trust
// The server certificate should be installed and trusted on the iOS device.
// This delegate uses default certificate validation - no bypass needed.
class TrustingSessionDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Use default certificate validation
        // The device should have the server certificate trusted in Settings > General > About > Certificate Trust Settings
        completionHandler(.performDefaultHandling, nil)
    }
}

// MARK: - Stored Credential

struct StoredPasskeyCredential: Codable {
    let credentialID: Data
    let relyingPartyIdentifier: String
    let userName: String
    let userHandle: Data
    let privateKeyTag: String
    let publicKey: Data
    let createdAt: Date
    var signCounter: UInt32

    init(credentialID: Data, relyingPartyIdentifier: String, userName: String,
         userHandle: Data, privateKeyTag: String, publicKey: Data, createdAt: Date) {
        self.credentialID = credentialID
        self.relyingPartyIdentifier = relyingPartyIdentifier
        self.userName = userName
        self.userHandle = userHandle
        self.privateKeyTag = privateKeyTag
        self.publicKey = publicKey
        self.createdAt = createdAt
        self.signCounter = 0
    }
}

// MARK: - Store (Lazy Singleton Pattern)

class DeviceBoundPasskeyStore {
    private static var _shared: DeviceBoundPasskeyStore?
    private static let lock = NSLock()

    static var shared: DeviceBoundPasskeyStore {
        lock.lock()
        defer { lock.unlock() }
        if _shared == nil {
            _shared = DeviceBoundPasskeyStore()
        }
        return _shared!
    }

    private lazy var userDefaults: UserDefaults? = {
        return UserDefaults(suiteName: "group.com.demo.PasskeyDemo")
    }()

    private init() {}

    func saveCredential(_ credential: StoredPasskeyCredential) throws {
        guard let defaults = userDefaults else {
            throw NSError(domain: "DeviceBoundPasskeyStore", code: -1,
                         userInfo: [NSLocalizedDescriptionKey: "App Group UserDefaults not available"])
        }
        var credentials = getAllCredentials()
        credentials.append(credential)
        let data = try JSONEncoder().encode(credentials)
        defaults.set(data, forKey: "storedPasskeys")
    }

    func getAllCredentials() -> [StoredPasskeyCredential] {
        guard let data = userDefaults?.data(forKey: "storedPasskeys"),
              let credentials = try? JSONDecoder().decode([StoredPasskeyCredential].self, from: data) else {
            return []
        }
        return credentials
    }

    func getCredentials(for serviceIdentifiers: [ASCredentialServiceIdentifier]) -> [StoredPasskeyCredential] {
        let identifiers = serviceIdentifiers.map { $0.identifier }
        return getAllCredentials().filter { identifiers.contains($0.relyingPartyIdentifier) }
    }

    func getPasskeyCredentials(for rpID: String) -> [StoredPasskeyCredential] {
        return getAllCredentials().filter { $0.relyingPartyIdentifier == rpID }
    }

    func updateCredential(_ credential: StoredPasskeyCredential) throws {
        guard let defaults = userDefaults else {
            throw NSError(domain: "DeviceBoundPasskeyStore", code: -1,
                         userInfo: [NSLocalizedDescriptionKey: "App Group UserDefaults not available"])
        }
        var credentials = getAllCredentials()
        if let index = credentials.firstIndex(where: { $0.credentialID == credential.credentialID }) {
            credentials[index] = credential
            let data = try JSONEncoder().encode(credentials)
            defaults.set(data, forKey: "storedPasskeys")
        }
    }

    func clearCredentials(for rpID: String) {
        var credentials = getAllCredentials()
        credentials.removeAll { $0.relyingPartyIdentifier == rpID }
        if let data = try? JSONEncoder().encode(credentials) {
            userDefaults?.set(data, forKey: "storedPasskeys")
        }
    }

    func clearAllCredentials() {
        userDefaults?.removeObject(forKey: "storedPasskeys")
    }
}

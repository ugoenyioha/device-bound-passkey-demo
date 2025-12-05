import Foundation
import Network
import CryptoKit

/**
 * EmbeddedWebServer - A lightweight HTTP server for on-device WebAuthn
 *
 * This server runs entirely on the iPhone, eliminating the need for
 * a separate Mac server. It implements the WebAuthn Relying Party protocol.
 *
 * Endpoints:
 * - GET  /health                              - Health check
 * - GET  /.well-known/apple-app-site-association - AASA file
 * - POST /api/register/options                - Registration challenge
 * - POST /api/register/verify                 - Registration verification
 * - POST /api/authenticate/options            - Authentication challenge
 * - POST /api/authenticate/verify             - Authentication verification
 */

@MainActor
class EmbeddedWebServer: ObservableObject {
    private var listener: NWListener?
    private var connections: [NWConnection] = []

    @Published var isRunning = false
    @Published var port: UInt16 = 8080
    @Published var lastLog = ""

    // Credential count for UI display
    var credentialCount: Int {
        credentials.count
    }

    // User count for UI display
    var userCount: Int {
        users.count
    }

    // In-memory storage
    private var users: [String: User] = [:]
    private var challenges: [String: ChallengeData] = [:]
    private var credentials: [String: StoredCredential] = [:]

    // Configuration
    let rpID = "localhost"
    let rpName = "Passkey Demo (Local)"
    let teamID = "7XCMFL4395"
    let bundleID = "com.demo.PasskeyDemo"

    var origin: String {
        "http://localhost:\(port)"
    }

    struct User: Codable {
        let id: String
        var username: String
        var displayName: String
        var credentialIDs: [String]
    }

    struct ChallengeData: Codable {
        let challenge: String
        let type: String // "registration" or "authentication"
        let timestamp: Date
        let userId: String?
    }

    struct StoredCredential: Codable {
        let credentialID: String
        let publicKey: String
        var counter: Int
        let userId: String
        let username: String
        let createdAt: Date
    }

    func log(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        let logMessage = "[\(timestamp)] \(message)"
        print("[EmbeddedServer] \(message)")
        lastLog = logMessage
    }

    // MARK: - Server Lifecycle

    func start() {
        guard !isRunning else { return }

        do {
            let parameters = NWParameters.tcp
            parameters.allowLocalEndpointReuse = true

            listener = try NWListener(using: parameters, on: NWEndpoint.Port(rawValue: port)!)

            listener?.stateUpdateHandler = { [weak self] state in
                Task { @MainActor in
                    switch state {
                    case .ready:
                        self?.isRunning = true
                        self?.log("Server started on port \(self?.port ?? 0)")
                    case .failed(let error):
                        self?.log("Server failed: \(error)")
                        self?.isRunning = false
                    case .cancelled:
                        self?.isRunning = false
                        self?.log("Server stopped")
                    default:
                        break
                    }
                }
            }

            listener?.newConnectionHandler = { [weak self] connection in
                Task { @MainActor in
                    self?.handleConnection(connection)
                }
            }

            listener?.start(queue: .main)

        } catch {
            log("Failed to start server: \(error)")
        }
    }

    func stop() {
        listener?.cancel()
        connections.forEach { $0.cancel() }
        connections.removeAll()
        isRunning = false
    }

    // MARK: - Connection Handling

    private func handleConnection(_ connection: NWConnection) {
        connections.append(connection)

        connection.stateUpdateHandler = { [weak self] state in
            Task { @MainActor in
                guard let self = self else { return }
                switch state {
                case .ready:
                    self.receiveRequest(on: connection)
                case .failed, .cancelled:
                    self.connections.removeAll { $0 === connection }
                default:
                    break
                }
            }
        }

        connection.start(queue: .main)
    }

    private func receiveRequest(on connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let data = data, !data.isEmpty else {
                connection.cancel()
                return
            }

            Task { @MainActor in
                guard let self = self else { return }
                let response = await self.handleRequest(data)
                self.sendResponse(response, on: connection)
            }
        }
    }

    private func sendResponse(_ response: String, on connection: NWConnection) {
        let responseData = response.data(using: .utf8)!
        connection.send(content: responseData, completion: .contentProcessed { error in
            connection.cancel()
        })
    }

    // MARK: - Request Routing

    private func handleRequest(_ data: Data) async -> String {
        guard let requestString = String(data: data, encoding: .utf8) else {
            return httpResponse(status: 400, body: ["error": "Invalid request"])
        }

        let lines = requestString.components(separatedBy: "\r\n")
        guard let firstLine = lines.first else {
            return httpResponse(status: 400, body: ["error": "Invalid request"])
        }

        let parts = firstLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            return httpResponse(status: 400, body: ["error": "Invalid request"])
        }

        let method = parts[0]
        let path = parts[1]

        // Extract body for POST requests
        var body: [String: Any] = [:]
        if method == "POST", let bodyStart = requestString.range(of: "\r\n\r\n") {
            let bodyString = String(requestString[bodyStart.upperBound...])
            if let bodyData = bodyString.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: bodyData) as? [String: Any] {
                body = json
            }
        }

        log("\(method) \(path)")

        // Route request
        switch (method, path) {
        case ("GET", "/health"):
            return handleHealth()

        case ("GET", "/.well-known/apple-app-site-association"):
            return handleAASA()

        case ("POST", "/api/user"):
            return handleUser(body: body)

        case ("POST", "/api/register/options"):
            return handleRegisterOptions(body: body)

        case ("POST", "/api/register/verify"):
            return handleRegisterVerify(body: body)

        case ("POST", "/api/authenticate/options"):
            return handleAuthenticateOptions(body: body)

        case ("POST", "/api/authenticate/verify"):
            return handleAuthenticateVerify(body: body)

        case ("GET", "/api/debug/users"):
            return handleDebugUsers()

        case ("POST", "/api/debug/reset"):
            return handleDebugReset()

        default:
            return httpResponse(status: 404, body: ["error": "Not found"])
        }
    }

    // MARK: - HTTP Response Helper

    private func httpResponse(status: Int, body: [String: Any], contentType: String = "application/json") -> String {
        let statusText: String
        switch status {
        case 200: statusText = "OK"
        case 400: statusText = "Bad Request"
        case 404: statusText = "Not Found"
        case 500: statusText = "Internal Server Error"
        default: statusText = "Unknown"
        }

        let jsonData = try? JSONSerialization.data(withJSONObject: body, options: .prettyPrinted)
        let jsonString = jsonData.flatMap { String(data: $0, encoding: .utf8) } ?? "{}"

        return """
        HTTP/1.1 \(status) \(statusText)\r
        Content-Type: \(contentType)\r
        Content-Length: \(jsonString.utf8.count)\r
        Access-Control-Allow-Origin: *\r
        Connection: close\r
        \r
        \(jsonString)
        """
    }

    // MARK: - Endpoint Handlers

    private func handleHealth() -> String {
        return httpResponse(status: 200, body: [
            "status": "ok",
            "rpId": rpID,
            "origin": origin,
            "mode": "embedded"
        ])
    }

    private func handleAASA() -> String {
        log("AASA file requested")

        let aasa: [String: Any] = [
            "webcredentials": [
                "apps": ["\(teamID).\(bundleID)"]
            ],
            "applinks": [
                "details": [
                    [
                        "appIDs": ["\(teamID).\(bundleID)"],
                        "components": [
                            ["/": "/auth/*", "comment": "Authentication deep links"]
                        ]
                    ]
                ]
            ]
        ]

        return httpResponse(status: 200, body: aasa)
    }

    private func handleUser(body: [String: Any]) -> String {
        guard let username = body["username"] as? String else {
            return httpResponse(status: 400, body: ["error": "Username required"])
        }

        if let user = users[username] {
            return httpResponse(status: 200, body: [
                "id": user.id,
                "username": user.username,
                "displayName": user.displayName,
                "credentialCount": user.credentialIDs.count
            ])
        }

        let newUser = User(
            id: UUID().uuidString,
            username: username,
            displayName: username,
            credentialIDs: []
        )
        users[username] = newUser
        log("Created new user: \(username)")

        return httpResponse(status: 200, body: [
            "id": newUser.id,
            "username": newUser.username,
            "displayName": newUser.displayName,
            "credentialCount": 0
        ])
    }

    // MARK: - Registration

    private func handleRegisterOptions(body: [String: Any]) -> String {
        guard let username = body["username"] as? String else {
            return httpResponse(status: 400, body: ["error": "Username required"])
        }

        // Get or create user
        let user = users[username] ?? User(
            id: UUID().uuidString,
            username: username,
            displayName: username,
            credentialIDs: []
        )
        users[username] = user

        // Generate challenge (32 random bytes, base64url encoded)
        let challengeBytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let challenge = Data(challengeBytes).base64URLEncodedString()

        // Store challenge
        challenges[user.id] = ChallengeData(
            challenge: challenge,
            type: "registration",
            timestamp: Date(),
            userId: user.id
        )

        // Build excludeCredentials
        let excludeCredentials: [[String: Any]] = user.credentialIDs.compactMap { credId in
            guard let cred = credentials[credId] else { return nil }
            return [
                "id": cred.credentialID,
                "type": "public-key",
                "transports": ["internal"]
            ]
        }

        let options: [String: Any] = [
            "challenge": challenge,
            "rp": [
                "id": rpID,
                "name": rpName
            ],
            "user": [
                "id": Data(user.id.utf8).base64URLEncodedString(),
                "name": user.username,
                "displayName": user.displayName
            ],
            "pubKeyCredParams": [
                ["type": "public-key", "alg": -7],   // ES256
                ["type": "public-key", "alg": -257]  // RS256
            ],
            "timeout": 60000,
            "attestationType": "none",
            "excludeCredentials": excludeCredentials,
            "authenticatorSelection": [
                "authenticatorAttachment": "platform",
                "residentKey": "required",
                "userVerification": "required"
            ]
        ]

        log("Registration options generated for: \(username)")
        return httpResponse(status: 200, body: options)
    }

    private func handleRegisterVerify(body: [String: Any]) -> String {
        guard let username = body["username"] as? String,
              let credential = body["credential"] as? [String: Any] else {
            return httpResponse(status: 400, body: ["error": "Username and credential required"])
        }

        guard let user = users[username] else {
            return httpResponse(status: 400, body: ["error": "User not found"])
        }

        guard let challengeData = challenges[user.id],
              challengeData.type == "registration" else {
            return httpResponse(status: 400, body: ["error": "No pending registration challenge"])
        }

        // Extract credential data
        guard let credentialID = credential["id"] as? String,
              let response = credential["response"] as? [String: Any],
              let clientDataJSON = response["clientDataJSON"] as? String,
              let attestationObject = response["attestationObject"] as? String else {
            return httpResponse(status: 400, body: ["error": "Invalid credential format"])
        }

        // Verify clientDataJSON contains the correct challenge
        if let clientData = Data(base64URLEncoded: clientDataJSON),
           let clientJSON = try? JSONSerialization.jsonObject(with: clientData) as? [String: Any],
           let receivedChallenge = clientJSON["challenge"] as? String {

            if receivedChallenge != challengeData.challenge {
                log("Challenge mismatch!")
                return httpResponse(status: 400, body: ["error": "Challenge mismatch"])
            }
        }

        // For demo purposes, we'll trust the attestation without full CBOR parsing
        // In production, you'd parse the attestationObject and extract the public key

        // Store credential
        let storedCred = StoredCredential(
            credentialID: credentialID,
            publicKey: attestationObject, // In production, extract actual public key
            counter: 0,
            userId: user.id,
            username: user.username,
            createdAt: Date()
        )

        log("Storing credential with ID: \(credentialID.prefix(30))...")
        credentials[credentialID] = storedCred
        users[username]?.credentialIDs.append(credentialID)
        log("Total stored credentials: \(credentials.count)")

        // Notify observers that credentials changed
        objectWillChange.send()

        // Clear challenge
        challenges.removeValue(forKey: user.id)

        log("Passkey registered for: \(username)")

        return httpResponse(status: 200, body: [
            "verified": true,
            "credentialID": credentialID
        ])
    }

    // MARK: - Authentication

    private func handleAuthenticateOptions(body: [String: Any]) -> String {
        let username = body["username"] as? String

        // Generate challenge
        let challengeBytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let challenge = Data(challengeBytes).base64URLEncodedString()

        var allowCredentials: [[String: Any]] = []
        var challengeId = "anon-\(UUID().uuidString)"

        if let username = username, let user = users[username] {
            challengeId = user.id
            allowCredentials = user.credentialIDs.compactMap { credId in
                guard let cred = credentials[credId] else { return nil }
                return [
                    "id": cred.credentialID,
                    "type": "public-key",
                    "transports": ["internal"]
                ]
            }
        }

        // Store challenge
        challenges[challengeId] = ChallengeData(
            challenge: challenge,
            type: "authentication",
            timestamp: Date(),
            userId: username.flatMap { users[$0]?.id }
        )

        var options: [String: Any] = [
            "challenge": challenge,
            "rpId": rpID,
            "timeout": 60000,
            "userVerification": "required",
            "_challengeId": challengeId
        ]

        if !allowCredentials.isEmpty {
            options["allowCredentials"] = allowCredentials
        }

        log("Authentication options generated")
        return httpResponse(status: 200, body: options)
    }

    private func handleAuthenticateVerify(body: [String: Any]) -> String {
        guard let credential = body["credential"] as? [String: Any],
              let challengeId = body["challengeId"] as? String else {
            return httpResponse(status: 400, body: ["error": "Credential and challengeId required"])
        }

        // Try both rawId and id fields
        let credentialID = (credential["rawId"] as? String) ?? (credential["id"] as? String) ?? ""

        if credentialID.isEmpty {
            log("Missing credential ID in request")
            return httpResponse(status: 400, body: ["error": "Missing credential ID"])
        }

        log("Looking up credential: \(credentialID.prefix(20))...")
        log("Available credentials: \(credentials.keys.map { String($0.prefix(20)) })")

        // Find the credential - try multiple ID formats
        guard let storedCred = credentials[credentialID] ?? credentials.values.first(where: { $0.credentialID == credentialID }) else {
            log("Credential not found: \(credentialID.prefix(30))...")
            return httpResponse(status: 400, body: ["error": "Credential not found"])
        }

        log("Found credential for user: \(storedCred.username)")

        guard let challengeData = challenges[challengeId] ?? challenges[storedCred.userId],
              challengeData.type == "authentication" else {
            return httpResponse(status: 400, body: ["error": "No pending authentication challenge"])
        }

        // Verify response (simplified - in production, verify signature)
        guard let response = credential["response"] as? [String: Any],
              let clientDataJSON = response["clientDataJSON"] as? String else {
            return httpResponse(status: 400, body: ["error": "Invalid credential response"])
        }

        // Verify challenge in clientDataJSON
        if let clientData = Data(base64URLEncoded: clientDataJSON),
           let clientJSON = try? JSONSerialization.jsonObject(with: clientData) as? [String: Any],
           let receivedChallenge = clientJSON["challenge"] as? String {

            if receivedChallenge != challengeData.challenge {
                log("Authentication challenge mismatch!")
                return httpResponse(status: 400, body: ["error": "Challenge mismatch"])
            }
        }

        // Update counter
        if var cred = credentials[credentialID] {
            cred.counter += 1
            credentials[credentialID] = cred
        }

        // Clear challenges
        challenges.removeValue(forKey: challengeId)
        challenges.removeValue(forKey: storedCred.userId)

        log("Authentication successful for: \(storedCred.username)")

        return httpResponse(status: 200, body: [
            "verified": true,
            "username": storedCred.username,
            "userId": storedCred.userId
        ])
    }

    // MARK: - Debug Endpoints

    private func handleDebugUsers() -> String {
        let userList: [[String: Any]] = users.values.map { user in
            [
                "username": user.username,
                "id": user.id,
                "credentialCount": user.credentialIDs.count
            ]
        }
        return httpResponse(status: 200, body: ["users": userList])
    }

    private func handleDebugReset() -> String {
        users.removeAll()
        challenges.removeAll()
        credentials.removeAll()
        log("All data cleared")
        return httpResponse(status: 200, body: ["success": true])
    }
}

// Note: Data extension for base64URL is defined in PasskeyManager.swift

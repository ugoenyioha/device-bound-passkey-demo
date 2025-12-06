# Project Context for AI Agents

## Overview
iOS device-bound passkey implementation using Secure Enclave. Demonstrates hardware-bound credentials that cannot be synced or exported.

## Key Technical Decisions

### BE/BS Flag Paradox
- iOS **requires** BE=1/BS=1 for third-party credential providers to participate in hybrid transport
- Without these flags: "The operation either timed out or was not allowed"
- This is a **protocol requirement**, not a security override
- The actual key remains device-bound via Secure Enclave + `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- Apple expects apps setting BE/BS=1 to provide sync - we intentionally do not (desired behavior)
- Reference: https://developer.apple.com/forums/thread/742209

### Secure Enclave Implementation
- Keys generated with `SecureEnclave.P256.Signing.PrivateKey`
- Access control: `.privateKeyUsage` + `.biometryCurrentSet`
- Storage: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (prevents iCloud sync)
- Only `dataRepresentation` (encrypted reference) is stored, never raw key

### Authenticator Flags
```
Registration: 0x5D = UP(0x01) + UV(0x04) + BE(0x08) + BS(0x10) + AT(0x40)
Assertion:    0x1D = UP(0x01) + UV(0x04) + BE(0x08) + BS(0x10)
```

### WebAuthn Security Features
- Challenge expiration: 5 minutes (`CHALLENGE_TIMEOUT_MS`)
- Signature counter: Incremented on each assertion, server verifies increasing
- Random challenge: Primary replay defense
- Counter: Secondary signal for cloned authenticator detection

## Known Limitations (Document for RPs)
1. **AAGUID**: Zero (anonymous) - production should register with FIDO Alliance
2. **App Attestation**: Received but not verified against Apple CA chain
3. **Counter enforcement**: Logs warning, doesn't reject (enable strict mode for production)
4. **Debug endpoints**: Exposed at `/api/debug/*` - remove in production

## File Locations

| Component | Path |
|-----------|------|
| Credential Provider | `mobile/CredentialProvider/CredentialProviderViewController.swift` |
| Passkey Store | Same file, `DeviceBoundPasskeyStore` class |
| WebAuthn Server | `web/server.js` |
| AASA | Served dynamically by server.js |

## Git Branches
- `main`: Clean single commit for public repo
- `main-with-history`: Full development history preserved locally

## Important Code Patterns

### Secure Enclave Key Generation (lines ~381-424 in CredentialProviderViewController.swift)
```swift
let accessControl = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    [.privateKeyUsage, .biometryCurrentSet],
    &error
)
let privateKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
```

### Challenge Expiration (server.js)
```javascript
const CHALLENGE_TIMEOUT_MS = 5 * 60 * 1000;
// Check in verify endpoints before processing
if (challengeAge > CHALLENGE_TIMEOUT_MS) {
  return res.status(400).json({ error: 'Challenge expired' });
}
```

## External Dependencies
- `@simplewebauthn/server` - WebAuthn RP library
- iOS 17+ required (ASCredentialProviderViewController passkey support)
- Physical device required (Secure Enclave not in Simulator)

## Future Work Considerations
- Implement App Attestation CA chain verification
- Add user-facing credential management UI
- Register AAGUID with FIDO Alliance for production
- Enable strict counter verification (reject non-increasing)
- Add credential filtering against backend (like "Smart Log On Authenticator" pattern)

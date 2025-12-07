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

### Credential Provider Extension Sheet (iOS Platform Limitation)

**Problem**: When user taps "Use Passkey", iOS presents a sheet before Face ID appears. Can this be hidden or made transparent?

**Answer**: No - this is an intentional iOS platform limitation.

**Research Findings**:
1. **System-controlled presentation**: iOS presents credential provider extensions using `UISheetPresentationController` with system-controlled detents. Developers cannot customize the sheet container.

2. **`NSExtensionActionWantsFullScreenPresentation`**: This Info.plist key only works for **Action extensions**, not credential provider extensions. See [Apple's App Extension Keys documentation](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Articles/AppExtensionKeys.html).

3. **`provideCredentialWithoutUserInteraction`**: Cannot use biometrics - iOS requires the UI sheet for Face ID/Touch ID. This method is for silent credential provision only (e.g., from unlocked keychain).

4. **Industry consensus**: Bitwarden, Strongbox, and other password managers accept this limitation. None have found a workaround.

5. **Apple Engineer confirmation**: In [Apple Developer Forums thread #694643](https://developer.apple.com/forums/thread/694643), regarding share extensions: "When asked if there is a way to customize the detents... the answer is unfortunately no."

**Solution**: Transform the mandatory sheet into useful visual feedback:
- Show provider branding and Face ID icon
- Display "Signing in as [username]" status
- Activity indicator while authentication proceeds
- Auto-trigger Face ID after 0.3s delay

This follows iOS design patterns and provides clear security context to users about which credential provider is active.

## Known Limitations (Document for RPs)
1. **AAGUID**: Zero (anonymous) - production should register with FIDO Alliance
2. **App Attestation**: Received but not verified against Apple CA chain
3. **Counter enforcement**: Logs warning, doesn't reject (enable strict mode for production)
4. **Debug endpoints**: Exposed at `/api/debug/*` - remove in production
5. **Extension sheet**: Cannot be hidden (iOS platform limitation) - shows branded status UI instead

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

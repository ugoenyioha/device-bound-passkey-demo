# Cross-Device Passkey Authentication Sequence Diagram

## Overview

This document describes the complete flow for cross-device (hybrid) passkey authentication, where a user authenticates on a **desktop browser** using a passkey stored on their **iPhone**.

## Flow Captured: December 3, 2025

**Scenario**: User scans QR code on desktop browser with iPhone to sign in using a passkey.

## Sequence Diagram

```
┌─────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Browser │     │  RP Server  │     │   macOS     │     │   iPhone     │     │  Credential │
│ (Web)   │     │  (Node.js)  │     │  (CTAP2)    │     │  (iOS 17+)   │     │  Provider   │
└────┬────┘     └──────┬──────┘     └──────┬──────┘     └──────┬───────┘     └──────┬──────┘
     │                 │                   │                   │                    │
     │ 1. Click "Cross-Device (QR Code)"   │                   │                    │
     │─────────────────────────────────────>                   │                    │
     │                 │                   │                   │                    │
     │ 2. POST /auth/start                 │                   │                    │
     │────────────────>│                   │                   │                    │
     │                 │                   │                   │                    │
     │ 3. Challenge + AllowCredentials     │                   │                    │
     │<────────────────│                   │                   │                    │
     │                 │                   │                   │                    │
     │ 4. navigator.credentials.get({      │                   │                    │
     │      transports: ['hybrid']         │                   │                    │
     │    })                               │                   │                    │
     │─────────────────────────────────────>                   │                    │
     │                 │                   │                   │                    │
     │                 │  5. Display QR Code (CTAP2 hybrid)    │                    │
     │<─────────────────────────────────────                   │                    │
     │                 │                   │                   │                    │
     │                 │                   │  6. User scans QR with Camera          │
     │                 │                   │<──────────────────│                    │
     │                 │                   │                   │                    │
     │                 │                   │  7. BLE/Internet handshake             │
     │                 │                   │<─────────────────>│                    │
     │                 │                   │                   │                    │
     │                 │                   │  8. CTAP2 authenticatorGetAssertion    │
     │                 │                   │──────────────────>│                    │
     │                 │                   │                   │                    │
     │                 │                   │                   │ 9. Lookup credential│
     │                 │                   │                   │   (rpId: passkeydemo.usableapps.local)
     │                 │                   │                   │───────────────────>│
     │                 │                   │                   │                    │
     │                 │                   │                   │ 10. Found matching │
     │                 │                   │                   │     credential     │
     │                 │                   │                   │<───────────────────│
     │                 │                   │                   │                    │
     │                 │                   │                   │ 11. Face ID prompt │
     │                 │                   │                   │<───────────────────│
     │                 │                   │                   │                    │
     │                 │                   │                   │ 12. User authenticates│
     │                 │                   │                   │     with Face ID   │
     │                 │                   │                   │                    │
     │                 │                   │                   │ 13. Sign with      │
     │                 │                   │                   │     Secure Enclave │
     │                 │                   │                   │───────────────────>│
     │                 │                   │                   │                    │
     │                 │                   │                   │ 14. Assertion:     │
     │                 │                   │                   │  - authenticatorData│
     │                 │                   │                   │  - signature       │
     │                 │                   │                   │  - userHandle      │
     │                 │                   │                   │<───────────────────│
     │                 │                   │                   │                    │
     │                 │                   │  15. Assertion response               │
     │                 │                   │<──────────────────│                    │
     │                 │                   │                   │                    │
     │  16. Credential assertion returned  │                   │                    │
     │<─────────────────────────────────────                   │                    │
     │                 │                   │                   │                    │
     │ 17. POST /auth/verify               │                   │                    │
     │────────────────>│                   │                   │                    │
     │                 │                   │                   │                    │
     │                 │ 18. Verify signature with stored public key               │
     │                 │     - Check rpIdHash matches          │                    │
     │                 │     - Verify flags (UP, UV, BE, BS)   │                    │
     │                 │     - Increment counter               │                    │
     │                 │                   │                   │                    │
     │ 19. Auth success + session          │                   │                    │
     │<────────────────│                   │                   │                    │
     │                 │                   │                   │                    │
     │ 20. Redirect to success.html        │                   │                    │
     │                 │                   │                   │                    │
```

## WebAuthn Authenticator Data Flags

The authenticator data returned in the assertion contains critical flags:

| Flag | Bit | Value | Meaning |
|------|-----|-------|---------|
| UP (User Present) | 0 | 0x01 | User was present (tapped/interacted) |
| UV (User Verified) | 2 | 0x04 | User was verified (Face ID/Touch ID) |
| **BE (Backup Eligible)** | 3 | 0x08 | Credential CAN be backed up |
| **BS (Backup State)** | 4 | 0x10 | Credential IS currently backed up |
| AT (Attested) | 6 | 0x40 | Attestation data included (registration only) |

### Critical for Cross-Device Auth

**BE and BS flags MUST be set (value: 1) for cross-device/hybrid authentication to work.**

- **Registration flags**: `0x5D` = UP + UV + BE + BS + AT
- **Assertion flags**: `0x1D` = UP + UV + BE + BS

If BE=0 and BS=0, iOS will show: *"You don't have any passkeys saved for this website or app."*

## Console Trace

```
[10:10:45 PM] Starting cross-device (hybrid) authentication...
[10:10:46 PM] Requesting credential with hybrid transport (QR code)...
[10:12:22 PM] Credential received from cross-device auth
[10:12:22 PM] Cross-device authentication successful: demo@example.com
```

## Success Response Data

| Field | Value |
|-------|-------|
| Username | demo@example.com |
| Authentication Method | Passkey |
| Credential Type | Third-Party |
| Counter Verified | ✓ Incremented |
| isDeviceBound | false (BE+BS flags set) |
| isThirdPartyExtension | true |
| credentialBackedUp | true |
| registrationMethod | browser |

## Technical Details

### CTAP2 Hybrid Transport

The cross-device flow uses **CTAP2 hybrid transport**:

1. **QR Code Contains**:
   - Routing ID for cloud-mediated connection
   - Public key for encryption
   - One-time connection token

2. **Communication Path**:
   - Initial connection: BLE advertisement OR cloud relay
   - Data exchange: Encrypted tunnel (Noise protocol)
   - Assertion delivery: Via established tunnel

3. **Security Properties**:
   - End-to-end encrypted
   - Phishing resistant (rpId bound)
   - Device proximity verified (for BLE)

### Credential Provider Extension Flow

When iOS receives the CTAP2 request:

1. **ASCredentialProviderViewController** is instantiated
2. **prepareInterfaceToProvideCredential()** called with:
   - `ASPasskeyCredentialRequest`
   - Contains: rpId, challenge, userHandle, allowedCredentials
3. Extension looks up matching credential in local storage
4. Face ID prompt shown for user verification
5. **Secure Enclave** signs the challenge
6. Assertion returned via **extensionContext.completeAssertionRequest()**

## Files Involved

| Component | File |
|-----------|------|
| Browser JS | `/web/public/app.js` |
| RP Server | `/web/src/index.ts` |
| Credential Provider | `/ios/CredentialProvider/CredentialProviderViewController.swift` |
| Auth Data Builder | Lines ~980-1050 in CredentialProviderViewController.swift |

## Screenshots

- QR Code Display: `~/.playwright-mcp/cross-device-qr-code.png`
- Success Page: `~/.playwright-mcp/cross-device-auth-success.png`

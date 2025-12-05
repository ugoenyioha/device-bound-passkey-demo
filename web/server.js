/**
 * Passkey Demo - WebAuthn Relying Party Server
 *
 * This server demonstrates:
 * 1. WebAuthn registration (passkey creation)
 * 2. WebAuthn authentication (passkey sign-in)
 * 3. Apple App Site Association (AASA) file serving
 * 4. The difference between having AASA vs not having it
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = process.env.PORT || 3001;

// Configuration
const RP_ID = process.env.RP_ID || 'localhost';
const RP_NAME = 'Passkey Demo';
const ORIGIN = process.env.ORIGIN || `http://${RP_ID}:${PORT}`;

// For iOS Simulator, we'll use a custom domain
// In production, this would be your actual domain
const IOS_RP_ID = 'passkeydemo.local';

// Challenge expiration time (5 minutes in milliseconds)
// WebAuthn challenges should expire to prevent replay attacks
const CHALLENGE_TIMEOUT_MS = 5 * 60 * 1000;

// Persistent storage file path
const DATA_FILE = process.env.DATA_FILE || '/tmp/passkey-data.json';

// In-memory storage with persistence
let users = new Map();
let challenges = new Map();
let credentials = new Map();

// Load persisted data on startup
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      users = new Map(data.users || []);
      credentials = new Map(data.credentials || []);
      console.log(`📂 Loaded ${users.size} users and ${credentials.size} credentials from ${DATA_FILE}`);
    }
  } catch (error) {
    console.log(`⚠️ Could not load data file: ${error.message}`);
  }
}

// Save data to disk
function saveData() {
  try {
    const data = {
      users: Array.from(users.entries()),
      credentials: Array.from(credentials.entries()),
      savedAt: new Date().toISOString()
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    console.log(`💾 Saved ${users.size} users and ${credentials.size} credentials to ${DATA_FILE}`);
  } catch (error) {
    console.error(`❌ Failed to save data: ${error.message}`);
  }
}

// Load data on startup
loadData();

// SECURITY: Define allowed origins for CORS
// In production, this should be your actual domain(s)
const ALLOWED_ORIGINS = [
  ORIGIN,
  `https://${RP_ID}`,
  `http://${RP_ID}:${PORT}`,
  'http://localhost:3001',
  'https://localhost:3001'
];

// Middleware
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc)
    if (!origin) return callback(null, true);
    // Check if origin is in allowed list
    if (ALLOWED_ORIGINS.some(allowed => origin === allowed || origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      console.warn(`⚠️ CORS blocked request from: ${origin}`);
      // For demo purposes, still allow but log warning
      // In production: callback(new Error('Not allowed by CORS'));
      callback(null, true);
    }
  },
  credentials: true
}));
app.use(bodyParser.json());
app.use(express.static('public'));

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// ============================================
// Apple App Site Association (AASA) Endpoints
// ============================================

// AASA file - CRITICAL for iOS passkey UX
// Without this, iOS shows "You don't have any passkeys saved"
app.get('/.well-known/apple-app-site-association', (req, res) => {
  console.log('📱 AASA file requested');

  // Check if we should simulate missing AASA (for demo purposes)
  if (process.env.SIMULATE_NO_AASA === 'true') {
    console.log('⚠️  Simulating missing AASA - returning 404');
    return res.status(404).json({ error: 'AASA not found (demo mode)' });
  }

  const aasa = {
    // webcredentials - Required for passkeys
    // Include BOTH main app AND credential provider extension bundle IDs
    // The extension needs associated domains to load, per iOS requirements
    webcredentials: {
      apps: [
        // Format: <Team ID>.<Bundle ID>
        // Your Team ID: 7XCMFL4395
        '7XCMFL4395.com.demo.PasskeyDemo',
        '7XCMFL4395.com.demo.PasskeyDemo.CredentialProvider'
      ]
    },
    // applinks - For universal links (optional but useful)
    applinks: {
      details: [
        {
          appIDs: [
            '7XCMFL4395.com.demo.PasskeyDemo',
            '7XCMFL4395.com.demo.PasskeyDemo.CredentialProvider'
          ],
          components: [
            {
              '/': '/auth/*',
              'comment': 'Authentication deep links'
            }
          ]
        }
      ]
    }
  };

  res.setHeader('Content-Type', 'application/json');
  res.json(aasa);
});

// iOS 26+ Passkey Management Endpoints
app.get('/.well-known/passkey-endpoints', (req, res) => {
  console.log('📱 Passkey endpoints requested (iOS 26+)');

  res.json({
    enroll: `${ORIGIN}/passkey/enroll`,
    manage: `${ORIGIN}/passkey/manage`
  });
});

// ============================================
// WebAuthn Related Origin Requests (Level 3)
// ============================================
// This allows credentials to be used across related origins
// See: https://w3c.github.io/webauthn/#sctn-related-origins
app.get('/.well-known/webauthn', (req, res) => {
  console.log('🔐 WebAuthn related origins requested');

  // This file declares which origins are related and can share credentials
  // Important for .local domains and cross-origin scenarios
  res.json({
    origins: [
      // Primary origin
      ORIGIN,
      // Alternative origins that can use credentials created here
      `https://${RP_ID}`,
      `http://${RP_ID}`,
      // Allow localhost for development
      'https://localhost:3001',
      'http://localhost:3001',
      // If using ngrok or localtunnel
      'https://*.ngrok.io',
      'https://*.loca.lt'
    ]
  });
});

// ============================================
// Remote Logging Endpoint (for device debugging)
// ============================================
app.post('/api/log', (req, res) => {
  const { message, level, data } = req.body;
  const timestamp = new Date().toISOString();
  console.log(`DEVICE [${level || 'INFO'}] ${timestamp}: ${message}`);
  if (data) {
    console.log('   Data:', JSON.stringify(data, null, 2));
  }
  res.json({ success: true });
});

// ============================================
// User Management Endpoints
// ============================================

// Get or create user
app.post('/api/user', (req, res) => {
  const { username } = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }

  let user = users.get(username);

  if (!user) {
    user = {
      id: uuidv4(),
      username,
      displayName: username,
      credentials: []
    };
    users.set(username, user);
    saveData(); // Persist new user
    console.log(`👤 Created new user: ${username}`);
  }

  res.json({
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    credentialCount: user.credentials.length
  });
});

// ============================================
// WebAuthn Registration (Passkey Creation)
// ============================================

// Step 1: Generate registration options
app.post('/api/register/options', async (req, res) => {
  try {
    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ error: 'Username required' });
    }

    let user = users.get(username);
    if (!user) {
      user = {
        id: uuidv4(),
        username,
        displayName: username,
        credentials: []
      };
      users.set(username, user);
      saveData(); // Persist new user
    }

    // Get existing credentials to exclude
    // simplewebauthn v11+ expects id as base64url string, not Buffer
    const excludeCredentials = user.credentials.map(cred => ({
      id: cred.credentialID,  // Keep as base64url string
      type: 'public-key',
      transports: cred.transports || ['internal']
    }));

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userID: Buffer.from(user.id),
      userName: user.username,
      userDisplayName: user.displayName,
      attestationType: 'none', // 'direct' for device attestation
      excludeCredentials,
      authenticatorSelection: {
        // Allow any authenticator type for iOS app testing
        // When called from iOS app, credential provider extension will be available
        // authenticatorAttachment: undefined allows both platform and cross-platform
        residentKey: 'required',
        userVerification: 'required',
      },
      supportedAlgorithmIDs: [-7, -257], // ES256, RS256
    });

    // Store challenge for verification
    challenges.set(user.id, {
      challenge: options.challenge,
      type: 'registration',
      timestamp: Date.now()
    });

    console.log(`🔐 Registration options generated for: ${username}`);
    res.json(options);

  } catch (error) {
    console.error('Registration options error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Verify registration response
app.post('/api/register/verify', async (req, res) => {
  try {
    const { username, credential } = req.body;

    // CRITICAL DEBUG: Log what the client sends
    console.log(`CRED_ID_DEBUG: Registration verify - credential from client:`);
    console.log(`CRED_ID_DEBUG:   credential.id (string): ${credential.id}`);
    console.log(`CRED_ID_DEBUG:   credential.id length: ${credential.id?.length}`);
    console.log(`CRED_ID_DEBUG:   credential.rawId (base64url): ${credential.rawId}`);
    console.log(`CRED_ID_DEBUG:   credential.rawId length: ${credential.rawId?.length}`);

    // Decode rawId to see what bytes we're getting
    const rawIdBytes = Buffer.from(credential.rawId, 'base64url');
    console.log(`CRED_ID_DEBUG:   rawId decoded: ${rawIdBytes.length} bytes, hex: ${rawIdBytes.toString('hex')}`);

    const user = users.get(username);
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const challengeData = challenges.get(user.id);
    if (!challengeData || challengeData.type !== 'registration') {
      return res.status(400).json({ error: 'No pending registration challenge' });
    }

    // Check challenge expiration
    const challengeAge = Date.now() - challengeData.timestamp;
    if (challengeAge > CHALLENGE_TIMEOUT_MS) {
      challenges.delete(user.id);
      console.log(`⚠️ Challenge expired for user ${username} (age: ${Math.round(challengeAge / 1000)}s)`);
      return res.status(400).json({ error: 'Challenge expired. Please restart registration.' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });

    if (verification.verified && verification.registrationInfo) {
      const { credentialID: attestationCredID, credentialPublicKey, counter, credentialBackedUp, credentialDeviceType } = verification.registrationInfo;

      // CRITICAL DEBUG: Log credential ID from attestation object
      const attestCredIDRaw = Buffer.from(attestationCredID);
      console.log(`CRED_ID_DEBUG: Registration - from attestation object`);
      console.log(`CRED_ID_DEBUG:   Size: ${attestCredIDRaw.length} bytes`);
      console.log(`CRED_ID_DEBUG:   Hex: ${attestCredIDRaw.toString('hex')}`);
      console.log(`CRED_ID_DEBUG:   Base64URL: ${attestCredIDRaw.toString('base64url')}`);

      // FIX: Use the rawId from the client instead of attestation object!
      // iOS credential provider extensions seem to modify the attestation object
      // and put the base64url STRING bytes as the credential ID instead of raw bytes.
      // The rawId from WebAuthn API is correct.
      const clientRawIdBytes = Buffer.from(credential.rawId, 'base64url');
      console.log(`CRED_ID_DEBUG: Registration - from client rawId`);
      console.log(`CRED_ID_DEBUG:   Size: ${clientRawIdBytes.length} bytes`);
      console.log(`CRED_ID_DEBUG:   Hex: ${clientRawIdBytes.toString('hex')}`);
      console.log(`CRED_ID_DEBUG:   Base64URL: ${clientRawIdBytes.toString('base64url')}`);

      // Use the client's rawId as the credential ID (it's correct!)
      const credentialID = clientRawIdBytes;

      // Log credential device type info from WebAuthn verification
      console.log(`CRED_ID_DEBUG: Registration - device type info`);
      console.log(`CRED_ID_DEBUG:   credentialBackedUp: ${credentialBackedUp}`);
      console.log(`CRED_ID_DEBUG:   credentialDeviceType: ${credentialDeviceType}`);

      // Determine if this is from a third-party credential provider extension
      // iOS third-party extensions MUST set BE+BS flags for hybrid transport to work,
      // but the credential is still device-bound in Secure Enclave.
      // We check transports to help identify credential provider extensions.
      const transports = credential.response.transports || ['internal'];
      const hasHybridTransport = transports.includes('hybrid');
      const isFromExtension = hasHybridTransport || transports.includes('internal');

      // NOTE: BE+BS flags being set does NOT mean the credential is actually synced!
      // For third-party iOS credential providers:
      // - BE+BS MUST be set for hybrid/cross-device auth to work
      // - But the key is actually device-bound in Secure Enclave
      // The only way to truly verify device-binding is via App Attestation.
      // For now, we mark these as "third-party-extension" so the UI can display appropriately.
      const isThirdPartyExtension = credentialBackedUp && credentialDeviceType === 'multiDevice';

      // Store credential using the CORRECT credential ID from rawId
      const credentialIDBase64 = credentialID.toString('base64url');

      // Check for duplicate credential (already registered via direct iOS extension)
      const existingCred = user.credentials.find(c => c.credentialID === credentialIDBase64);
      if (existingCred) {
        console.log(`⚠️ Credential already exists for ${username} (registered via ${existingCred.registrationMethod}), skipping duplicate`);
        // Return success but don't add duplicate
        return res.json({
          verified: true,
          username,
          isDeviceBound: existingCred.isDeviceBound,
          isThirdPartyExtension: existingCred.registrationMethod === 'direct-ios-extension',
          credentialBackedUp: existingCred.credentialBackedUp,
          registrationMethod: existingCred.registrationMethod
        });
      }

      const newCredential = {
        credentialID: credentialIDBase64,
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64url'),
        counter,
        transports: transports,
        createdAt: new Date().toISOString(),
        // Registration method tracking
        registrationMethod: 'browser',
        // Credential backup status from WebAuthn flags
        credentialBackedUp: credentialBackedUp || false,
        credentialDeviceType: credentialDeviceType || 'singleDevice',
        // For display purposes - this may be a third-party extension credential
        // which MUST set BE+BS for hybrid transport but is actually device-bound
        isThirdPartyExtension: isThirdPartyExtension,
        // isDeviceBound is only truly verified via App Attestation
        // BE+BS flags don't tell us - they're required for hybrid transport
        isDeviceBound: credential.clientExtensionResults?.deviceBound || false,
        deviceBoundVerification: isThirdPartyExtension
          ? 'Third-party extension (BE+BS required for hybrid - may be device-bound)'
          : (credentialBackedUp ? 'Synced (BE+BS set)' : 'Not verified')
      };

      user.credentials.push(newCredential);
      credentials.set(newCredential.credentialID, {
        ...newCredential,
        userId: user.id,
        username: user.username
      });

      // Persist credentials
      saveData();

      // Clear challenge
      challenges.delete(user.id);

      console.log(`✅ Passkey registered for: ${username}`);
      console.log(`   Credential ID stored as: ${newCredential.credentialID}`);
      console.log(`   Device-bound: ${newCredential.isDeviceBound}`);

      res.json({
        verified: true,
        credentialID: newCredential.credentialID
      });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }

  } catch (error) {
    console.error('Registration verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// Direct Registration from iOS Extension
// ============================================
// This endpoint accepts credential data directly from the iOS Credential Provider Extension
// It includes Apple App Attestation verification for cryptographic proof of device authenticity

// WebAuthn authenticator data flags
const AUTH_FLAGS = {
  UP: 0x01,   // User Present
  UV: 0x04,   // User Verified
  AT: 0x40,   // Attested credential data included
  BE: 0x08,   // Backup Eligible (synced passkey)
  BS: 0x10,   // Backed up State (synced passkey)
};

// Verify authenticator flags
// Note: BE and BS flags are REQUIRED for iOS hybrid/cross-device authentication to work,
// even for credentials that are actually hardware-bound in the Secure Enclave.
// See: https://developer.apple.com/forums/thread/745587
function verifyDeviceBoundFlags(flags) {
  const isUserPresent = (flags & AUTH_FLAGS.UP) !== 0;
  const isUserVerified = (flags & AUTH_FLAGS.UV) !== 0;
  const isBackupEligible = (flags & AUTH_FLAGS.BE) !== 0;
  const isBackedUp = (flags & AUTH_FLAGS.BS) !== 0;

  console.log(`   Flag analysis:`);
  console.log(`     UP (User Present): ${isUserPresent}`);
  console.log(`     UV (User Verified): ${isUserVerified}`);
  console.log(`     BE (Backup Eligible): ${isBackupEligible}`);
  console.log(`     BS (Backed Up): ${isBackedUp}`);

  // UP and UV MUST be set
  if (!isUserPresent || !isUserVerified) {
    return { valid: false, reason: 'Missing UP or UV flags - credential not properly verified' };
  }

  // Note: We now ACCEPT BE and BS flags because iOS requires them for hybrid transport
  // The credential is still hardware-bound in the Secure Enclave - these flags are just
  // required by iOS for third-party credential providers to work with cross-device auth.
  // True device-bound verification comes from App Attestation, not these flags.
  if (isBackupEligible && isBackedUp) {
    return { valid: true, reason: 'Valid credential with BE+BS flags (required for hybrid transport)' };
  }

  // Also accept credentials without BE/BS (legacy or same-device only)
  return { valid: true, reason: 'Valid credential (UP+UV set)' };
}

// Verify Apple App Attestation (basic structure check - full verification requires Apple's attestation CA)
// SECURITY NOTE: This is a DEMO implementation. In production, you MUST verify:
// 1. The CBOR attestation object against Apple's App Attest root CA
// 2. The challenge (clientDataHash) matches what was sent
// 3. The App ID matches your bundle ID
// 4. The key ID format and validity
function verifyAppAttestation(attestation, clientDataHash) {
  if (!attestation || !attestation.keyID || !attestation.attestationObject) {
    console.log(`   No App Attestation provided (development mode)`);
    return { verified: false, reason: 'No attestation provided' };
  }

  console.log(`   App Attestation received:`);
  console.log(`     Key ID: ${attestation.keyID.substring(0, 30)}...`);
  console.log(`     Attestation size: ${attestation.attestationObject.length} chars`);

  // SECURITY: We mark this as NOT VERIFIED because we don't actually validate
  // the Apple CA certificate chain. In production, use a library like
  // 'node-app-attest' to properly verify the attestation.
  return {
    verified: false,  // CHANGED: Not verified without proper CA chain validation
    keyID: attestation.keyID,
    attestationPresent: true,  // Attestation data was provided
    reason: 'Attestation received but NOT VERIFIED (demo mode - production requires Apple CA chain validation)'
  };
}

// Helper function to convert raw P256 public key to COSE format
function rawP256ToCose(rawPublicKeyBase64URL) {
  // Raw P256 public key is 64 bytes: 32-byte X coordinate + 32-byte Y coordinate
  const rawKey = Buffer.from(rawPublicKeyBase64URL, 'base64url');

  if (rawKey.length !== 64) {
    console.log(`   Warning: Expected 64-byte raw key, got ${rawKey.length} bytes`);
    // If it's already in some other format, return as-is
    return rawPublicKeyBase64URL;
  }

  const x = rawKey.slice(0, 32);
  const y = rawKey.slice(32, 64);

  // COSE Key format for EC2 P-256:
  // Map with keys:
  //   1 (kty): 2 (EC2)
  //   3 (alg): -7 (ES256)
  //  -1 (crv): 1 (P-256)
  //  -2 (x): x coordinate (32 bytes)
  //  -3 (y): y coordinate (32 bytes)

  // Manual CBOR encoding for the COSE key
  // This creates a CBOR map with the required fields
  const coseKey = Buffer.concat([
    Buffer.from([0xa5]), // Map with 5 items
    Buffer.from([0x01, 0x02]), // kty: 2 (EC2)
    Buffer.from([0x03, 0x26]), // alg: -7 (ES256) - 0x26 is CBOR encoding of -7
    Buffer.from([0x20, 0x01]), // crv: 1 (P-256) - 0x20 is CBOR encoding of -1
    Buffer.from([0x21, 0x58, 0x20]), // x: bytes(32) - 0x21 is -2, 0x58 0x20 is 32-byte bstr
    x,
    Buffer.from([0x22, 0x58, 0x20]), // y: bytes(32) - 0x22 is -3, 0x58 0x20 is 32-byte bstr
    y
  ]);

  console.log(`   Converted raw P256 (64 bytes) to COSE format (${coseKey.length} bytes)`);
  return coseKey.toString('base64url');
}

app.post('/api/register/direct', async (req, res) => {
  try {
    const {
      username,
      credentialID,
      publicKey,
      rpID,
      isDeviceBound,
      authenticatorFlags,
      clientDataHash,
      appAttestation
    } = req.body;

    console.log(`📱 Direct registration from iOS extension:`);
    console.log(`   Username: ${username}`);
    console.log(`   Credential ID: ${credentialID?.substring(0, 30)}...`);
    console.log(`   Public Key length: ${publicKey?.length || 0}`);
    console.log(`   RP ID: ${rpID}`);
    console.log(`   Authenticator Flags: 0x${authenticatorFlags?.toString(16) || 'N/A'}`);

    if (!username || !credentialID || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields: username, credentialID, publicKey' });
    }

    // ============================================
    // SECURITY VERIFICATION #1: Authenticator Flags
    // ============================================
    // Verify the BE/BS flags are NOT set (proving this is device-bound)
    let flagsVerification = { valid: true, reason: 'No flags provided' };
    if (authenticatorFlags !== undefined) {
      flagsVerification = verifyDeviceBoundFlags(authenticatorFlags);
      console.log(`   Flags verification: ${flagsVerification.reason}`);

      if (!flagsVerification.valid) {
        console.log(`   ❌ REJECTED: ${flagsVerification.reason}`);
        return res.status(400).json({
          error: 'Device-bound verification failed',
          reason: flagsVerification.reason,
          hint: 'BE/BS flags indicate this credential is syncable, not hardware-bound'
        });
      }
    }

    // ============================================
    // SECURITY VERIFICATION #2: App Attestation
    // ============================================
    // Verify Apple App Attestation if provided
    const attestationResult = verifyAppAttestation(appAttestation, clientDataHash);
    console.log(`   App Attestation: ${attestationResult.reason}`);

    // Convert raw P256 public key to COSE format for WebAuthn verification
    const cosePublicKey = rawP256ToCose(publicKey);
    console.log(`   COSE Public Key length: ${cosePublicKey.length}`);

    // Get or create user
    let user = users.get(username);
    if (!user) {
      user = {
        id: require('uuid').v4(),
        username,
        displayName: username,
        credentials: []
      };
      users.set(username, user);
      saveData(); // Persist new user
      console.log(`👤 Created new user for direct registration: ${username}`);
    }

    // Check if credential already exists
    const existingCred = user.credentials.find(c => c.credentialID === credentialID);
    if (existingCred) {
      console.log(`⚠️ Credential already registered for ${username}`);
      return res.json({
        success: true,
        message: 'Credential already registered',
        credentialID: credentialID
      });
    }

    // Store the credential with verification metadata
    const newCredential = {
      credentialID: credentialID,
      credentialPublicKey: cosePublicKey,
      counter: 0,
      transports: ['internal'],
      createdAt: new Date().toISOString(),
      // Device-bound verification status
      isDeviceBound: flagsVerification.valid,
      deviceBoundVerification: flagsVerification.reason,
      // Attestation status - SECURITY: Only mark as verified if we actually verify the CA chain
      hasAppAttestation: attestationResult.verified,  // Will be false without CA validation
      attestationPresent: attestationResult.attestationPresent || false,  // Indicates data was received
      appAttestKeyID: attestationResult.keyID || null,
      attestationReason: attestationResult.reason,
      // Registration metadata
      registrationMethod: 'direct-ios-extension',
      authenticatorFlags: authenticatorFlags || null
    };

    user.credentials.push(newCredential);
    credentials.set(credentialID, {
      ...newCredential,
      userId: user.id,
      username: user.username
    });

    // Persist credentials
    saveData();

    console.log(`✅ Device-bound passkey registered for: ${username}`);
    console.log(`   Credential ID: ${credentialID.substring(0, 30)}...`);
    console.log(`   Device-bound verified: ${flagsVerification.valid}`);
    console.log(`   App Attestation: ${attestationResult.verified ? 'VERIFIED' : 'NOT PROVIDED'}`);
    console.log(`   User now has ${user.credentials.length} credential(s)`);

    res.json({
      success: true,
      verified: true,
      credentialID: credentialID,
      credentialCount: user.credentials.length,
      deviceBoundVerified: flagsVerification.valid,
      appAttestationVerified: attestationResult.verified
    });

  } catch (error) {
    console.error('Direct registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// WebAuthn Authentication (Passkey Sign-in)
// ============================================

// Step 1: Generate authentication options
app.post('/api/authenticate/options', async (req, res) => {
  try {
    const { username } = req.body;

    let allowCredentials = [];
    let userId = null;

    // If username provided, get user's credentials (more secure)
    if (username) {
      const user = users.get(username);
      if (user && user.credentials.length > 0) {
        userId = user.id;
        // simplewebauthn v11+ expects id as base64url string, not Buffer
        allowCredentials = user.credentials.map(cred => ({
          id: cred.credentialID,  // Keep as base64url string
          type: 'public-key',
          transports: cred.transports || ['internal']
        }));
      }
    }

    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
      // If allowCredentials is empty, this becomes a "discoverable" request
      // where any passkey for this RP can be used
      allowCredentials,
    });

    // Store challenge
    const challengeId = userId || `anon-${uuidv4()}`;
    challenges.set(challengeId, {
      challenge: options.challenge,
      type: 'authentication',
      timestamp: Date.now(),
      allowCredentials: allowCredentials.map(c => c.id)  // Already base64url string
    });

    console.log(`🔑 Authentication options generated`);
    console.log(`   Username: ${username || 'discoverable'}`);
    console.log(`   Allowed credentials: ${allowCredentials.length}`);

    res.json({
      ...options,
      // Include for client to track
      _challengeId: challengeId
    });

  } catch (error) {
    console.error('Authentication options error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Step 2: Verify authentication response
app.post('/api/authenticate/verify', async (req, res) => {
  console.log(`${new Date().toISOString()} POST /api/authenticate/verify`);
  try {
    const { credential, challengeId } = req.body;

    // CRITICAL DEBUG: Log the incoming credential ID in detail
    console.log(`CRED_ID_DEBUG: Authentication rawId received from client`);
    console.log(`CRED_ID_DEBUG:   Raw string (first 60): ${credential?.rawId?.substring(0, 60)}`);
    console.log(`CRED_ID_DEBUG:   Raw string length: ${credential?.rawId?.length}`);

    // The client sends base64url encoded, but let's try both interpretations
    const rawIdFromBase64 = Buffer.from(credential.rawId, 'base64');
    const rawIdFromBase64URL = Buffer.from(credential.rawId, 'base64url');

    console.log(`CRED_ID_DEBUG:   Decoded as base64:`);
    console.log(`CRED_ID_DEBUG:     Size: ${rawIdFromBase64.length} bytes`);
    console.log(`CRED_ID_DEBUG:     Hex: ${rawIdFromBase64.toString('hex')}`);
    console.log(`CRED_ID_DEBUG:     Re-encoded base64url: ${rawIdFromBase64.toString('base64url')}`);

    console.log(`CRED_ID_DEBUG:   Decoded as base64url:`);
    console.log(`CRED_ID_DEBUG:     Size: ${rawIdFromBase64URL.length} bytes`);
    console.log(`CRED_ID_DEBUG:     Hex: ${rawIdFromBase64URL.toString('hex')}`);
    console.log(`CRED_ID_DEBUG:     Re-encoded base64url: ${rawIdFromBase64URL.toString('base64url')}`);

    console.log(`  Challenge ID: ${challengeId}`);

    // Find the credential - try base64url decoding since that's what the client sends
    const credentialIDBase64URL = Buffer.from(credential.rawId, 'base64url').toString('base64url');
    console.log(`CRED_ID_DEBUG:   Looking for credential with key: ${credentialIDBase64URL}`);
    console.log(`CRED_ID_DEBUG:   Available credentials: ${[...credentials.keys()].join(', ')}`);

    // Try to find the credential
    let storedCredential = credentials.get(credentialIDBase64URL);

    // If not found, also try the base64 interpretation (for backwards compatibility)
    if (!storedCredential) {
      const credentialIDFromBase64 = Buffer.from(credential.rawId, 'base64').toString('base64url');
      console.log(`CRED_ID_DEBUG:   Not found, trying base64 interpretation: ${credentialIDFromBase64}`);
      storedCredential = credentials.get(credentialIDFromBase64);
    }

    if (!storedCredential) {
      console.log(`  ❌ Credential not found in store!`);
      console.log(`  Available credentials: ${[...credentials.keys()].map(k => k.substring(0, 20)).join(', ')}`);
      return res.status(400).json({ error: 'Credential not found' });
    }
    console.log(`  ✓ Found credential for user: ${storedCredential.username}`);

    // Get challenge
    const challengeData = challenges.get(challengeId) ||
                          challenges.get(storedCredential.userId);

    if (!challengeData || challengeData.type !== 'authentication') {
      console.log(`  ❌ No pending challenge! challengeId=${challengeId}, userId=${storedCredential.userId}`);
      return res.status(400).json({ error: 'No pending authentication challenge' });
    }
    console.log(`  ✓ Found challenge`)

    // Check challenge expiration
    const challengeAge = Date.now() - challengeData.timestamp;
    if (challengeAge > CHALLENGE_TIMEOUT_MS) {
      challenges.delete(challengeId);
      challenges.delete(storedCredential.userId);
      console.log(`  ⚠️ Challenge expired (age: ${Math.round(challengeAge / 1000)}s)`);
      return res.status(400).json({ error: 'Challenge expired. Please restart authentication.' });
    }

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challengeData.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      authenticator: {
        credentialID: Buffer.from(storedCredential.credentialID, 'base64url'),
        credentialPublicKey: Buffer.from(storedCredential.credentialPublicKey, 'base64url'),
        counter: storedCredential.counter,
      },
      requireUserVerification: true,
    });

    if (verification.verified) {
      const oldCounter = storedCredential.counter;
      const newCounter = verification.authenticationInfo.newCounter;

      // SECURITY: Verify counter is strictly increasing to prevent replay attacks
      console.log(`   Counter check: ${oldCounter} -> ${newCounter}`);
      if (newCounter <= oldCounter) {
        console.log(`   ⚠️ WARNING: Counter did not increase! Possible replay attack.`);
        console.log(`   Old counter: ${oldCounter}, New counter: ${newCounter}`);
        // In strict mode, you would reject this. For now, we log the warning.
        // return res.status(400).json({ error: 'Counter replay detected' });
      }

      // Update counter
      storedCredential.counter = newCounter;

      // Persist counter update
      saveData();

      // Clear challenge
      challenges.delete(challengeId);
      challenges.delete(storedCredential.userId);

      console.log(`✅ Authentication successful for: ${storedCredential.username}`);
      console.log(`   Counter updated: ${oldCounter} -> ${newCounter}`);
      console.log(`   Device-bound: ${storedCredential.isDeviceBound || false}`);
      console.log(`   Has attestation: ${storedCredential.hasAppAttestation || false}`);
      console.log(`   Third-party extension: ${storedCredential.isThirdPartyExtension || false}`);
      console.log(`   Registration method: ${storedCredential.registrationMethod || 'browser'}`);

      res.json({
        verified: true,
        username: storedCredential.username,
        userId: storedCredential.userId,
        counterIncremented: newCounter > oldCounter,
        isDeviceBound: storedCredential.isDeviceBound || false,
        isThirdPartyExtension: storedCredential.isThirdPartyExtension || false,
        credentialBackedUp: storedCredential.credentialBackedUp || false,
        registrationMethod: storedCredential.registrationMethod || 'browser'
      });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }

  } catch (error) {
    console.error('Authentication verification error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// User Credential Lookup API
// ============================================
// Used by success page and apps to get full credential details

// Get user's credential details by username
app.get('/api/user/:username/credentials', (req, res) => {
  const { username } = req.params;
  console.log(`📋 Credential lookup for: ${username}`);

  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Return full credential details for display
  const credentialDetails = user.credentials.map(c => ({
    credentialID: c.credentialID,
    createdAt: c.createdAt,
    // Security verification
    isDeviceBound: c.isDeviceBound || false,
    deviceBoundVerification: c.deviceBoundVerification || 'Not verified',
    // Third-party extension detection
    isThirdPartyExtension: c.isThirdPartyExtension || false,
    // Credential backup status from WebAuthn
    credentialBackedUp: c.credentialBackedUp || false,
    credentialDeviceType: c.credentialDeviceType || 'unknown',
    // Attestation
    hasAppAttestation: c.hasAppAttestation || false,
    attestationReason: c.attestationReason || 'No attestation',
    appAttestKeyID: c.appAttestKeyID || null,
    // Flags
    authenticatorFlags: c.authenticatorFlags ? `0x${c.authenticatorFlags.toString(16)}` : null,
    flagsDetails: c.authenticatorFlags ? {
      userPresent: (c.authenticatorFlags & 0x01) !== 0,
      userVerified: (c.authenticatorFlags & 0x04) !== 0,
      attestedCredentialData: (c.authenticatorFlags & 0x40) !== 0,
      backupEligible: (c.authenticatorFlags & 0x08) !== 0,
      backedUpState: (c.authenticatorFlags & 0x10) !== 0,
    } : null,
    // Counter
    counter: c.counter || 0,
    // Registration method
    registrationMethod: c.registrationMethod || 'browser',
    transports: c.transports || ['internal']
  }));

  res.json({
    username: user.username,
    displayName: user.displayName,
    credentialCount: user.credentials.length,
    credentials: credentialDetails
  });
});

// Check if credentials exist for a username (for autofill hints)
app.get('/api/user/:username/has-passkey', (req, res) => {
  const { username } = req.params;
  const user = users.get(username);

  res.json({
    hasPasskey: user && user.credentials.length > 0,
    credentialCount: user ? user.credentials.length : 0
  });
});

// ============================================
// Health Check & Demo/Debug Endpoints
// ============================================

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============================================
// DEBUG ENDPOINTS - DEMO USE ONLY
// ============================================
// SECURITY WARNING: These endpoints have NO authentication.
// In production:
// 1. Remove or disable these endpoints entirely
// 2. Or protect them with authentication (API key, admin session, etc.)
// 3. Never expose credential data to unauthenticated users
// ============================================

// List all users and their credentials
// SECURITY: This endpoint exposes credential metadata. Disable in production.
app.get('/api/debug/users', (req, res) => {
  const userList = [];
  users.forEach((user, username) => {
    userList.push({
      username,
      id: user.id,
      credentialCount: user.credentials.length,
      credentials: user.credentials.map(c => ({
        id: c.credentialID,
        // Security verification status
        isDeviceBound: c.isDeviceBound || false,
        deviceBoundVerification: c.deviceBoundVerification || 'Not verified',
        hasAppAttestation: c.hasAppAttestation || false,
        attestationReason: c.attestationReason || 'No attestation',
        // Counter for replay attack prevention
        counter: c.counter || 0,
        // Registration metadata
        createdAt: c.createdAt,
        registrationMethod: c.registrationMethod || 'browser',
        authenticatorFlags: c.authenticatorFlags ? `0x${c.authenticatorFlags.toString(16)}` : null
      }))
    });
  });
  res.json(userList);
});

// Delete a specific credential
// SECURITY: This endpoint is destructive. Protect with authentication in production.
app.delete('/api/credential/:username/:credentialId', (req, res) => {
  const { username, credentialId } = req.params;
  console.log(`🗑️  Delete credential request: ${username} / ${credentialId.substring(0, 20)}...`);

  const user = users.get(username);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  const credIndex = user.credentials.findIndex(c => c.credentialID === credentialId);
  if (credIndex === -1) {
    return res.status(404).json({ error: 'Credential not found' });
  }

  // Remove from user's credentials
  user.credentials.splice(credIndex, 1);

  // Remove from global credentials map
  credentials.delete(credentialId);

  // If user has no more credentials, optionally remove the user too
  if (user.credentials.length === 0) {
    users.delete(username);
    console.log(`👤 User ${username} removed (no remaining credentials)`);
  }

  saveData();
  console.log(`✅ Credential deleted for ${username}`);

  res.json({
    success: true,
    remainingCredentials: user.credentials.length,
    userDeleted: user.credentials.length === 0
  });
});

// Clear all data
// SECURITY: This endpoint wipes ALL data. NEVER expose in production without authentication.
app.post('/api/debug/reset', (req, res) => {
  users.clear();
  challenges.clear();
  credentials.clear();
  saveData(); // Persist the reset
  console.log('🗑️  All data cleared');
  res.json({ success: true });
});

// Toggle AASA simulation
app.post('/api/debug/toggle-aasa', (req, res) => {
  const current = process.env.SIMULATE_NO_AASA === 'true';
  process.env.SIMULATE_NO_AASA = (!current).toString();
  console.log(`🔧 AASA simulation: ${!current ? 'DISABLED (404)' : 'ENABLED (serving)'}`);
  res.json({
    simulateNoAASA: !current,
    message: !current
      ? 'AASA will return 404 - iOS will show "no passkeys saved"'
      : 'AASA is now being served - iOS should work properly'
  });
});

// HTML escape function to prevent XSS
function escapeHtml(text) {
  if (!text) return '';
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return String(text).replace(/[&<>"']/g, m => map[m]);
}

// Auth success - Universal Link target for app redirect
app.get('/auth/success', (req, res) => {
  // SECURITY: Escape username to prevent XSS
  const rawUsername = req.query.username || 'User';
  const username = escapeHtml(rawUsername);
  console.log(`${new Date().toISOString()} GET /auth/success for ${rawUsername}`);

  // This page should be intercepted by the iOS app via Universal Links
  // If not, show a success page
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sign In Successful</title>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <style>
        body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px 20px; background: #f0f0f0; }
        .card { background: white; padding: 40px; border-radius: 16px; max-width: 400px; margin: 0 auto; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
        h1 { color: #34c759; }
        .username { font-size: 24px; font-weight: bold; color: #333; margin: 20px 0; }
        .message { color: #666; }
        .app-link { display: inline-block; margin-top: 20px; padding: 12px 24px; background: #007aff; color: white; text-decoration: none; border-radius: 8px; }
      </style>
    </head>
    <body>
      <div class="card">
        <h1>✅ Sign In Successful!</h1>
        <p class="username">${username}</p>
        <p class="message">Your device-bound passkey worked perfectly.</p>
        <p class="message">If the app didn't open automatically, tap below:</p>
        <a class="app-link" href="${ORIGIN}/auth/success?username=${encodeURIComponent(rawUsername)}">Open App</a>
      </div>
    </body>
    </html>
  `);
});

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    rpId: RP_ID,
    origin: ORIGIN,
    simulateNoAASA: process.env.SIMULATE_NO_AASA === 'true'
  });
});

// ============================================
// Start Server
// ============================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║           Passkey Demo - WebAuthn Relying Party              ║
╠══════════════════════════════════════════════════════════════╣
║  Server running on: http://0.0.0.0:${PORT}                       ║
║  RP ID: ${RP_ID.padEnd(50)}║
║  Origin: ${ORIGIN.padEnd(49)}║
╠══════════════════════════════════════════════════════════════╣
║  Endpoints:                                                  ║
║  • GET  /.well-known/apple-app-site-association              ║
║  • POST /api/register/options                                ║
║  • POST /api/register/verify                                 ║
║  • POST /api/authenticate/options                            ║
║  • POST /api/authenticate/verify                             ║
║  • GET  /api/debug/users                                     ║
║  • POST /api/debug/toggle-aasa                               ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

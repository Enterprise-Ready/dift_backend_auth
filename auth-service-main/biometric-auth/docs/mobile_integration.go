/* ============================================================
   MOBILE BIOMETRIC INTEGRATION GUIDE
   Android Keystore + iOS Secure Enclave
   ============================================================ */

// ═══════════════════════════════════════════════════════════
// ANDROID — StrongBox / Android Keystore (Kotlin)
// ═══════════════════════════════════════════════════════════

/*
STEP 1: Generate key pair in Android Keystore (hardware-backed)

```kotlin
fun generateBiometricKey(keyAlias: String) {
    val keyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
    )

    val builder = KeyGenParameterSpec.Builder(
        keyAlias,
        KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
    )
        .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")) // P-256
        .setDigests(KeyProperties.DIGEST_SHA256)
        // 🔑 REQUIRE biometric authentication to use key
        .setUserAuthenticationRequired(true)
        // Use StrongBox (Titan M chip) if available
        .setIsStrongBoxBacked(true)
        // Invalidate key if new biometric is enrolled
        .setInvalidatedByBiometricEnrollment(true)
        // No timeout — fresh auth required every use
        .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)

    keyPairGenerator.initialize(builder.build())
    keyPairGenerator.generateKeyPair()
}
```

STEP 2: Export public key (PEM) to send to server during enrollment

```kotlin
fun getPublicKeyPEM(keyAlias: String): String {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val publicKey = keyStore.getCertificate(keyAlias).publicKey
    val encoded = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
    return "-----BEGIN PUBLIC KEY-----\n$encoded\n-----END PUBLIC KEY-----"
}
```

STEP 3: Sign challenge payload with biometric authentication

```kotlin
fun signChallenge(
    keyAlias: String,
    nonce: String,
    deviceID: String,
    action: String,
    timestamp: Long,
    biometricPrompt: BiometricPrompt,
    onSuccess: (String) -> Unit,
    onError: (String) -> Unit
) {
    val payload = "$nonce.$deviceID.$action.$timestamp"
    val digest = MessageDigest.getInstance("SHA-256").digest(payload.toByteArray())

    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val privateKey = keyStore.getKey(keyAlias, null) as PrivateKey

    val signature = Signature.getInstance("SHA256withECDSA").apply {
        initSign(privateKey)
    }

    // CryptoObject binds signature to biometric auth
    val cryptoObject = BiometricPrompt.CryptoObject(signature)

    biometricPrompt.authenticate(
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Verify your identity")
            .setSubtitle("Use fingerprint or face to authenticate")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .build(),
        cryptoObject
    )

    // In callback:
    // val sig = it.cryptoObject?.signature!!
    // sig.update(digest)
    // val rawSig = sig.sign()  // DER encoded — convert to raw R||S for ES256
    // val base64Sig = Base64.encodeToString(derToRawES256(rawSig), Base64.URL_SAFE or Base64.NO_PADDING)
    // onSuccess(base64Sig)
}

// Convert DER signature to raw R||S bytes (ES256 format)
fun derToRawES256(der: ByteArray): ByteArray {
    val seq = ASN1Primitive.fromByteArray(der) as DLSequence
    val r = (seq.getObjectAt(0) as ASN1Integer).positiveValue.toByteArray().takeLast(32)
    val s = (seq.getObjectAt(1) as ASN1Integer).positiveValue.toByteArray().takeLast(32)
    return (r + s).toByteArray()
}
```

STEP 4: Root / integrity detection

```kotlin
fun isDeviceCompromised(): Boolean {
    return RootBeer(context).isRooted || // RootBeer library
           isEmulator() ||
           isDebuggable() ||
           isMagiskDetected()
}

// Also use Google Play Integrity API (replaces SafetyNet):
suspend fun getIntegrityToken(): String {
    val integrityManager = IntegrityManagerFactory.create(context)
    val request = StandardIntegrityManager.StandardIntegrityTokenRequest.builder()
        .setRequestHash(hashOfRequest)
        .build()
    return integrityManager.requestIntegrityToken(request).await().token()
}
```

STEP 5: Store refresh token in EncryptedSharedPreferences

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val sharedPreferences = EncryptedSharedPreferences.create(
    context,
    "auth_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)
sharedPreferences.edit().putString("refresh_token", token).apply()
```
*/

// ═══════════════════════════════════════════════════════════
// iOS — Secure Enclave + LocalAuthentication (Swift)
// ═══════════════════════════════════════════════════════════

/*
STEP 1: Generate key pair in Secure Enclave

```swift
func generateBiometricKey(tag: String) throws -> SecKey {
    let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet], // invalidate on new biometric
        nil
    )!

    let attributes: [String: Any] = [
        kSecAttrKeyType as String:            kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String:      256,
        kSecAttrTokenID as String:            kSecAttrTokenIDSecureEnclave,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String:    true,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
            kSecAttrAccessControl as String:  access
        ]
    ]

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        throw error!.takeRetainedValue() as Error
    }
    return privateKey
}
```

STEP 2: Export public key PEM

```swift
func getPublicKeyPEM(tag: String) throws -> String {
    let privateKey = try loadKey(tag: tag)
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        throw BiometricError.keyNotFound
    }
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
        throw error!.takeRetainedValue() as Error
    }
    // data is 65 bytes (04 + X + Y) — wrap in SubjectPublicKeyInfo DER + PEM
    let spkiHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
    ])
    let derKey = spkiHeader + data
    let b64 = derKey.base64EncodedString(options: .lineLength64Characters)
    return "-----BEGIN PUBLIC KEY-----\n\(b64)\n-----END PUBLIC KEY-----"
}
```

STEP 3: Sign with biometric-protected key

```swift
func signChallenge(
    tag: String,
    nonce: String, deviceID: String, action: String, timestamp: Int64
) throws -> String {
    let payload = "\(nonce).\(deviceID).\(action).\(timestamp)"
    let payloadData = payload.data(using: .utf8)!
    let digest = SHA256.hash(data: payloadData)
    let digestData = Data(digest)

    let privateKey = try loadKey(tag: tag)
    // Secure Enclave triggers FaceID/TouchID automatically here
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureDigestX962SHA256,
        digestData as CFData,
        &error
    ) as Data? else {
        throw error!.takeRetainedValue() as Error
    }

    // Convert DER to raw R||S for ES256
    let raw = try derToRawES256(signature)
    return raw.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
```

STEP 4: Jailbreak detection

```swift
func isJailbroken() -> Bool {
    #if targetEnvironment(simulator)
    return false
    #else
    let paths = [
        "/Applications/Cydia.app",
        "/private/var/lib/apt/",
        "/usr/bin/ssh",
        "/bin/bash"
    ]
    return paths.contains { FileManager.default.fileExists(atPath: $0) }
        || canOpenCydiaURL()
        || canWriteOutsideSandbox()
    #endif
}
```

STEP 5: Store tokens in Keychain (NOT UserDefaults)

```swift
func storeToken(_ token: String, key: String) throws {
    let data = token.data(using: .utf8)!
    let query: [String: Any] = [
        kSecClass as String:             kSecClassGenericPassword,
        kSecAttrAccount as String:       key,
        kSecValueData as String:         data,
        kSecAttrAccessible as String:    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAttrSynchronizable as String: false // never sync to iCloud
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw KeychainError.storeFailed(status) }
}
```
*/

// ═══════════════════════════════════════════════════════════
// API FLOW SEQUENCE
// ═══════════════════════════════════════════════════════════

/*
┌─────────────────────────────────────────────────────────────┐
│                    ENROLLMENT FLOW                           │
└─────────────────────────────────────────────────────────────┘

Mobile                          Backend
  │                                │
  │── POST /auth/login ───────────▶│  1. Login with password+OTP
  │◀─ {access_token, refresh_token}│
  │                                │
  │── POST /biometric/challenge ──▶│  2. Request enrollment challenge
  │   {action: "enroll"}           │
  │◀─ {challenge_id, nonce, hmac} ─│
  │                                │
  │  [Generate ECDSA key in        │
  │   Keystore/Secure Enclave]     │
  │  [Trigger biometric scan]      │
  │  [Sign SHA256(nonce.device.    │
  │   enroll.timestamp)]           │
  │                                │
  │── POST /biometric/enroll ─────▶│  3. Send public key + signature
  │   {challenge_id, public_key,   │
  │    signature, timestamp,       │
  │    attestation_data}           │
  │◀─ {status: "enrolled"} ────────│

┌─────────────────────────────────────────────────────────────┐
│              SUBSEQUENT AUTH FLOW                            │
└─────────────────────────────────────────────────────────────┘

Mobile                          Backend
  │                                │
  │── POST /biometric/challenge ──▶│  1. Get fresh nonce
  │◀─ {challenge_id, nonce} ───────│
  │                                │
  │  [Trigger biometric scan]      │
  │  [Sign with Keystore key]      │
  │                                │
  │── POST /biometric/authenticate▶│  2. Send signature
  │◀─ {access_token, refresh_token}│  3. Backend verifies signature
  │                                │     checks device status
  │                                │     validates timestamp drift
  │                                │     issues new token pair

┌─────────────────────────────────────────────────────────────┐
│                 STEP-UP FLOW (Payment)                       │
└─────────────────────────────────────────────────────────────┘

Mobile                          Backend
  │                                │
  │── POST /biometric/challenge ──▶│  1. Get step-up challenge
  │   {action: "step_up"}          │
  │◀─ {challenge_id, nonce} ───────│
  │                                │
  │  [Show "Confirm payment"       │
  │   biometric prompt]            │
  │  [Sign with Keystore key]      │
  │                                │
  │── POST /payment/authorize ────▶│  2. Send step-up signature
  │   Authorization: Bearer <token>│
  │   {challenge_id, signature...} │
  │◀─ {step_up_token} ─────────────│  3. Short-lived 5min token
  │                                │
  │── POST /payment/execute ──────▶│  4. Use step-up token
  │   Authorization: Bearer        │     to authorize payment
  │             <step_up_token>    │
*/

package com.relay.emergency.crypto

import android.content.Context
import java.util.Base64
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * End-to-End Authenticated Encryption for RELAY emergency coordination.
 *
 * Cryptographic Architecture:
 * - Key Agreement: Curve25519 / X25519 Diffie-Hellman (RFC 7748) via Bouncy Castle.
 * - Key Derivation: HKDF-SHA256 (RFC 5869) extracting 256-bit AES symmetric key.
 * - Authenticated Cipher: AES-256-GCM (NIST SP 800-38D) with 128-bit authentication tag.
 * - Nonce: 12-byte unique cryptographic nonce generated via [SecureRandom].
 * - Authenticated Associated Data (AAD): Canonical binding of sender, recipient, packet ID, and timestamp.
 * - Peer Authentication: Encryption public keys are cryptographically bound and signed by the peer's Ed25519 identity key.
 */
object RelayE2EEncryption {

    const val E2EE_VERSION = "RELAY_E2EE_V1"
    private const val GCM_TAG_LENGTH_BITS = 128
    private const val GCM_NONCE_LENGTH_BYTES = 12
    private const val HKDF_SALT = "RELAY_DISASTER_MESH_E2EE_SALT_V1"
    private const val HKDF_INFO = "RELAY_AES_256_GCM_SESSION_KEY"

    private val secureRandom = SecureRandom()

    // Cache of authenticated peer X25519 encryption keys: NodeId -> AuthenticatedPeerKey
    private val peerKeyRegistry = ConcurrentHashMap<String, AuthenticatedPeerKey>()

    data class AuthenticatedPeerKey(
        val nodeId: String,
        val ed25519IdentityKeyHex: String,
        val x25519EncryptionKeyHex: String,
        val establishedAt: Long,
        val signature: String
    )

    data class EncryptedMessageEnvelope(
        val version: String = E2EE_VERSION,
        val packetId: String,
        val senderNodeId: String,
        val recipientNodeId: String,
        val ephemeralPublicKeyHex: String,
        val nonceHex: String,
        val ciphertextBase64: String,
        val timestamp: Long
    )

    // ========================================================================
    // 1. PEER KEY ESTABLISHMENT & AUTHENTICATION
    // ========================================================================

    /**
     * Builds canonical bytes for binding an X25519 encryption public key
     * to a device's Ed25519 identity key.
     */
    fun buildKeyBindingCanonicalBytes(
        nodeId: String,
        ed25519PubKeyHex: String,
        x25519PubKeyHex: String,
        timestamp: Long
    ): ByteArray {
        val stream = ByteArrayOutputStream()
        val out = DataOutputStream(stream)
        out.writeUTF("RELAY_KEY_BINDING_V1")
        out.writeUTF(nodeId)
        out.writeUTF(ed25519PubKeyHex)
        out.writeUTF(x25519PubKeyHex)
        out.writeLong(timestamp)
        out.flush()
        return stream.toByteArray()
    }

    /**
     * Registers and authenticates an incoming peer's encryption key.
     * Verifies that the X25519 key is signed by the peer's Ed25519 identity key.
     */
    fun registerPeerEncryptionKey(
        nodeId: String,
        ed25519PubKeyHex: String,
        x25519PubKeyHex: String,
        timestamp: Long,
        signature: String
    ): Boolean {
        if (nodeId.isBlank() || ed25519PubKeyHex.isBlank() || x25519PubKeyHex.isBlank() || signature.isBlank()) {
            return false
        }

        val canonicalBytes = buildKeyBindingCanonicalBytes(nodeId, ed25519PubKeyHex, x25519PubKeyHex, timestamp)
        val sigBytes = RelayKeyStoreManager.hexToBytes(signature)
        val pubBytes = RelayKeyStoreManager.hexToBytes(ed25519PubKeyHex)

        if (sigBytes.size != 64 || pubBytes.size != 32) {
            return false
        }

        val isSigValid = Ed25519.verify(canonicalBytes, sigBytes, pubBytes)
        if (!isSigValid) {
            return false
        }

        peerKeyRegistry[nodeId] = AuthenticatedPeerKey(
            nodeId = nodeId,
            ed25519IdentityKeyHex = ed25519PubKeyHex,
            x25519EncryptionKeyHex = x25519PubKeyHex,
            establishedAt = timestamp,
            signature = signature
        )
        return true
    }

    fun getPeerEncryptionKey(nodeId: String): AuthenticatedPeerKey? {
        return peerKeyRegistry[nodeId]
    }

    fun clearPeerKeysForTesting() {
        peerKeyRegistry.clear()
    }

    // ========================================================================
    // 2. KEY DERIVATION & DIFFIE-HELLMAN AGREEMENT
    // ========================================================================

    /**
     * Generates an ephemeral X25519 keypair for single-shot forward secrecy.
     */
    fun generateEphemeralX25519KeyPair(): Pair<X25519PrivateKeyParameters, X25519PublicKeyParameters> {
        val privKey = X25519PrivateKeyParameters(secureRandom)
        val pubKey = privKey.generatePublicKey()
        return Pair(privKey, pubKey)
    }

    /**
     * Computes X25519 Diffie-Hellman shared secret between private key and peer's public key.
     */
    fun calculateSharedSecret(
        myPrivateKey: X25519PrivateKeyParameters,
        peerPublicKeyBytes: ByteArray
    ): ByteArray {
        val peerPubKey = X25519PublicKeyParameters(peerPublicKeyBytes, 0)
        val agreement = X25519Agreement()
        agreement.init(myPrivateKey)
        val secret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(peerPubKey, secret, 0)
        return secret
    }

    /**
     * Derives a 256-bit AES key from the shared secret using HKDF-SHA256 (RFC 5869).
     */
    fun deriveAesKey(sharedSecret: ByteArray, salt: ByteArray, info: ByteArray): SecretKeySpec {
        // Step 1: HKDF-Extract: PRK = HMAC-SHA256(salt, sharedSecret)
        val macExtract = Mac.getInstance("HmacSHA256")
        macExtract.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = macExtract.doFinal(sharedSecret)

        // Step 2: HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
        val macExpand = Mac.getInstance("HmacSHA256")
        macExpand.init(SecretKeySpec(prk, "HmacSHA256"))
        macExpand.update(info)
        macExpand.update(0x01.toByte())
        val okm = macExpand.doFinal()

        // 256-bit AES key (first 32 bytes of OKM)
        val aesKeyBytes = ByteArray(32)
        System.arraycopy(okm, 0, aesKeyBytes, 0, 32)
        return SecretKeySpec(aesKeyBytes, "AES")
    }

    // ========================================================================
    // 3. AUTHENTICATED ASSOCIATED DATA (AAD)
    // ========================================================================

    /**
     * Deterministically builds binary Associated Authenticated Data (AAD)
     * binding the packet metadata to the ciphertext.
     */
    fun buildAad(
        packetId: String,
        senderNodeId: String,
        recipientNodeId: String,
        timestamp: Long
    ): ByteArray {
        val stream = ByteArrayOutputStream()
        val out = DataOutputStream(stream)
        out.writeUTF(E2EE_VERSION)
        out.writeUTF(packetId)
        out.writeUTF(senderNodeId)
        out.writeUTF(recipientNodeId)
        out.writeLong(timestamp)
        out.flush()
        return stream.toByteArray()
    }

    // ========================================================================
    // 4. AUTHENTICATED ENCRYPT & DECRYPT
    // ========================================================================

    /**
     * Encrypts plaintext bytes for a target peer using X25519 key agreement,
     * HKDF key derivation, and AES-256-GCM authenticated encryption.
     *
     * @param recipientX25519PubKeyHex The verified X25519 public key of the recipient.
     * @param packetId Unique identifier of the message/request.
     * @param senderNodeId Node ID of the sender.
     * @param recipientNodeId Node ID of the recipient.
     * @param plaintext Unencrypted payload bytes.
     * @param timestamp Creation timestamp.
     */
    fun encrypt(
        recipientX25519PubKeyHex: String,
        packetId: String,
        senderNodeId: String,
        recipientNodeId: String,
        plaintext: ByteArray,
        timestamp: Long = System.currentTimeMillis()
    ): EncryptedMessageEnvelope {
        val recipientPubBytes = RelayKeyStoreManager.hexToBytes(recipientX25519PubKeyHex)
        if (recipientPubBytes.size != 32) {
            throw IllegalArgumentException("Invalid recipient X25519 public key length: expected 32 bytes")
        }

        // Generate ephemeral X25519 keypair for single-shot forward secrecy
        val (ephemeralPriv, ephemeralPub) = generateEphemeralX25519KeyPair()
        val ephemeralPubBytes = ephemeralPub.encoded

        // Calculate shared secret via Curve25519 ECDH
        val sharedSecret = calculateSharedSecret(ephemeralPriv, recipientPubBytes)

        // Derive AES-256 key via HKDF-SHA256
        val aesKey = deriveAesKey(
            sharedSecret = sharedSecret,
            salt = HKDF_SALT.toByteArray(Charsets.UTF_8),
            info = HKDF_INFO.toByteArray(Charsets.UTF_8)
        )

        // Generate unique 12-byte nonce
        val nonce = ByteArray(GCM_NONCE_LENGTH_BYTES)
        secureRandom.nextBytes(nonce)

        // Build Authenticated Associated Data (AAD)
        val aad = buildAad(packetId, senderNodeId, recipientNodeId, timestamp)

        // AES-256-GCM Encrypt
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
        cipher.updateAAD(aad)
        val ciphertextWithTag = cipher.doFinal(plaintext)

        return EncryptedMessageEnvelope(
            version = E2EE_VERSION,
            packetId = packetId,
            senderNodeId = senderNodeId,
            recipientNodeId = recipientNodeId,
            ephemeralPublicKeyHex = RelayKeyStoreManager.bytesToHex(ephemeralPubBytes),
            nonceHex = RelayKeyStoreManager.bytesToHex(nonce),
            ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertextWithTag),
            timestamp = timestamp
        )
    }

    /**
     * Decrypts and authenticates an incoming [EncryptedMessageEnvelope] using the recipient's
     * X25519 private key.
     *
     * Throws [SecurityException] if:
     * - Ciphertext has been modified or corrupted.
     * - AAD / metadata (sender, recipient, packetId, timestamp) has been altered.
     * - Wrong private key is supplied.
     */
    fun decrypt(
        recipientPrivateKey: X25519PrivateKeyParameters,
        envelope: EncryptedMessageEnvelope
    ): ByteArray {
        val ephemeralPubBytes = RelayKeyStoreManager.hexToBytes(envelope.ephemeralPublicKeyHex)
        val nonceBytes = RelayKeyStoreManager.hexToBytes(envelope.nonceHex)
        val ciphertextWithTag = Base64.getDecoder().decode(envelope.ciphertextBase64)

        if (ephemeralPubBytes.size != 32 || nonceBytes.size != GCM_NONCE_LENGTH_BYTES) {
            throw SecurityException("Invalid E2EE envelope parameters")
        }

        // Calculate shared secret
        val sharedSecret = calculateSharedSecret(recipientPrivateKey, ephemeralPubBytes)

        // Derive AES-256 key
        val aesKey = deriveAesKey(
            sharedSecret = sharedSecret,
            salt = HKDF_SALT.toByteArray(Charsets.UTF_8),
            info = HKDF_INFO.toByteArray(Charsets.UTF_8)
        )

        // Build expected AAD
        val aad = buildAad(
            packetId = envelope.packetId,
            senderNodeId = envelope.senderNodeId,
            recipientNodeId = envelope.recipientNodeId,
            timestamp = envelope.timestamp
        )

        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, aesKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonceBytes))
            cipher.updateAAD(aad)
            cipher.doFinal(ciphertextWithTag)
        } catch (e: Exception) {
            throw SecurityException("E2EE verification failed: Modified ciphertext or unauthenticated metadata", e)
        }
    }

    // ========================================================================
    // 5. TRIAGE MEDICAL NOTE ENCRYPTION & DECRYPTION HELPERS
    // ========================================================================

    const val ENC_PREFIX = "RELAY_ENC_V1:"
    const val CONFIDENTIAL_NOTE_HEADER = "🔒 [CONFIDENTIAL MEDICAL NOTE]"

    data class DecryptedTriageResult(
        val publicDetails: String,
        val confidentialNote: String?,
        val isEncrypted: Boolean,
        val isDecrypted: Boolean,
        val recipientNodeId: String? = null,
        val failureReason: String? = null
    )

    fun getAllPeerEncryptionKeys(): List<AuthenticatedPeerKey> {
        return peerKeyRegistry.values.toList()
    }

    /**
     * Serializes an [EncryptedMessageEnvelope] and optional author ciphertext into a deterministic Base64 payload.
     */
    fun serializeEnvelope(envelope: EncryptedMessageEnvelope, authorCiphertextBase64: String? = null): String {
        val authPart = authorCiphertextBase64 ?: ""
        val payload = "${envelope.version}:${envelope.packetId}:${envelope.senderNodeId}:${envelope.recipientNodeId}:${envelope.ephemeralPublicKeyHex}:${envelope.nonceHex}:${envelope.ciphertextBase64}:${envelope.timestamp}:$authPart"
        val b64 = Base64.getEncoder().encodeToString(payload.toByteArray(Charsets.UTF_8))
        return "$ENC_PREFIX$b64"
    }

    /**
     * Parses a serialized encrypted note envelope.
     */
    fun parseEnvelope(serialized: String): Pair<EncryptedMessageEnvelope, String?>? {
        val trimmed = serialized.trim()
        val encIndex = trimmed.indexOf(ENC_PREFIX)
        if (encIndex == -1) return null
        val b64 = trimmed.substring(encIndex + ENC_PREFIX.length).trim()
        return try {
            val decoded = String(Base64.getDecoder().decode(b64), Charsets.UTF_8)
            val parts = decoded.split(":")
            if (parts.size < 8) return null
            val env = EncryptedMessageEnvelope(
                version = parts[0],
                packetId = parts[1],
                senderNodeId = parts[2],
                recipientNodeId = parts[3],
                ephemeralPublicKeyHex = parts[4],
                nonceHex = parts[5],
                ciphertextBase64 = parts[6],
                timestamp = parts[7].toLong()
            )
            val authorCiphertext = if (parts.size >= 9 && parts[8].isNotBlank()) parts[8] else null
            Pair(env, authorCiphertext)
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Encrypts confidential triage/medical notes for the target responder's X25519 public key,
     * optionally also encrypting an author envelope copy so the civilian author can view their own notes.
     */
    fun encryptTriageNote(
        confidentialNote: String,
        recipientX25519PubKeyHex: String,
        packetId: String,
        senderNodeId: String,
        recipientNodeId: String,
        authorX25519PubKeyHex: String? = null,
        timestamp: Long = System.currentTimeMillis()
    ): String {
        val plaintextBytes = confidentialNote.toByteArray(Charsets.UTF_8)
        val envelope = encrypt(
            recipientX25519PubKeyHex = recipientX25519PubKeyHex,
            packetId = packetId,
            senderNodeId = senderNodeId,
            recipientNodeId = recipientNodeId,
            plaintext = plaintextBytes,
            timestamp = timestamp
        )

        var authorCiphertextBase64: String? = null
        if (!authorX25519PubKeyHex.isNullOrBlank()) {
            try {
                val authorPubBytes = RelayKeyStoreManager.hexToBytes(authorX25519PubKeyHex)
                if (authorPubBytes.size == 32) {
                    val authorEnv = encrypt(
                        recipientX25519PubKeyHex = authorX25519PubKeyHex,
                        packetId = packetId,
                        senderNodeId = senderNodeId,
                        recipientNodeId = recipientNodeId,
                        plaintext = plaintextBytes,
                        timestamp = timestamp
                    )
                    authorCiphertextBase64 = "${authorEnv.ephemeralPublicKeyHex}|${authorEnv.nonceHex}|${authorEnv.ciphertextBase64}"
                }
            } catch (_: Exception) {
                // Non-fatal if author key is invalid or unavailable
            }
        }

        return serializeEnvelope(envelope, authorCiphertextBase64)
    }

    /**
     * Decrypts a serialized triage note using the local node's X25519 private key.
     * Attempts recipient decryption first, then author decryption.
     * Throws [SecurityException] if the device is neither the recipient nor the author.
     */
    fun decryptTriageNote(
        serialized: String,
        myPrivateKey: X25519PrivateKeyParameters,
        myNodeId: String
    ): String {
        val parsed = parseEnvelope(serialized) ?: throw IllegalArgumentException("Not a valid encrypted note envelope")
        val (envelope, authorCiphertext) = parsed

        // Attempt 1: Decrypt as intended recipient
        try {
            val clearBytes = decrypt(myPrivateKey, envelope)
            return String(clearBytes, Charsets.UTF_8)
        } catch (_: Exception) {
            // Not recipient or recipient decryption failed
        }

        // Attempt 2: Decrypt as author if author copy exists
        if (authorCiphertext != null && authorCiphertext.contains("|")) {
            val subParts = authorCiphertext.split("|")
            if (subParts.size == 3) {
                try {
                    val authorEnv = EncryptedMessageEnvelope(
                        version = envelope.version,
                        packetId = envelope.packetId,
                        senderNodeId = envelope.senderNodeId,
                        recipientNodeId = envelope.recipientNodeId,
                        ephemeralPublicKeyHex = subParts[0],
                        nonceHex = subParts[1],
                        ciphertextBase64 = subParts[2],
                        timestamp = envelope.timestamp
                    )
                    val clearBytes = decrypt(myPrivateKey, authorEnv)
                    return String(clearBytes, Charsets.UTF_8)
                } catch (_: Exception) {
                    // Author decryption failed
                }
            }
        }

        throw SecurityException("Decryption failed: device is neither the authorized recipient nor author, or payload was tampered")
    }

    /**
     * Formats full description by joining public location details with the encrypted confidential note envelope.
     */
    fun formatFullDescription(publicDetails: String, serializedEncryptedNote: String): String {
        val cleanPublic = publicDetails.trim()
        return if (cleanPublic.isEmpty()) {
            "$CONFIDENTIAL_NOTE_HEADER\n$serializedEncryptedNote"
        } else {
            "$cleanPublic\n\n$CONFIDENTIAL_NOTE_HEADER\n$serializedEncryptedNote"
        }
    }

    /**
     * Parses and safely decrypts full description text without crashing on relay nodes or untrusted peers.
     */
    fun parseAndDecryptDescription(
        fullDescription: String,
        myPrivateKey: X25519PrivateKeyParameters?,
        myNodeId: String
    ): DecryptedTriageResult {
        val encIndex = fullDescription.indexOf(ENC_PREFIX)
        if (encIndex == -1) {
            return DecryptedTriageResult(
                publicDetails = fullDescription,
                confidentialNote = null,
                isEncrypted = false,
                isDecrypted = false
            )
        }

        val publicPart = if (fullDescription.contains(CONFIDENTIAL_NOTE_HEADER)) {
            fullDescription.substringBefore(CONFIDENTIAL_NOTE_HEADER).trim()
        } else {
            fullDescription.substring(0, encIndex).trim()
        }

        val envelopeStr = fullDescription.substring(encIndex).trim()
        val parsed = parseEnvelope(envelopeStr)
        val recipientNodeId = parsed?.first?.recipientNodeId

        if (myPrivateKey == null) {
            return DecryptedTriageResult(
                publicDetails = publicPart,
                confidentialNote = null,
                isEncrypted = true,
                isDecrypted = false,
                recipientNodeId = recipientNodeId,
                failureReason = "No private key available"
            )
        }

        return try {
            val clearText = decryptTriageNote(envelopeStr, myPrivateKey, myNodeId)
            DecryptedTriageResult(
                publicDetails = publicPart,
                confidentialNote = clearText,
                isEncrypted = true,
                isDecrypted = true,
                recipientNodeId = recipientNodeId
            )
        } catch (e: Exception) {
            DecryptedTriageResult(
                publicDetails = publicPart,
                confidentialNote = null,
                isEncrypted = true,
                isDecrypted = false,
                recipientNodeId = recipientNodeId,
                failureReason = e.message
            )
        }
    }
}

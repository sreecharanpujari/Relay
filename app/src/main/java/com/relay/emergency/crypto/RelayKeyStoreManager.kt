package com.relay.emergency.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyInfo
import javax.crypto.SecretKeyFactory
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import java.security.MessageDigest

import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Manages device identity keys using the hardware-backed Android Keystore.
 * Protects the Ed25519 private seed with an AES-256-GCM master key stored in Android Keystore.
 */
class RelayKeyStoreManager private constructor(context: Context) {

    private val appContext = context.applicationContext

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    enum class KeyLifecycleState {
        ACTIVE,
        CORRUPTED,
        ROTATED
    }

    var lifecycleState: KeyLifecycleState = KeyLifecycleState.ACTIVE
        private set

    private var cachedSeed: ByteArray? = null
    private var cachedPublicKeyHex: String? = null
    private var cachedX25519PrivateKey: X25519PrivateKeyParameters? = null
    private var cachedX25519PublicKeyHex: String? = null

    companion object {
        private const val TAG = "RelayKeyStoreManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val MASTER_KEY_ALIAS = "relay_ed25519_master_key"
        private const val PREFS_NAME = "relay_secure_vault"
        private const val KEY_ENCRYPTED_SEED = "encrypted_seed_b64"
        private const val KEY_GCM_IV = "gcm_iv_b64"

        @Volatile
        private var INSTANCE: RelayKeyStoreManager? = null

        fun getInstance(context: Context): RelayKeyStoreManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: RelayKeyStoreManager(context).also { INSTANCE = it }
            }
        }

        fun bytesToHex(bytes: ByteArray): String {
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) {
                sb.append(String.format("%02x", b.toInt() and 0xFF))
            }
            return sb.toString()
        }

        fun hexToBytes(hex: String): ByteArray {
            val clean = hex.trim()
            if (clean.length % 2 != 0) return ByteArray(0)
            val len = clean.length
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                val hi = Character.digit(clean[i], 16)
                val lo = Character.digit(clean[i + 1], 16)
                if (hi == -1 || lo == -1) return ByteArray(0)
                data[i / 2] = ((hi shl 4) + lo).toByte()
                i += 2
            }
            return data
        }
    }

    init {
        ensureMasterKey()
        loadOrCreateEd25519Seed()
    }

    private fun ensureMasterKey() {
        if (!keyStore.containsAlias(MASTER_KEY_ALIAS)) {
            Log.d(TAG, "Generating new hardware-backed AES-256-GCM Master Key in Android Keystore")
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val builder = KeyGenParameterSpec.Builder(
                MASTER_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)

            keyGenerator.init(builder.build())
            keyGenerator.generateKey()
        }
    }

    private fun getMasterKey(): SecretKey {
        return keyStore.getKey(MASTER_KEY_ALIAS, null) as SecretKey
    }

    @Synchronized
    private fun loadOrCreateEd25519Seed() {
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedSeedB64 = prefs.getString(KEY_ENCRYPTED_SEED, null)
        val ivB64 = prefs.getString(KEY_GCM_IV, null)
        val hasInitializedBefore = prefs.getBoolean("has_initialized_identity", false)

        if (encryptedSeedB64 != null && ivB64 != null) {
            try {
                val iv = Base64.decode(ivB64, Base64.NO_WRAP)
                val encryptedSeed = Base64.decode(encryptedSeedB64, Base64.NO_WRAP)

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, getMasterKey(), GCMParameterSpec(128, iv))
                val seed = cipher.doFinal(encryptedSeed)

                if (seed.size == 32) {
                    cachedSeed = seed
                    val pubBytes = Ed25519.getPublicKey(seed)
                    cachedPublicKeyHex = bytesToHex(pubBytes)
                    deriveAndCacheX25519Keys(seed)
                    lifecycleState = KeyLifecycleState.ACTIVE
                    Log.d(TAG, "Loaded existing Ed25519 identity key. PubKey: $cachedPublicKeyHex")
                    return
                }
            } catch (e: Exception) {
                lifecycleState = KeyLifecycleState.CORRUPTED
                Log.e(TAG, "Cryptographic failure: Cannot decrypt existing Ed25519 identity key vault", e)
                throw SecurityException("Cryptographic security failure: Unable to decrypt hardware-protected Ed25519 seed. Failing closed to prevent silent identity destruction.", e)
            }
        }

        // Safety enforcement: If identity existed previously but the seed data is missing/corrupted,
        // NEVER silently regenerate an identity and destroy existing trust.
        if (hasInitializedBefore) {
            lifecycleState = KeyLifecycleState.CORRUPTED
            Log.e(TAG, "Security violation: Identity records missing after prior initialization. Failing closed.")
            throw SecurityException("Security violation: Identity record missing after prior initialization. Silent regeneration blocked.")
        }

        // Generate brand new 32-byte Ed25519 seed for first-time launch
        val secureRandom = SecureRandom()
        val newSeed = ByteArray(32)
        secureRandom.nextBytes(newSeed)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey())
        val iv = cipher.iv
        val encryptedSeed = cipher.doFinal(newSeed)

        prefs.edit()
            .putString(KEY_GCM_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_ENCRYPTED_SEED, Base64.encodeToString(encryptedSeed, Base64.NO_WRAP))
            .putBoolean("has_initialized_identity", true)
            .apply()

        cachedSeed = newSeed
        val pubBytes = Ed25519.getPublicKey(newSeed)
        cachedPublicKeyHex = bytesToHex(pubBytes)
        deriveAndCacheX25519Keys(newSeed)
        lifecycleState = KeyLifecycleState.ACTIVE
        Log.d(TAG, "Generated and protected new Ed25519 identity key. PubKey: $cachedPublicKeyHex")
    }

    fun getPublicKeyHex(): String {
        return cachedPublicKeyHex ?: synchronized(this) {
            val seed = cachedSeed ?: throw IllegalStateException("Seed not initialized")
            val pub = bytesToHex(Ed25519.getPublicKey(seed))
            cachedPublicKeyHex = pub
            pub
        }
    }

    fun getPublicKeyBytes(): ByteArray {
        val seed = cachedSeed ?: throw IllegalStateException("Seed not initialized")
        return Ed25519.getPublicKey(seed)
    }

    /**
     * Signs data using the local device's Ed25519 identity key.
     * Returns a 64-byte Ed25519 signature as a lowercase Hex string.
     */
    fun sign(data: ByteArray): String {
        val seed = cachedSeed ?: throw IllegalStateException("Seed not initialized")
        val sigBytes = Ed25519.sign(data, seed)
        return bytesToHex(sigBytes)
    }

    /**
     * Verifies an Ed25519 signature for a given message and public key.
     */
    fun verify(data: ByteArray, signatureHex: String, publicKeyHex: String): Boolean {
        val sigBytes = hexToBytes(signatureHex)
        val pubBytes = hexToBytes(publicKeyHex)
        if (sigBytes.size != 64 || pubBytes.size != 32) return false
        return Ed25519.verify(data, sigBytes, pubBytes)
    }

    private fun deriveAndCacheX25519Keys(seed: ByteArray) {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(seed)
        digest.update("RELAY_X25519_DERIVATION_V1".toByteArray(Charsets.UTF_8))
        val x25519Seed = digest.digest()
        
        // Clamp scalar according to RFC 7748
        x25519Seed[0] = (x25519Seed[0].toInt() and 248).toByte()
        x25519Seed[31] = (x25519Seed[31].toInt() and 127).toByte()
        x25519Seed[31] = (x25519Seed[31].toInt() or 64).toByte()

        val privKey = X25519PrivateKeyParameters(x25519Seed, 0)
        cachedX25519PrivateKey = privKey
        cachedX25519PublicKeyHex = bytesToHex(privKey.generatePublicKey().encoded)
    }

    fun getX25519PrivateKey(): X25519PrivateKeyParameters {
        return cachedX25519PrivateKey ?: synchronized(this) {
            val seed = cachedSeed ?: throw IllegalStateException("Seed not initialized")
            deriveAndCacheX25519Keys(seed)
            cachedX25519PrivateKey!!
        }
    }

    fun getX25519PublicKeyHex(): String {
        return cachedX25519PublicKeyHex ?: synchronized(this) {
            val seed = cachedSeed ?: throw IllegalStateException("Seed not initialized")
            deriveAndCacheX25519Keys(seed)
            cachedX25519PublicKeyHex!!
        }
    }

    fun getX25519PublicKeyBytes(): ByteArray {
        val hex = getX25519PublicKeyHex()
        return hexToBytes(hex)
    }

    /**
     * Verifies whether the master key in Android Keystore is backed by hardware (TEE / StrongBox).
     */
    fun isHardwareBacked(): Boolean {
        return try {
            val masterKey = getMasterKey()
            val factory = SecretKeyFactory.getInstance(masterKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(masterKey, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                keyInfo.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }
        } catch (_: Exception) {
            false
        }
    }

    fun getSecurityLevel(): String {
        return try {
            val masterKey = getMasterKey()
            val factory = SecretKeyFactory.getInstance(masterKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(masterKey, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "Hardware: StrongBox Keymaster"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "Hardware: Trusted Execution Environment (TEE)"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software Keystore"
                    else -> "Unknown Security Level"
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) "Hardware: Secure Hardware (TEE)" else "Software Keystore"
            }
        } catch (e: Exception) {
            "Keystore Check Status: ${e.message}"
        }
    }

    /**
     * Safely rotates the device identity keypair.
     * Records previous public key in rotation history and re-encrypts the new seed under the Keystore master key.
     */
    @Synchronized
    fun rotateIdentityKey(newSeed: ByteArray): String {
        if (newSeed.size != 32) {
            throw IllegalArgumentException("New seed must be exactly 32 bytes")
        }

        val oldPubKey = getPublicKeyHex()
        val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        // Record old public key in rotation history log
        val history = prefs.getStringSet("key_rotation_history", mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        history.add("$oldPubKey:${System.currentTimeMillis()}")

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getMasterKey())
        val iv = cipher.iv
        val encryptedSeed = cipher.doFinal(newSeed)

        prefs.edit()
            .putString(KEY_GCM_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_ENCRYPTED_SEED, Base64.encodeToString(encryptedSeed, Base64.NO_WRAP))
            .putStringSet("key_rotation_history", history)
            .putBoolean("has_initialized_identity", true)
            .apply()

        cachedSeed = newSeed
        val pubBytes = Ed25519.getPublicKey(newSeed)
        val newPubKeyHex = bytesToHex(pubBytes)
        cachedPublicKeyHex = newPubKeyHex
        deriveAndCacheX25519Keys(newSeed)
        lifecycleState = KeyLifecycleState.ROTATED

        Log.d(TAG, "Identity rotated safely. Old PubKey: $oldPubKey -> New PubKey: $newPubKeyHex")
        return newPubKeyHex
    }
}

package com.relay.emergency.crypto

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Hardened RFC 8032 Ed25519 digital signature provider backed by the mature,
 * independently reviewed, constant-time Bouncy Castle engine.
 *
 * Replaces custom BigInteger arithmetic with constant-time scalar multiplication
 * to prevent timing side-channel attacks on Android API 26+.
 */
object Ed25519 {

    const val PUBLIC_KEY_SIZE = 32
    const val PRIVATE_KEY_SEED_SIZE = 32
    const val SIGNATURE_SIZE = 64

    /**
     * Derives the 32-byte Ed25519 public key from the 32-byte private seed.
     */
    fun getPublicKey(privateSeed: ByteArray): ByteArray {
        require(privateSeed.size == PRIVATE_KEY_SEED_SIZE) {
            "Ed25519 private seed must be exactly $PRIVATE_KEY_SEED_SIZE bytes, got ${privateSeed.size}"
        }
        val privateKeyParams = Ed25519PrivateKeyParameters(privateSeed, 0)
        return privateKeyParams.generatePublicKey().encoded
    }

    /**
     * Signs data using the 32-byte Ed25519 private seed.
     * Returns the 64-byte Ed25519 signature.
     */
    fun sign(message: ByteArray, privateSeed: ByteArray): ByteArray {
        require(privateSeed.size == PRIVATE_KEY_SEED_SIZE) {
            "Ed25519 private seed must be exactly $PRIVATE_KEY_SEED_SIZE bytes, got ${privateSeed.size}"
        }
        val privateKeyParams = Ed25519PrivateKeyParameters(privateSeed, 0)
        val signer = Ed25519Signer()
        signer.init(true, privateKeyParams)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /**
     * Verifies an Ed25519 signature against the message and 32-byte public key.
     * Returns true if and only if the signature is mathematically valid.
     */
    fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
        if (signature.size != SIGNATURE_SIZE || publicKey.size != PUBLIC_KEY_SIZE) {
            return false
        }
        return try {
            val publicKeyParams = Ed25519PublicKeyParameters(publicKey, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, publicKeyParams)
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (_: Throwable) {
            false
        }
    }
}

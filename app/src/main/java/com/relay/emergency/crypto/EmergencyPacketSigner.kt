package com.relay.emergency.crypto

import android.content.Context
import com.relay.emergency.EmergencyRequest
import com.relay.emergency.RequestStatus
import com.relay.emergency.SosMessage
import com.relay.emergency.mesh.NodeIdentityManager
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * Handles canonical serialization, digital signing, and signature verification
 * for RELAY emergency requests, authenticated status updates, SOS distress messages,
 * and signed delivery acknowledgements using Ed25519.
 */
object EmergencyPacketSigner {

    private const val CANONICAL_HEADER = "RELAY_AUTH_V1"
    private const val CANONICAL_STATUS_HEADER = "RELAY_STATUS_V1"
    private const val CANONICAL_SOS_HEADER = "RELAY_SOS_V1"
    private const val CANONICAL_ACK_HEADER = "RELAY_ACK_V1"

    // ========================================================================
    // 1. EMERGENCY REQUESTS CANONICAL BYTES & SIGNING
    // ========================================================================

    /**
     * Builds deterministic, architecture-independent binary representation
     * of the immutable author fields for signing and verification.
     */
    fun buildCanonicalBytes(
        id: String,
        type: String,
        description: String,
        people: Int,
        priority: String,
        createdAt: Long,
        ttlHours: Int,
        originatorNodeId: String,
        senderPublicKey: String
    ): ByteArray {
        val byteStream = ByteArrayOutputStream()
        val dataOut = DataOutputStream(byteStream)

        dataOut.writeUTF(CANONICAL_HEADER)
        dataOut.writeUTF(id)
        dataOut.writeUTF(type)
        dataOut.writeUTF(description)
        dataOut.writeInt(people)
        dataOut.writeUTF(priority)
        dataOut.writeLong(createdAt)
        dataOut.writeInt(ttlHours)
        dataOut.writeUTF(originatorNodeId)
        dataOut.writeUTF(senderPublicKey)

        dataOut.flush()
        return byteStream.toByteArray()
    }

    fun buildCanonicalBytes(request: EmergencyRequest): ByteArray {
        return buildCanonicalBytes(
            id = request.id,
            type = request.type,
            description = request.description,
            people = request.people,
            priority = request.priority,
            createdAt = request.createdAt,
            ttlHours = request.ttlHours,
            originatorNodeId = request.originatorNodeId,
            senderPublicKey = request.senderPublicKey ?: ""
        )
    }

    /**
     * Signs an EmergencyRequest using the device's hardware-protected Ed25519 key.
     * Enforces the local origin boundary: only requests registered in [LocalOriginRegistry]
     * can be signed.
     */
    fun signRequest(context: Context, request: EmergencyRequest): EmergencyRequest {
        if (request.isCryptographicallySigned) {
            return request
        }

        // Trustworthy Local-Origin Boundary Enforcement:
        // Refuse to sign any request not registered as locally authored on this device.
        if (!LocalOriginRegistry.isLocallyAuthored(context, request.id)) {
            throw SecurityException("Security violation: Refusing to sign request ${request.id} because it is not registered in LocalOriginRegistry")
        }

        val keyManager = RelayKeyStoreManager.getInstance(context)
        val publicKeyHex = keyManager.getPublicKeyHex()
        val localNodeId = NodeIdentityManager.getLocalNodeId(context)

        val staged = request.copy(
            senderPublicKey = publicKeyHex,
            originatorNodeId = localNodeId
        )

        val canonicalBytes = buildCanonicalBytes(staged)
        val signatureHex = keyManager.sign(canonicalBytes)

        return staged.copy(signature = signatureHex)
    }

    /**
     * Verifies the Ed25519 digital signature of an EmergencyRequest.
     * Returns true if and only if the signature is mathematically valid
     * and none of the author fields have been tampered with.
     */
    fun verifyRequest(request: EmergencyRequest): Boolean {
        val pubKey = request.senderPublicKey
        val signature = request.signature

        if (pubKey.isNullOrBlank() || signature.isNullOrBlank()) {
            return false
        }

        val canonicalBytes = buildCanonicalBytes(request)
        val sigBytes = RelayKeyStoreManager.hexToBytes(signature)
        val pubBytes = RelayKeyStoreManager.hexToBytes(pubKey)

        if (sigBytes.size != 64 || pubBytes.size != 32) {
            return false
        }

        return Ed25519.verify(canonicalBytes, sigBytes, pubBytes)
    }

    // ========================================================================
    // 2. STATUS UPDATES CANONICAL BYTES & SIGNING
    // ========================================================================

    /**
     * Builds deterministic binary canonical representation for status updates.
     */
    fun buildCanonicalStatusBytes(
        requestId: String,
        authorNodeId: String,
        updaterPublicKey: String,
        newStatus: String,
        sequenceNumber: Int,
        updatedAt: Long,
        updaterRole: String
    ): ByteArray {
        val byteStream = ByteArrayOutputStream()
        val dataOut = DataOutputStream(byteStream)

        dataOut.writeUTF(CANONICAL_STATUS_HEADER)
        dataOut.writeUTF(requestId)
        dataOut.writeUTF(authorNodeId)
        dataOut.writeUTF(updaterPublicKey)
        dataOut.writeUTF(newStatus)
        dataOut.writeInt(sequenceNumber)
        dataOut.writeLong(updatedAt)
        dataOut.writeUTF(updaterRole)

        dataOut.flush()
        return byteStream.toByteArray()
    }

    /**
     * Cryptographically signs a status update using the device's Ed25519 key.
     * Enforces valid state transitions and authorization policies.
     */
    fun signStatusUpdate(
        context: Context,
        request: EmergencyRequest,
        newStatus: String,
        updaterRole: String = "AUTHOR"
    ): EmergencyRequest {
        if (!StatusAuthorizationPolicy.isValidTransition(request.status, newStatus)) {
            throw IllegalArgumentException("Illegal status transition from '${request.status}' to '$newStatus'")
        }

        val keyManager = RelayKeyStoreManager.getInstance(context)
        val updaterPubKey = keyManager.getPublicKeyHex()

        if (!StatusAuthorizationPolicy.isAuthorizedToUpdate(request, updaterPubKey, newStatus)) {
            throw SecurityException("Security violation: Node with public key $updaterPubKey is not authorized to update status of request ${request.id}")
        }

        val nextSeq = request.sequenceNumber + 1
        val now = System.currentTimeMillis()

        val canonicalBytes = buildCanonicalStatusBytes(
            requestId = request.id,
            authorNodeId = request.originatorNodeId,
            updaterPublicKey = updaterPubKey,
            newStatus = newStatus,
            sequenceNumber = nextSeq,
            updatedAt = now,
            updaterRole = updaterRole
        )

        val statusSig = keyManager.sign(canonicalBytes)

        return request.copy(
            status = newStatus,
            updatedAt = now,
            sequenceNumber = nextSeq,
            lastStatusSignature = statusSig,
            lastStatusUpdaterPublicKey = updaterPubKey,
            lastStatusUpdaterRole = updaterRole
        )
    }

    /**
     * Verifies the cryptographic signature of a status update.
     * Returns true if and only if the status update signature is mathematically valid.
     */
    fun verifyStatusUpdate(request: EmergencyRequest): Boolean {
        // If request is still at creation state (seq 0 and no status signature), status verification is not applicable
        if (request.sequenceNumber == 0 && request.lastStatusSignature.isNullOrBlank()) {
            return request.status == RequestStatus.PENDING
        }

        val sig = request.lastStatusSignature
        val updaterPubKey = request.lastStatusUpdaterPublicKey
        val role = request.lastStatusUpdaterRole ?: "AUTHOR"

        if (sig.isNullOrBlank() || updaterPubKey.isNullOrBlank()) {
            return false
        }

        val canonicalBytes = buildCanonicalStatusBytes(
            requestId = request.id,
            authorNodeId = request.originatorNodeId,
            updaterPublicKey = updaterPubKey,
            newStatus = request.status,
            sequenceNumber = request.sequenceNumber,
            updatedAt = request.updatedAt,
            updaterRole = role
        )

        val sigBytes = RelayKeyStoreManager.hexToBytes(sig)
        val pubBytes = RelayKeyStoreManager.hexToBytes(updaterPubKey)

        if (sigBytes.size != 64 || pubBytes.size != 32) {
            return false
        }

        return Ed25519.verify(canonicalBytes, sigBytes, pubBytes)
    }

    // ========================================================================
    // 3. SOS CHAT MESSAGES CANONICAL BYTES & SIGNING (SEC-07)
    // ========================================================================

    fun buildCanonicalSosBytes(
        id: String,
        senderName: String,
        message: String,
        isEmergency: Boolean,
        timestamp: Long,
        senderNodeId: String,
        senderPublicKey: String
    ): ByteArray {
        val byteStream = ByteArrayOutputStream()
        val dataOut = DataOutputStream(byteStream)

        dataOut.writeUTF(CANONICAL_SOS_HEADER)
        dataOut.writeUTF(id)
        dataOut.writeUTF(senderName)
        dataOut.writeUTF(message)
        dataOut.writeBoolean(isEmergency)
        dataOut.writeLong(timestamp)
        dataOut.writeUTF(senderNodeId)
        dataOut.writeUTF(senderPublicKey)

        dataOut.flush()
        return byteStream.toByteArray()
    }

    fun signSosMessage(context: Context, msg: SosMessage): SosMessage {
        val keyManager = RelayKeyStoreManager.getInstance(context)
        val pubKey = keyManager.getPublicKeyHex()
        val localNodeId = NodeIdentityManager.getLocalNodeId(context)

        val staged = msg.copy(
            senderPublicKey = pubKey,
            senderNodeId = localNodeId
        )

        val canonicalBytes = buildCanonicalSosBytes(
            id = staged.id,
            senderName = staged.senderName,
            message = staged.message,
            isEmergency = staged.isEmergency,
            timestamp = staged.timestamp,
            senderNodeId = staged.senderNodeId,
            senderPublicKey = pubKey
        )

        val sig = keyManager.sign(canonicalBytes)
        return staged.copy(signature = sig)
    }

    fun verifySosMessage(msg: SosMessage): Boolean {
        val pubKey = msg.senderPublicKey
        val sig = msg.signature

        if (pubKey.isNullOrBlank() || sig.isNullOrBlank()) {
            return false
        }

        val canonicalBytes = buildCanonicalSosBytes(
            id = msg.id,
            senderName = msg.senderName,
            message = msg.message,
            isEmergency = msg.isEmergency,
            timestamp = msg.timestamp,
            senderNodeId = msg.senderNodeId,
            senderPublicKey = pubKey
        )

        val sigBytes = RelayKeyStoreManager.hexToBytes(sig)
        val pubBytes = RelayKeyStoreManager.hexToBytes(pubKey)

        if (sigBytes.size != 64 || pubBytes.size != 32) {
            return false
        }

        return Ed25519.verify(canonicalBytes, sigBytes, pubBytes)
    }

    // ========================================================================
    // 4. DELIVERY ACKNOWLEDGEMENTS CANONICAL BYTES & SIGNING (SEC-09)
    // ========================================================================

    fun buildCanonicalAckBytes(
        requestId: String,
        nodeId: String,
        status: String,
        timestamp: Long,
        ackPublicKey: String
    ): ByteArray {
        val byteStream = ByteArrayOutputStream()
        val dataOut = DataOutputStream(byteStream)

        dataOut.writeUTF(CANONICAL_ACK_HEADER)
        dataOut.writeUTF(requestId)
        dataOut.writeUTF(nodeId)
        dataOut.writeUTF(status)
        dataOut.writeLong(timestamp)
        dataOut.writeUTF(ackPublicKey)

        dataOut.flush()
        return byteStream.toByteArray()
    }

    fun signAck(context: Context, requestId: String, status: String): Triple<String, String, Long> {
        val keyManager = RelayKeyStoreManager.getInstance(context)
        val localNodeId = NodeIdentityManager.getLocalNodeId(context)
        val pubKey = keyManager.getPublicKeyHex()
        val now = System.currentTimeMillis()

        val canonical = buildCanonicalAckBytes(requestId, localNodeId, status, now, pubKey)
        val sig = keyManager.sign(canonical)
        return Triple(sig, pubKey, now)
    }

    fun verifyAck(
        requestId: String,
        nodeId: String,
        status: String,
        timestamp: Long,
        ackPublicKey: String,
        signature: String
    ): Boolean {
        if (ackPublicKey.isBlank() || signature.isBlank()) return false
        val canonical = buildCanonicalAckBytes(requestId, nodeId, status, timestamp, ackPublicKey)
        val sigBytes = RelayKeyStoreManager.hexToBytes(signature)
        val pubBytes = RelayKeyStoreManager.hexToBytes(ackPublicKey)
        if (sigBytes.size != 64 || pubBytes.size != 32) return false
        return Ed25519.verify(canonical, sigBytes, pubBytes)
    }
}

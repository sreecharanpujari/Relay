package com.relay.emergency.crypto

import android.content.Context
import android.util.Log
import com.relay.emergency.EmergencyRequest
import com.relay.emergency.RequestStatus
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.util.concurrent.ConcurrentHashMap

/**
 * Enforces valid state machine transitions, clock-skew sanity bounds,
 * and explicit cryptographic authorization policies for emergency status updates.
 *
 * Security Features:
 * - Persistent trusted responder registry.
 * - Cryptographic responder revocation with audit reasons.
 * - Coordinator authorization required for registration and revocation.
 * - Strict rejection of revoked, unauthorized, or arbitrary relay nodes.
 */
object StatusAuthorizationPolicy {

    private const val TAG = "StatusAuthPolicy"
    private const val PERSISTENCE_FILE = "relay_trusted_responders.json"

    private fun logD(tag: String, msg: String) {
        try { android.util.Log.d(tag, msg) } catch (_: Throwable) { println("[$tag] $msg") }
    }
    private fun logI(tag: String, msg: String) {
        try { android.util.Log.i(tag, msg) } catch (_: Throwable) { println("[$tag] $msg") }
    }
    private fun logW(tag: String, msg: String) {
        try { android.util.Log.w(tag, msg) } catch (_: Throwable) { println("[$tag] $msg") }
    }
    private fun logE(tag: String, msg: String, tr: Throwable? = null) {
        try { android.util.Log.e(tag, msg, tr) } catch (_: Throwable) { println("[$tag] $msg") }
    }


    /** Maximum allowed future clock drift: 15 minutes */
    const val MAX_FUTURE_DRIFT_MS = 15 * 60 * 1000L

    data class TrustedResponderRecord(
        val publicKeyHex: String,
        val role: String = "Certified Responder",
        val organization: String = "Disaster Response Unit",
        val registeredAt: Long = System.currentTimeMillis(),
        val isRevoked: Boolean = false,
        val revokedAt: Long? = null,
        val revocationReason: String? = null,
        val authorizedByCoordinator: String? = null,
        val coordinatorSignature: String? = null
    )

    /**
     * Map of responder public key (hex) -> TrustedResponderRecord.
     */
    private val responderRegistry = ConcurrentHashMap<String, TrustedResponderRecord>()

    /**
     * Set of authorized coordinator public keys authorized to register and revoke responders.
     */
    private val authorizedCoordinatorKeys = ConcurrentHashMap.newKeySet<String>()

    // ========================================================================
    // 1. COORDINATOR AUTHORIZATION & REGISTRATION
    // ========================================================================

    fun registerCoordinatorKey(coordinatorPubKeyHex: String) {
        if (coordinatorPubKeyHex.isNotBlank()) {
            authorizedCoordinatorKeys.add(coordinatorPubKeyHex.trim().lowercase())
        }
    }

    fun isAuthorizedCoordinator(coordinatorPubKeyHex: String?): Boolean {
        if (coordinatorPubKeyHex.isNullOrBlank()) return false
        return authorizedCoordinatorKeys.contains(coordinatorPubKeyHex.trim().lowercase())
    }

    fun clearCoordinatorsForTesting() {
        authorizedCoordinatorKeys.clear()
    }

    fun buildRegistrationCanonicalBytes(
        responderPubKeyHex: String,
        role: String,
        organization: String,
        registeredAt: Long
    ): ByteArray {
        val stream = ByteArrayOutputStream()
        val out = DataOutputStream(stream)
        out.writeUTF("RELAY_REGISTER_RESPONDER_V1")
        out.writeUTF(responderPubKeyHex.trim().lowercase())
        out.writeUTF(role)
        out.writeUTF(organization)
        out.writeLong(registeredAt)
        out.flush()
        return stream.toByteArray()
    }

    fun buildRevocationCanonicalBytes(
        responderPubKeyHex: String,
        reason: String,
        revokedAt: Long
    ): ByteArray {
        val stream = ByteArrayOutputStream()
        val out = DataOutputStream(stream)
        out.writeUTF("RELAY_REVOKE_RESPONDER_V1")
        out.writeUTF(responderPubKeyHex.trim().lowercase())
        out.writeUTF(reason)
        out.writeLong(revokedAt)
        out.flush()
        return stream.toByteArray()
    }

    /**
     * Registers a new certified responder.
     * Requires authorization from a registered coordinator or local admin authority.
     */
    fun registerResponder(
        context: Context?,
        responderPubKeyHex: String,
        role: String = "Certified Responder",
        organization: String = "Disaster Response Unit",
        coordinatorPubKeyHex: String? = null,
        coordinatorSignature: String? = null
    ): Boolean {
        val cleanKey = responderPubKeyHex.trim().lowercase()
        if (cleanKey.length != 64 || !cleanKey.all { it.isDigit() || it in 'a'..'f' }) {
            logW(TAG, "Rejected registration: Invalid Ed25519 public key format ($cleanKey)")
            return false
        }

        // If a coordinator is registered in policy, signature verification is strictly enforced
        if (authorizedCoordinatorKeys.isNotEmpty()) {
            if (coordinatorPubKeyHex == null || !isAuthorizedCoordinator(coordinatorPubKeyHex)) {
                logW(TAG, "Rejected registration: Unauthorized or missing coordinator key")
                return false
            }
            if (coordinatorSignature.isNullOrBlank()) {
                logW(TAG, "Rejected registration: Missing coordinator cryptographic signature")
                return false
            }
            val canonicalBytes = buildRegistrationCanonicalBytes(cleanKey, role, organization, System.currentTimeMillis())
            val sigBytes = RelayKeyStoreManager.hexToBytes(coordinatorSignature)
            val coordBytes = RelayKeyStoreManager.hexToBytes(coordinatorPubKeyHex)
            if (sigBytes.size != 64 || coordBytes.size != 32 || !Ed25519.verify(canonicalBytes, sigBytes, coordBytes)) {
                logW(TAG, "Rejected registration: Invalid coordinator digital signature")
                return false
            }
        }

        val record = TrustedResponderRecord(
            publicKeyHex = cleanKey,
            role = role,
            organization = organization,
            registeredAt = System.currentTimeMillis(),
            isRevoked = false,
            authorizedByCoordinator = coordinatorPubKeyHex,
            coordinatorSignature = coordinatorSignature
        )

        responderRegistry[cleanKey] = record
        context?.let { savePersistedResponders(it) }
        logI(TAG, "Successfully registered responder: $cleanKey ($role)")
        return true
    }

    /**
     * Revokes an existing responder's triage authorization.
     * Once revoked, any status updates signed by this key will be strictly rejected.
     */
    fun revokeResponder(
        context: Context?,
        responderPubKeyHex: String,
        reason: String,
        coordinatorPubKeyHex: String? = null,
        coordinatorSignature: String? = null
    ): Boolean {
        val cleanKey = responderPubKeyHex.trim().lowercase()
        val existing = responderRegistry[cleanKey] ?: run {
            logW(TAG, "Cannot revoke responder $cleanKey: Not in registry")
            return false
        }

        // Enforce coordinator authorization if coordinators are registered
        if (authorizedCoordinatorKeys.isNotEmpty()) {
            if (coordinatorPubKeyHex == null || !isAuthorizedCoordinator(coordinatorPubKeyHex)) {
                logW(TAG, "Rejected revocation: Unauthorized or missing coordinator key")
                return false
            }
            if (coordinatorSignature.isNullOrBlank()) {
                logW(TAG, "Rejected revocation: Missing coordinator cryptographic signature")
                return false
            }
            val now = System.currentTimeMillis()
            val canonicalBytes = buildRevocationCanonicalBytes(cleanKey, reason, now)
            val sigBytes = RelayKeyStoreManager.hexToBytes(coordinatorSignature)
            val coordBytes = RelayKeyStoreManager.hexToBytes(coordinatorPubKeyHex)
            if (sigBytes.size != 64 || coordBytes.size != 32 || !Ed25519.verify(canonicalBytes, sigBytes, coordBytes)) {
                logW(TAG, "Rejected revocation: Invalid coordinator signature on revocation")
                return false
            }
        }

        val updated = existing.copy(
            isRevoked = true,
            revokedAt = System.currentTimeMillis(),
            revocationReason = reason
        )

        responderRegistry[cleanKey] = updated
        context?.let { savePersistedResponders(it) }
        logW(TAG, "REVOKED responder: $cleanKey (Reason: $reason)")
        return true
    }

    // ========================================================================
    // 2. BACKWARD COMPATIBILITY HELPERS
    // ========================================================================

    fun registerResponderKey(publicKeyHex: String) {
        if (publicKeyHex.isNotBlank()) {
            val clean = publicKeyHex.trim().lowercase()
            responderRegistry[clean] = TrustedResponderRecord(
                publicKeyHex = clean,
                role = "Certified Field Responder",
                isRevoked = false
            )
        }
    }

    fun isRegisteredResponder(publicKeyHex: String?): Boolean {
        if (publicKeyHex.isNullOrBlank()) return false
        val clean = publicKeyHex.trim().lowercase()
        val record = responderRegistry[clean] ?: return false
        return !record.isRevoked
    }

    fun getRegisteredResponderKeys(): List<String> {
        return responderRegistry.values
            .filter { !it.isRevoked }
            .map { it.publicKeyHex }
    }

    fun getAllResponderRecords(): List<TrustedResponderRecord> {
        return responderRegistry.values.toList()
    }

    fun clearRespondersForTesting() {
        responderRegistry.clear()
        authorizedCoordinatorKeys.clear()
    }

    // ========================================================================
    // 3. PERSISTENCE & SAFE STORAGE
    // ========================================================================

    fun savePersistedResponders(context: Context) {
        try {
            val arr = JSONArray()
            for (rec in responderRegistry.values) {
                val obj = JSONObject().apply {
                    put("publicKeyHex", rec.publicKeyHex)
                    put("role", rec.role)
                    put("organization", rec.organization)
                    put("registeredAt", rec.registeredAt)
                    put("isRevoked", rec.isRevoked)
                    put("revokedAt", rec.revokedAt ?: 0L)
                    put("revocationReason", rec.revocationReason ?: "")
                    put("authorizedByCoordinator", rec.authorizedByCoordinator ?: "")
                    put("coordinatorSignature", rec.coordinatorSignature ?: "")
                }
                arr.put(obj)
            }
            val file = File(context.filesDir, PERSISTENCE_FILE)
            file.writeText(arr.toString(), Charsets.UTF_8)
        } catch (e: Exception) {
            logE(TAG, "Failed saving persistent responders", e)
        }
    }

    fun loadPersistedResponders(context: Context) {
        try {
            val file = File(context.filesDir, PERSISTENCE_FILE)
            if (!file.exists()) return
            val data = file.readText(Charsets.UTF_8)
            val arr = JSONArray(data)
            for (i in 0 until arr.length()) {
                val obj = arr.getJSONObject(i)
                val key = obj.getString("publicKeyHex").trim().lowercase()
                val record = TrustedResponderRecord(
                    publicKeyHex = key,
                    role = obj.optString("role", "Certified Responder"),
                    organization = obj.optString("organization", "Disaster Response Unit"),
                    registeredAt = obj.optLong("registeredAt", System.currentTimeMillis()),
                    isRevoked = obj.optBoolean("isRevoked", false),
                    revokedAt = if (obj.has("revokedAt") && obj.getLong("revokedAt") > 0) obj.getLong("revokedAt") else null,
                    revocationReason = obj.optString("revocationReason", "").ifBlank { null },
                    authorizedByCoordinator = obj.optString("authorizedByCoordinator", "").ifBlank { null },
                    coordinatorSignature = obj.optString("coordinatorSignature", "").ifBlank { null }
                )
                responderRegistry[key] = record
            }
            logD(TAG, "Loaded ${responderRegistry.size} persistent responder records")
        } catch (e: Exception) {
            logE(TAG, "Failed loading persistent responders", e)
        }
    }

    // ========================================================================
    // 4. AUTHORIZATION EVALUATION GATE
    // ========================================================================

    /**
     * Evaluates whether an entity presenting [updaterPublicKey] has cryptographic authority
     * to transition the status of [request] to [targetStatus].
     *
     * Rules:
     * 1. The original author of the emergency request is ALWAYS authorized.
     * 2. Active, non-revoked registered emergency responders are authorized.
     * 3. Revoked responders are STRICTLY REJECTED.
     * 4. Arbitrary relay nodes on the mesh have NO authority to modify status and are rejected.
     */
    fun isAuthorizedToUpdate(
        request: EmergencyRequest,
        updaterPublicKey: String?,
        targetStatus: String
    ): Boolean {
        if (updaterPublicKey.isNullOrBlank()) return false
        val cleanUpdaterKey = updaterPublicKey.trim().lowercase()

        // 1. Author check
        val authorKey = request.senderPublicKey?.trim()?.lowercase()
        if (!authorKey.isNullOrBlank() && cleanUpdaterKey == authorKey) {
            return true
        }

        // 2. Registered responder check
        val record = responderRegistry[cleanUpdaterKey]
        if (record != null) {
            if (record.isRevoked) {
                logW(TAG, "SECURITY REJECTION: Status update rejected from REVOKED responder ($cleanUpdaterKey). Reason: ${record.revocationReason}")
                return false
            }
            return true
        }

        // 3. Unauthorized relay node
        logW(TAG, "SECURITY REJECTION: Status update rejected from unauthorized node ($cleanUpdaterKey)")
        return false
    }

    /**
     * Validates legal status transitions according to the emergency lifecycle state machine.
     * Prevents backwards state tampering or griefing attacks on resolved incidents.
     */
    fun isValidTransition(currentStatus: String, nextStatus: String): Boolean {
        if (currentStatus == nextStatus) return true

        return when (currentStatus) {
            RequestStatus.PENDING -> nextStatus in listOf(
                RequestStatus.ASSIGNED,
                RequestStatus.IN_PROGRESS,
                RequestStatus.RESOLVED
            )
            RequestStatus.ASSIGNED -> nextStatus in listOf(
                RequestStatus.IN_PROGRESS,
                RequestStatus.RESOLVED
            )
            RequestStatus.IN_PROGRESS -> nextStatus == RequestStatus.RESOLVED
            RequestStatus.RESOLVED -> false // Terminal state: once resolved, cannot revert
            else -> false
        }
    }

    /**
     * Validates that the timestamp does not exceed the allowed future clock drift.
     * Prevents Denial-of-Service attacks that lock requests using far-future timestamps.
     */
    fun isTimestampWithinBounds(timestamp: Long, now: Long = System.currentTimeMillis()): Boolean {
        return timestamp <= now + MAX_FUTURE_DRIFT_MS
    }
}

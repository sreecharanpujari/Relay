package com.relay.emergency.mesh

import android.content.Context
import android.os.Build
import org.json.JSONArray
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.security.MessageDigest

// ============================================================================
// STORE-AND-FORWARD PROTOCOL CONSTANTS
// ============================================================================

const val SERVICE_ID = "com.relay.emergency"
const val MAX_STORE_FORWARD_HOPS = 5
const val DEFAULT_REQUEST_TTL_HOURS = 24
const val MAX_TRANSFER_RETRIES = 3
const val ACK_TIMEOUT_MS = 4500L

enum class TransferType(val icon: String, val tag: String) {
    RECEIVED("📥", "Received"),
    FORWARDED("📤", "Forwarded"),
    ACK_SENT("📬", "ACK Sent"),
    ACK_RECEIVED("✅", "ACK Confirmed"),
    RETRY("⏳", "Retrying"),
    EXPIRED("⏱️", "Expired"),
    LOOP_PREVENTED("🛡️", "Loop Blocked"),
    SECURITY_REJECTED("🚫", "Security Blocked")
}

data class TransferLogEntry(
    val id: String = UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val type: TransferType,
    val requestId: String,
    val summary: String,
    val peerName: String,
    val hopCount: Int
) {
    val formattedTime: String
        get() {
            val sdf = SimpleDateFormat("HH:mm:ss", Locale.getDefault())
            return sdf.format(Date(timestamp))
        }
}

data class PendingTransfer(
    val requestId: String,
    val endpointId: String,
    val peerName: String,
    val payloadBytes: ByteArray,
    val sentAt: Long = System.currentTimeMillis(),
    var attempts: Int = 1
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PendingTransfer

        if (requestId != other.requestId) return false
        if (endpointId != other.endpointId) return false
        if (peerName != other.peerName) return false
        if (!payloadBytes.contentEquals(other.payloadBytes)) return false
        if (sentAt != other.sentAt) return false
        if (attempts != other.attempts) return false

        return true
    }

    override fun hashCode(): Int {
        var result = requestId.hashCode()
        result = 31 * result + endpointId.hashCode()
        result = 31 * result + peerName.hashCode()
        result = 31 * result + payloadBytes.contentHashCode()
        result = 31 * result + sentAt.hashCode()
        result = 31 * result + attempts
        return result
    }
}

object NodeIdentityManager {
    private const val PREFS_NAME = "relay_node_meta"
    private const val KEY_NODE_ID = "local_node_id"
    private const val KEY_ROTATION_HISTORY = "node_id_rotation_history"

    /** Length of the cryptographic fingerprint suffix (16 hex chars = 64 bits of entropy) */
    const val FINGERPRINT_HEX_LENGTH = 16

    @Volatile
    private var cachedNodeId: String? = null

    /**
     * Computes a collision-resistant 64-bit cryptographic fingerprint (16 hex characters)
     * from the SHA-256 digest of the device's public key bytes.
     */
    fun computeFingerprint(publicKeyHex: String): String {
        if (publicKeyHex.isBlank()) return "0".repeat(FINGERPRINT_HEX_LENGTH)
        val pubBytes = com.relay.emergency.crypto.RelayKeyStoreManager.hexToBytes(publicKeyHex)
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(pubBytes)
        return com.relay.emergency.crypto.RelayKeyStoreManager.bytesToHex(hash)
            .take(FINGERPRINT_HEX_LENGTH)
            .uppercase()
    }

    /**
     * Cryptographically verifies whether a given [nodeId] is validly bound
     * to the provided [publicKeyHex].
     */
    fun verifyIdentityBinding(nodeId: String, publicKeyHex: String): Boolean {
        if (!nodeId.startsWith("RELAY-") || publicKeyHex.isBlank()) return false
        val expectedFingerprint = computeFingerprint(publicKeyHex)
        return nodeId.endsWith(expectedFingerprint)
    }

    fun getLocalNodeId(context: Context): String {
        cachedNodeId?.let { return it }

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        var nodeId = prefs.getString(KEY_NODE_ID, null)

        val pubKeyHex = try {
            com.relay.emergency.crypto.RelayKeyStoreManager.getInstance(context).getPublicKeyHex()
        } catch (_: Throwable) {
            null
        }

        // Check if existing nodeId matches current public key binding; if not, recompute
        val isBindingValid = if (!nodeId.isNullOrBlank() && !pubKeyHex.isNullOrBlank()) {
            verifyIdentityBinding(nodeId, pubKeyHex)
        } else {
            false
        }

        if (nodeId.isNullOrBlank() || !isBindingValid) {
            val cleanModel = Build.MODEL
                .replace(Regex("[^a-zA-Z0-9]"), "")
                .take(6)
                .uppercase()

            val fingerprint = if (!pubKeyHex.isNullOrBlank()) {
                computeFingerprint(pubKeyHex)
            } else {
                UUID.randomUUID().toString().replace("-", "").take(FINGERPRINT_HEX_LENGTH).uppercase()
            }

            nodeId = "RELAY-$cleanModel-$fingerprint"
            prefs.edit().putString(KEY_NODE_ID, nodeId).apply()
        }

        cachedNodeId = nodeId
        return nodeId
    }

    /**
     * Handles identity updates on key rotation safely without clobbering historical records.
     */
    fun updateIdentityOnKeyRotation(context: Context, newPublicKeyHex: String): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val oldNodeId = prefs.getString(KEY_NODE_ID, "") ?: ""

        val history = prefs.getStringSet(KEY_ROTATION_HISTORY, mutableSetOf())?.toMutableSet() ?: mutableSetOf()
        if (oldNodeId.isNotBlank()) {
            history.add("$oldNodeId:${System.currentTimeMillis()}")
        }

        val cleanModel = Build.MODEL
            .replace(Regex("[^a-zA-Z0-9]"), "")
            .take(6)
            .uppercase()
        val newFingerprint = computeFingerprint(newPublicKeyHex)
        val newNodeId = "RELAY-$cleanModel-$newFingerprint"

        prefs.edit()
            .putString(KEY_NODE_ID, newNodeId)
            .putStringSet(KEY_ROTATION_HISTORY, history)
            .apply()

        cachedNodeId = newNodeId
        return newNodeId
    }

    fun clearCachedNodeIdForTesting() {
        cachedNodeId = null
    }
}

object StoreAndForwardHelper {
    fun serializeNodeHistory(history: List<String>): JSONArray {
        val array = JSONArray()
        for (node in history) {
            array.put(node)
        }
        return array
    }

    fun parseNodeHistory(array: JSONArray?): List<String> {
        if (array == null) return emptyList()
        val list = mutableListOf<String>()
        for (i in 0 until array.length()) {
            val item = array.optString(i)
            if (!item.isNullOrBlank()) {
                list.add(item)
            }
        }
        return list
    }
}

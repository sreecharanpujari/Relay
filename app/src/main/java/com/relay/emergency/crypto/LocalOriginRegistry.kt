package com.relay.emergency.crypto

import android.content.Context
import java.util.concurrent.ConcurrentHashMap

/**
 * Authoritative local origin boundary and registry for emergency requests.
 *
 * Ensures that only requests explicitly authored by the local user through this device's
 * UI can ever be signed with the local device's private Ed25519 key.
 *
 * Remotely mutable or supplied packet fields (such as originatorNodeId, hopCount,
 * or nodeHistory) are NEVER trusted as proof of local creation.
 */
object LocalOriginRegistry {

    private const val PREFS_NAME = "relay_local_origin_registry"
    private const val KEY_AUTHORED_IDS = "authored_request_ids"

    private val localOriginIds = ConcurrentHashMap.newKeySet<String>()

    @Volatile
    private var isLoadedFromDisk = false

    private fun loadFromDisk(context: Context) {
        if (!isLoadedFromDisk) {
            synchronized(this) {
                if (!isLoadedFromDisk) {
                    try {
                        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                        val stored = prefs.getStringSet(KEY_AUTHORED_IDS, emptySet()) ?: emptySet()
                        localOriginIds.addAll(stored)
                        isLoadedFromDisk = true
                    } catch (_: Throwable) {
                        // In test environments or when storage is unavailable
                    }
                }
            }
        }
    }

    /**
     * Records that a request ID was authored locally on this device.
     * Must only be invoked at the explicit local user creation boundary (e.g. CreateRequestScreen).
     */
    fun recordLocalCreation(context: Context?, requestId: String) {
        localOriginIds.add(requestId)
        if (context != null) {
            try {
                loadFromDisk(context)
                val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                val current = prefs.getStringSet(KEY_AUTHORED_IDS, emptySet())?.toMutableSet() ?: mutableSetOf()
                current.add(requestId)
                prefs.edit().putStringSet(KEY_AUTHORED_IDS, current).apply()
            } catch (_: Throwable) {
                // In test environments or when storage is unavailable
            }
        }
    }

    /**
     * Verifies whether the request ID originated on this local device.
     * Never trusts packet headers or remotely mutable metadata.
     */
    fun isLocallyAuthored(context: Context?, requestId: String): Boolean {
        if (!isLoadedFromDisk && context != null) {
            loadFromDisk(context)
        }
        return localOriginIds.contains(requestId)
    }

    /**
     * Clears in-memory registry. Used for unit testing.
     */
    fun clearForTesting() {
        localOriginIds.clear()
        isLoadedFromDisk = false
    }
}


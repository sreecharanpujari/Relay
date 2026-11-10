package com.relay.emergency.mesh

import java.util.concurrent.ConcurrentHashMap

/**
 * In-memory sliding-window rate limiter per peer endpoint.
 * Prevents radio exhaustion, battery drain, and packet-flooding Denial-of-Service attacks.
 */
object MeshRateLimiter {

    /** Maximum allowed incoming packets per window per direct peer endpoint */
    const val MAX_PACKETS_PER_WINDOW = 30
    /** Sliding window duration: 60 seconds */
    const val WINDOW_MS = 60 * 1000L

    private val peerTimestamps = ConcurrentHashMap<String, MutableList<Long>>()

    /**
     * Evaluates whether an incoming payload from [endpointId] is within rate limits.
     * Returns true if allowed, false if rate limit is exceeded.
     */
    fun isAllowed(endpointId: String, now: Long = System.currentTimeMillis()): Boolean {
        val timestamps = peerTimestamps.computeIfAbsent(endpointId) { mutableListOf() }

        synchronized(timestamps) {
            timestamps.removeAll { (now - it) > WINDOW_MS }
            return if (timestamps.size < MAX_PACKETS_PER_WINDOW) {
                timestamps.add(now)
                true
            } else {
                false
            }
        }
    }

    fun clearEndpoint(endpointId: String) {
        peerTimestamps.remove(endpointId)
    }

    fun clearAllForTesting() {
        peerTimestamps.clear()
    }
}


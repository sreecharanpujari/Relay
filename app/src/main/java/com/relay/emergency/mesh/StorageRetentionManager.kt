package com.relay.emergency.mesh

import com.relay.emergency.EmergencyRequest
import com.relay.emergency.SosMessage

/**
 * Manages storage retention and pruning to prevent unbounded disk usage
 * during prolonged off-grid mesh operation.
 */
object StorageRetentionManager {

    /** Retain expired requests up to 48 hours past expiration for audit and diagnostic review */
    const val EXPIRED_REQUEST_RETENTION_MS = 48 * 3600 * 1000L

    /** Retain up to 200 SOS chat messages */
    const val MAX_SOS_MESSAGES = 200

    /** Retain SOS chat messages up to 72 hours */
    const val SOS_MESSAGE_RETENTION_MS = 72 * 3600 * 1000L

    /**
     * Filters out requests whose expiration timestamp exceeds the retention window.
     */
    fun pruneExpiredRequests(requests: List<EmergencyRequest>, now: Long = System.currentTimeMillis()): List<EmergencyRequest> {
        return requests.filter { req ->
            if (!req.isExpired) return@filter true
            val expiredAt = req.createdAt + (req.ttlHours * 3600 * 1000L)
            (now - expiredAt) < EXPIRED_REQUEST_RETENTION_MS
        }
    }

    /**
     * Filters out old SOS chat messages exceeding retention duration or max message cap.
     */
    fun pruneSosMessages(messages: List<SosMessage>, now: Long = System.currentTimeMillis()): List<SosMessage> {
        val timePruned = messages.filter { (now - it.timestamp) < SOS_MESSAGE_RETENTION_MS }
        return if (timePruned.size > MAX_SOS_MESSAGES) {
            timePruned.takeLast(MAX_SOS_MESSAGES)
        } else {
            timePruned
        }
    }
}


package com.relay.emergency.mesh

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ArrayBlockingQueue

/**
 * Manages mesh transport reliability, maximum payload size enforcement,
 * bounded memory queues, and endpoint connection churn protection.
 */
object MeshReliabilityManager {

    private const val TAG = "MeshReliability"

    private fun logD(tag: String, msg: String) {
        try { android.util.Log.d(tag, msg) } catch (_: Throwable) { println("[$tag] $msg") }
    }
    private fun logW(tag: String, msg: String) {
        try { android.util.Log.w(tag, msg) } catch (_: Throwable) { println("[$tag] $msg") }
    }


    /** Maximum allowed transmission payload size: 32 KB */
    const val MAX_PAYLOAD_BYTES = 32 * 1024

    /** Maximum capacity for incoming processing queue */
    const val MAX_INCOMING_QUEUE_SIZE = 50

    /** Maximum capacity for outgoing pending dispatch queue */
    const val MAX_OUTGOING_QUEUE_SIZE = 50

    /** Maximum rapid connection attempts allowed per peer within window */
    const val MAX_CONNECTION_ATTEMPTS_PER_WINDOW = 5

    /** Connection churn evaluation window: 60 seconds */
    const val CHURN_WINDOW_MS = 60 * 1000L

    // In-memory churn tracker: endpointId -> list of attempt timestamps
    private val endpointConnectionAttempts = ConcurrentHashMap<String, MutableList<Long>>()

    // Bounded queues to prevent unbounded memory growth and Out-Of-Memory under mesh flood
    private val incomingQueue = ArrayBlockingQueue<ByteArray>(MAX_INCOMING_QUEUE_SIZE)
    private val outgoingQueue = ArrayBlockingQueue<ByteArray>(MAX_OUTGOING_QUEUE_SIZE)

    /**
     * Validates whether an incoming or outgoing raw payload is within safety limits.
     * Rejects oversized packets to prevent memory exhaustion and buffer overflow attacks.
     */
    fun isPayloadSizeValid(payloadBytes: ByteArray?): Boolean {
        if (payloadBytes == null) return false
        if (payloadBytes.isEmpty()) return false
        return payloadBytes.size <= MAX_PAYLOAD_BYTES
    }

    /**
     * Evaluates endpoint connection churn.
     * Prevents rapid connection/disconnection loops and battery exhaustion attacks.
     * Returns true if connection attempt is permitted, false if rate-limited due to churn.
     */
    fun isConnectionAttemptAllowed(endpointId: String, now: Long = System.currentTimeMillis()): Boolean {
        val attempts = endpointConnectionAttempts.computeIfAbsent(endpointId) { mutableListOf() }
        synchronized(attempts) {
            attempts.removeAll { (now - it) > CHURN_WINDOW_MS }
            return if (attempts.size < MAX_CONNECTION_ATTEMPTS_PER_WINDOW) {
                attempts.add(now)
                true
            } else {
                logW(TAG, "Connection rate limited for endpoint $endpointId: exceeded $MAX_CONNECTION_ATTEMPTS_PER_WINDOW attempts in 60s")
                false
            }
        }
    }

    /**
     * Cleans up endpoint-specific churn tracking when an endpoint permanently disconnects.
     */
    fun onEndpointDisconnected(endpointId: String) {
        endpointConnectionAttempts.remove(endpointId)
        MeshRateLimiter.clearEndpoint(endpointId)
        logD(TAG, "Cleaned up state and rate counters for disconnected endpoint $endpointId")
    }

    /**
     * Enqueues incoming raw bytes into the bounded queue.
     * If the queue is saturated, drops the packet to enforce backpressure.
     */
    fun offerIncoming(bytes: ByteArray): Boolean {
        if (!isPayloadSizeValid(bytes)) {
            logW(TAG, "Incoming payload rejected: size ${bytes.size} exceeds $MAX_PAYLOAD_BYTES limit")
            return false
        }
        val accepted = incomingQueue.offer(bytes)
        if (!accepted) {
            logW(TAG, "Incoming queue saturated (${incomingQueue.size}/$MAX_INCOMING_QUEUE_SIZE). Dropping packet for backpressure.")
        }
        return accepted
    }

    /**
     * Enqueues outgoing payload into the bounded queue.
     */
    fun offerOutgoing(bytes: ByteArray): Boolean {
        if (!isPayloadSizeValid(bytes)) {
            logW(TAG, "Outgoing payload rejected: size ${bytes.size} exceeds $MAX_PAYLOAD_BYTES limit")
            return false
        }
        val accepted = outgoingQueue.offer(bytes)
        if (!accepted) {
            logW(TAG, "Outgoing queue saturated (${outgoingQueue.size}/$MAX_OUTGOING_QUEUE_SIZE). Dropping dispatch for backpressure.")
        }
        return accepted
    }

    fun pollIncoming(): ByteArray? = incomingQueue.poll()
    fun pollOutgoing(): ByteArray? = outgoingQueue.poll()

    fun getIncomingQueueSize(): Int = incomingQueue.size
    fun getOutgoingQueueSize(): Int = outgoingQueue.size

    fun clearQueuesForTesting() {
        incomingQueue.clear()
        outgoingQueue.clear()
        endpointConnectionAttempts.clear()
    }
}

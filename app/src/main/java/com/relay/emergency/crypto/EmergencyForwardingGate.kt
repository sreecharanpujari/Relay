package com.relay.emergency.crypto

import android.content.Context
import com.relay.emergency.EmergencyRequest
import com.relay.emergency.mesh.MAX_STORE_FORWARD_HOPS
import com.relay.emergency.mesh.TransferType

sealed class ForwardingDecision {
    data class Allow(val stagedRequest: EmergencyRequest) : ForwardingDecision()
    data class Reject(val reason: String, val transferType: TransferType, val ackStatus: String? = null) : ForwardingDecision()
}

sealed class IngressDecision {
    data class Accept(val request: EmergencyRequest) : IngressDecision()
    data class Reject(val reason: String, val transferType: TransferType, val ackStatus: String) : IngressDecision()
}

/**
 * Pure, authoritative security gate evaluating packet forwarding and ingress.
 * Enforces cryptographic boundaries for initial requests and authenticated status updates.
 */
object EmergencyForwardingGate {

    /**
     * Evaluates whether an emergency request is allowed to be forwarded to a mesh peer.
     * Enforces the following rules:
     * 1. Expired requests are never forwarded.
     * 2. Unsigned requests are ONLY signed if proven to be locally created via [LocalOriginRegistry].
     *    Remotely supplied or mutable fields (originatorNodeId, hopCount, nodeHistory) are NEVER trusted.
     * 3. Signed requests MUST have valid Ed25519 author signatures before being forwarded.
     * 4. Status updates (sequenceNumber > 0) must have valid Ed25519 status signatures,
     *    bounded timestamps, and authorized updaters.
     * 5. Legitimate third-party requests have their original signatures and author identities preserved.
     */
    fun evaluateForwarding(
        context: Context?,
        request: EmergencyRequest,
        localNodeId: String
    ): ForwardingDecision {
        if (request.isExpired) {
            return ForwardingDecision.Reject(
                reason = "Request is expired",
                transferType = TransferType.EXPIRED
            )
        }

        if (!request.isCryptographicallySigned) {
            // Anti-Laundering Enforcement:
            // Only sign requests that are explicitly registered in LocalOriginRegistry.
            val isLocallyAuthored = LocalOriginRegistry.isLocallyAuthored(context, request.id)
            if (!isLocallyAuthored) {
                return ForwardingDecision.Reject(
                    reason = "Unauthenticated / unsigned request (not locally authored)",
                    transferType = TransferType.SECURITY_REJECTED
                )
            }

            return if (context != null) {
                try {
                    val signed = EmergencyPacketSigner.signRequest(context, request)
                    ForwardingDecision.Allow(signed)
                } catch (e: Exception) {
                    ForwardingDecision.Reject(
                        reason = "Signing failed: ${e.message}",
                        transferType = TransferType.SECURITY_REJECTED
                    )
                }
            } else {
                ForwardingDecision.Reject(
                    reason = "Context required to sign locally authored request",
                    transferType = TransferType.SECURITY_REJECTED
                )
            }
        } else {
            // Signed request: verify author signature integrity before forwarding
            if (!EmergencyPacketSigner.verifyRequest(request)) {
                return ForwardingDecision.Reject(
                    reason = "Signature verification failed (tampered or invalid packet)",
                    transferType = TransferType.SECURITY_REJECTED
                )
            }

            // Authenticated status update check
            if (request.sequenceNumber > 0) {
                if (!EmergencyPacketSigner.verifyStatusUpdate(request)) {
                    return ForwardingDecision.Reject(
                        reason = "Status update signature verification failed",
                        transferType = TransferType.SECURITY_REJECTED
                    )
                }
                if (!StatusAuthorizationPolicy.isTimestampWithinBounds(request.updatedAt)) {
                    return ForwardingDecision.Reject(
                        reason = "Status update timestamp exceeds future bounds",
                        transferType = TransferType.SECURITY_REJECTED
                    )
                }
                if (!StatusAuthorizationPolicy.isAuthorizedToUpdate(request, request.lastStatusUpdaterPublicKey, request.status)) {
                    return ForwardingDecision.Reject(
                        reason = "Status update signer is not authorized",
                        transferType = TransferType.SECURITY_REJECTED
                    )
                }
            }

            // Legitimate signed request: preserve original author's signature and identity
            return ForwardingDecision.Allow(request)
        }
    }

    /**
     * Evaluates incoming network payloads before accepting, storing, ACK-ing as delivered, or forwarding.
     * Rejects unsigned or invalidly signed packets at ingress.
     */
    fun evaluateIngress(
        incomingRequest: EmergencyRequest,
        localNodeId: String
    ): IngressDecision {
        if (!incomingRequest.isCryptographicallySigned) {
            return IngressDecision.Reject(
                reason = "Rejected: Missing Signature / Public Key",
                transferType = TransferType.SECURITY_REJECTED,
                ackStatus = "UNSIGNED_REJECTED"
            )
        }

        if (!EmergencyPacketSigner.verifyRequest(incomingRequest)) {
            return IngressDecision.Reject(
                reason = "Rejected: Signature Invalid / Tampered",
                transferType = TransferType.SECURITY_REJECTED,
                ackStatus = "SIGNATURE_INVALID"
            )
        }

        // Authenticated status update check
        if (incomingRequest.sequenceNumber > 0) {
            if (!EmergencyPacketSigner.verifyStatusUpdate(incomingRequest)) {
                return IngressDecision.Reject(
                    reason = "Rejected: Status update signature invalid",
                    transferType = TransferType.SECURITY_REJECTED,
                    ackStatus = "STATUS_SIGNATURE_INVALID"
                )
            }
            if (!StatusAuthorizationPolicy.isTimestampWithinBounds(incomingRequest.updatedAt)) {
                return IngressDecision.Reject(
                    reason = "Rejected: Status update timestamp is in the future",
                    transferType = TransferType.SECURITY_REJECTED,
                    ackStatus = "STATUS_TIMESTAMP_INVALID"
                )
            }
            if (!StatusAuthorizationPolicy.isAuthorizedToUpdate(incomingRequest, incomingRequest.lastStatusUpdaterPublicKey, incomingRequest.status)) {
                return IngressDecision.Reject(
                    reason = "Rejected: Status update signer not authorized",
                    transferType = TransferType.SECURITY_REJECTED,
                    ackStatus = "STATUS_UNAUTHORIZED"
                )
            }
        }

        if (incomingRequest.isExpired) {
            return IngressDecision.Reject(
                reason = "Dropped: Expired",
                transferType = TransferType.EXPIRED,
                ackStatus = "EXPIRED"
            )
        }

        if (incomingRequest.hopCount > MAX_STORE_FORWARD_HOPS) {
            return IngressDecision.Reject(
                reason = "Max $MAX_STORE_FORWARD_HOPS hops exceeded",
                transferType = TransferType.LOOP_PREVENTED,
                ackStatus = "MAX_HOPS"
            )
        }

        return IngressDecision.Accept(incomingRequest)
    }
}

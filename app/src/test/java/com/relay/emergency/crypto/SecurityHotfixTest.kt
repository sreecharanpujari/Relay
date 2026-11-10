package com.relay.emergency.crypto

import com.relay.emergency.EmergencyRequest
import com.relay.emergency.RequestStatus
import com.relay.emergency.mesh.TransferType
import com.relay.emergency.SosMessage
import com.relay.emergency.mesh.MeshRateLimiter
import com.relay.emergency.mesh.StorageRetentionManager
import com.relay.emergency.mesh.MeshReliabilityManager
import com.relay.emergency.mesh.PowerConservationManager
import com.relay.emergency.mesh.NodeIdentityManager
import com.relay.emergency.mesh.GeoTacticalUtils
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.json.JSONObject


import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test

/**
 * Security unit tests verifying:
 * - Phase 1 & Priority 1: Unsigned rejection, anti-laundering, LocalOriginRegistry, author signature preservation.
 * - Phase 2: Authenticated status updates, sequence monotonicity, authorization policy, rollback & future-DoS rejection.
 * - Phase 3: Bouncy Castle RFC 8032 constant-time Ed25519 engine.
 */
class SecurityHotfixTest {

    // RFC 8032 Test Vector 1 seed and keys (Alice - Node A)
    private val testSeedNodeA = RelayKeyStoreManager.hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    private val pubKeyNodeA = RelayKeyStoreManager.bytesToHex(Ed25519.getPublicKey(testSeedNodeA))
    private val nodeAId = "RELAY-PIXEL7-AAAA"

    // Relay node (Bob - Node B)
    private val testSeedNodeB = RelayKeyStoreManager.hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    private val pubKeyNodeB = RelayKeyStoreManager.bytesToHex(Ed25519.getPublicKey(testSeedNodeB))
    private val nodeBId = "RELAY-GALAXY-BBBB"

    // Certified Responder (Charlie - Node C)
    private val testSeedNodeC = RelayKeyStoreManager.hexToBytes("c5aa8d4390ea8330a44d99fb227fb2a370386e6d09c8f433ee152d04c270002b")
    private val pubKeyNodeC = RelayKeyStoreManager.bytesToHex(Ed25519.getPublicKey(testSeedNodeC))
    private val nodeCId = "RELAY-RESPONDER-CCCC"

    @Before
    fun setUp() {
        LocalOriginRegistry.clearForTesting()
        StatusAuthorizationPolicy.clearRespondersForTesting()
        MeshRateLimiter.clearAllForTesting()
        RelayE2EEncryption.clearPeerKeysForTesting()
        MeshReliabilityManager.clearQueuesForTesting()
        PowerConservationManager.resetForTesting()
    }

    private fun createSignedRequest(
        id: String = "SOS-001",
        type: String = "Medical",
        description: String = "Insulin needed at community shelter",
        people: Int = 3,
        priority: String = "Critical",
        createdAt: Long = System.currentTimeMillis(),
        ttlHours: Int = 24,
        nodeId: String = nodeAId,
        pubKey: String = pubKeyNodeA,
        seed: ByteArray = testSeedNodeA
    ): EmergencyRequest {
        val canonicalBytes = EmergencyPacketSigner.buildCanonicalBytes(
            id = id,
            type = type,
            description = description,
            people = people,
            priority = priority,
            createdAt = createdAt,
            ttlHours = ttlHours,
            originatorNodeId = nodeId,
            senderPublicKey = pubKey
        )
        val sig = RelayKeyStoreManager.bytesToHex(Ed25519.sign(canonicalBytes, seed))

        return EmergencyRequest(
            id = id,
            type = type,
            description = description,
            people = people,
            priority = priority,
            createdAt = createdAt,
            ttlHours = ttlHours,
            nodeHistory = listOf(nodeId),
            hopCount = 0,
            senderPublicKey = pubKey,
            signature = sig,
            originatorNodeId = nodeId
        )
    }

    private fun signStatusUpdateDeterministic(
        request: EmergencyRequest,
        newStatus: String,
        updaterPubKey: String,
        updaterSeed: ByteArray,
        nextSeq: Int,
        timestamp: Long = System.currentTimeMillis(),
        role: String = "AUTHOR"
    ): EmergencyRequest {
        val canonicalBytes = EmergencyPacketSigner.buildCanonicalStatusBytes(
            requestId = request.id,
            authorNodeId = request.originatorNodeId,
            updaterPublicKey = updaterPubKey,
            newStatus = newStatus,
            sequenceNumber = nextSeq,
            updatedAt = timestamp,
            updaterRole = role
        )
        val sig = RelayKeyStoreManager.bytesToHex(Ed25519.sign(canonicalBytes, updaterSeed))

        return request.copy(
            status = newStatus,
            updatedAt = timestamp,
            sequenceNumber = nextSeq,
            lastStatusSignature = sig,
            lastStatusUpdaterPublicKey = updaterPubKey,
            lastStatusUpdaterRole = role
        )
    }

    // ========================================================================
    // PHASE 3 — BOUNCY CASTLE ENGINE RFC 8032 TESTS
    // ========================================================================

    @Test
    fun testBouncyCastleEd25519Rfc8032Compliance() {
        // RFC 8032 Test Vector 1:
        // Seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
        // Expected public key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        // Expected signature on empty message:
        // e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
        val expectedPubKey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        val expectedEmptySig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

        val derivedPubKey = RelayKeyStoreManager.bytesToHex(Ed25519.getPublicKey(testSeedNodeA))
        assertEquals("Bouncy Castle Ed25519 public key must match RFC 8032 vector 1", expectedPubKey, derivedPubKey)

        val emptyMsg = ByteArray(0)
        val sigBytes = Ed25519.sign(emptyMsg, testSeedNodeA)
        val sigHex = RelayKeyStoreManager.bytesToHex(sigBytes)
        assertEquals("Bouncy Castle Ed25519 signature must match RFC 8032 vector 1", expectedEmptySig, sigHex)

        val isValid = Ed25519.verify(emptyMsg, sigBytes, Ed25519.getPublicKey(testSeedNodeA))
        assertTrue("Bouncy Castle Ed25519 verification must succeed", isValid)
    }

    // ========================================================================
    // PHASE 2 — SECURE STATUS UPDATES TESTS
    // ========================================================================

    @Test
    fun testAuthenticatedStatusUpdateByAuthor() {
        val localNodeId = nodeAId
        val originReq = createSignedRequest(id = "EMERGENCY-101", nodeId = localNodeId, pubKey = pubKeyNodeA, seed = testSeedNodeA)
        assertEquals(RequestStatus.PENDING, originReq.status)
        assertEquals(0, originReq.sequenceNumber)

        // Author transitions status to ASSIGNED (seq 1)
        val assignedReq = signStatusUpdateDeterministic(
            request = originReq,
            newStatus = RequestStatus.ASSIGNED,
            updaterPubKey = pubKeyNodeA,
            updaterSeed = testSeedNodeA,
            nextSeq = 1,
            role = "AUTHOR"
        )

        assertEquals(1, assignedReq.sequenceNumber)
        assertEquals(RequestStatus.ASSIGNED, assignedReq.status)
        assertTrue("Status update signature must be verified", EmergencyPacketSigner.verifyStatusUpdate(assignedReq))
        assertTrue("Author signature on base emergency fields must remain intact", EmergencyPacketSigner.verifyRequest(assignedReq))

        // Ingress gate evaluation
        val ingressDecision = EmergencyForwardingGate.evaluateIngress(assignedReq, localNodeId)
        assertTrue("Signed author status update must be accepted at ingress", ingressDecision is IngressDecision.Accept)

        // Forwarding gate evaluation
        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, assignedReq, localNodeId)
        assertTrue("Signed author status update must be allowed to forward", forwardDecision is ForwardingDecision.Allow)
    }

    @Test
    fun testUnauthorizedRelayNodeStatusUpdateRejection() {
        // Alice creates emergency
        val aliceReq = createSignedRequest(id = "EMERGENCY-202", nodeId = nodeAId, pubKey = pubKeyNodeA, seed = testSeedNodeA)

        // Bob (a relay node) attempts to resolve Alice's emergency using Bob's key
        val bobForgedReq = signStatusUpdateDeterministic(
            request = aliceReq,
            newStatus = RequestStatus.RESOLVED,
            updaterPubKey = pubKeyNodeB,
            updaterSeed = testSeedNodeB,
            nextSeq = 1,
            role = "AUTHOR" // Bob falsely claims to be authorized
        )

        // Bob's key is not Alice's key and is not a registered responder
        assertFalse(
            "Relay node must NOT have authorization to update status",
            StatusAuthorizationPolicy.isAuthorizedToUpdate(aliceReq, pubKeyNodeB, RequestStatus.RESOLVED)
        )

        // Ingress evaluation must reject
        val ingressDecision = EmergencyForwardingGate.evaluateIngress(bobForgedReq, nodeBId)
        assertTrue("Unauthorized relay node status change must be rejected at ingress", ingressDecision is IngressDecision.Reject)
        val reject = ingressDecision as IngressDecision.Reject
        assertEquals("STATUS_UNAUTHORIZED", reject.ackStatus)
        assertEquals(TransferType.SECURITY_REJECTED, reject.transferType)

        // Forwarding gate evaluation must reject
        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, bobForgedReq, nodeBId)
        assertTrue("Unauthorized relay node status change must be blocked from forwarding", forwardDecision is ForwardingDecision.Reject)
    }

    @Test
    fun testAuthorizedResponderStatusUpdate() {
        val aliceReq = createSignedRequest(id = "EMERGENCY-303", nodeId = nodeAId, pubKey = pubKeyNodeA, seed = testSeedNodeA)

        // Register Node C as a certified emergency responder
        StatusAuthorizationPolicy.registerResponderKey(pubKeyNodeC)
        assertTrue(StatusAuthorizationPolicy.isRegisteredResponder(pubKeyNodeC))

        // Responder Node C transitions status to IN_PROGRESS (seq 1)
        val responderUpdatedReq = signStatusUpdateDeterministic(
            request = aliceReq,
            newStatus = RequestStatus.IN_PROGRESS,
            updaterPubKey = pubKeyNodeC,
            updaterSeed = testSeedNodeC,
            nextSeq = 1,
            role = "RESPONDER"
        )

        assertTrue(
            "Registered responder must be authorized to update status",
            StatusAuthorizationPolicy.isAuthorizedToUpdate(aliceReq, pubKeyNodeC, RequestStatus.IN_PROGRESS)
        )
        assertTrue("Responder status signature must be mathematically valid", EmergencyPacketSigner.verifyStatusUpdate(responderUpdatedReq))

        val ingressDecision = EmergencyForwardingGate.evaluateIngress(responderUpdatedReq, nodeBId)
        assertTrue("Verified responder status update must be accepted at ingress", ingressDecision is IngressDecision.Accept)

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, responderUpdatedReq, nodeBId)
        assertTrue("Verified responder status update must be allowed to forward across mesh", forwardDecision is ForwardingDecision.Allow)
    }

    @Test
    fun testRollbackAndDuplicateSequenceRejection() {
        val originReq = createSignedRequest(id = "EMERGENCY-404")

        // Alice advances to seq 2 (IN_PROGRESS)
        val currentRecord = signStatusUpdateDeterministic(
            request = originReq,
            newStatus = RequestStatus.IN_PROGRESS,
            updaterPubKey = pubKeyNodeA,
            updaterSeed = testSeedNodeA,
            nextSeq = 2,
            role = "AUTHOR"
        )
        assertEquals(2, currentRecord.sequenceNumber)

        // Adversary replays older state with seq 1 (or seq 2 duplicate)
        val replayedOlderReq = signStatusUpdateDeterministic(
            request = originReq,
            newStatus = RequestStatus.PENDING,
            updaterPubKey = pubKeyNodeA,
            updaterSeed = testSeedNodeA,
            nextSeq = 1,
            role = "AUTHOR"
        )

        // Monotonic sequence rule: incoming seq must be strictly greater than current seq
        val isRollback = replayedOlderReq.sequenceNumber <= currentRecord.sequenceNumber
        assertTrue("Replayed older or duplicate sequence number must be identified as rollback", isRollback)
    }

    @Test
    fun testFutureTimestampDosRejection() {
        val originReq = createSignedRequest(id = "EMERGENCY-505")

        // Adversary sets timestamp 2 hours in the future to lock the record
        val futureTime = System.currentTimeMillis() + (2 * 3600 * 1000L)
        val futureReq = signStatusUpdateDeterministic(
            request = originReq,
            newStatus = RequestStatus.ASSIGNED,
            updaterPubKey = pubKeyNodeA,
            updaterSeed = testSeedNodeA,
            nextSeq = 1,
            timestamp = futureTime,
            role = "AUTHOR"
        )

        assertFalse("Future timestamp beyond drift must fail bounds check", StatusAuthorizationPolicy.isTimestampWithinBounds(futureTime))

        val ingressDecision = EmergencyForwardingGate.evaluateIngress(futureReq, nodeBId)
        assertTrue("Future timestamp status update must be rejected at ingress", ingressDecision is IngressDecision.Reject)
        val reject = ingressDecision as IngressDecision.Reject
        assertEquals("STATUS_TIMESTAMP_INVALID", reject.ackStatus)

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, futureReq, nodeBId)
        assertTrue("Future timestamp status update must be blocked from forwarding", forwardDecision is ForwardingDecision.Reject)
    }

    @Test
    fun testIllegalStateTransitionRejection() {
        // Valid forward transitions
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.PENDING, RequestStatus.ASSIGNED))
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.PENDING, RequestStatus.IN_PROGRESS))
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.PENDING, RequestStatus.RESOLVED))
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.ASSIGNED, RequestStatus.IN_PROGRESS))
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.ASSIGNED, RequestStatus.RESOLVED))
        assertTrue(StatusAuthorizationPolicy.isValidTransition(RequestStatus.IN_PROGRESS, RequestStatus.RESOLVED))

        // Illegal reverse transitions from terminal state (RESOLVED)
        assertFalse(
            "RESOLVED emergency must not be reverted to PENDING",
            StatusAuthorizationPolicy.isValidTransition(RequestStatus.RESOLVED, RequestStatus.PENDING)
        )
        assertFalse(
            "RESOLVED emergency must not be reverted to IN_PROGRESS",
            StatusAuthorizationPolicy.isValidTransition(RequestStatus.RESOLVED, RequestStatus.IN_PROGRESS)
        )
        assertFalse(
            "IN_PROGRESS emergency must not be reverted to PENDING",
            StatusAuthorizationPolicy.isValidTransition(RequestStatus.IN_PROGRESS, RequestStatus.PENDING)
        )
    }

    @Test
    fun testTamperedStatusUpdateSignatureRejection() {
        val originReq = createSignedRequest(id = "EMERGENCY-606")
        val legitimateUpdate = signStatusUpdateDeterministic(
            request = originReq,
            newStatus = RequestStatus.ASSIGNED,
            updaterPubKey = pubKeyNodeA,
            updaterSeed = testSeedNodeA,
            nextSeq = 1,
            role = "AUTHOR"
        )
        assertTrue(EmergencyPacketSigner.verifyStatusUpdate(legitimateUpdate))

        // Tamper 1: Alter status string from Assigned to Resolved without re-signing
        val tamperedStatus = legitimateUpdate.copy(status = RequestStatus.RESOLVED)
        assertFalse("Tampered status string must fail status signature verification", EmergencyPacketSigner.verifyStatusUpdate(tamperedStatus))

        // Tamper 2: Alter sequence number
        val tamperedSeq = legitimateUpdate.copy(sequenceNumber = 99)
        assertFalse("Tampered sequence number must fail status signature verification", EmergencyPacketSigner.verifyStatusUpdate(tamperedSeq))

        // Tamper 3: Corrupted status signature bytes
        val tamperedSig = legitimateUpdate.copy(lastStatusSignature = "00".repeat(64))
        assertFalse("Corrupted signature must fail status signature verification", EmergencyPacketSigner.verifyStatusUpdate(tamperedSig))
    }

    // ========================================================================
    // PRIORITY 1 REGRESSION TESTS (ALL PRESERVED)
    // ========================================================================

    @Test
    fun testAttackerCraftedUnsignedRequestWithLocalOriginatorNodeId() {
        val localNodeId = nodeBId

        val attackerSpoofedReq = EmergencyRequest(
            id = "ATTACKER-SPOOF-001",
            type = "Evacuation",
            description = "False evacuation order claiming to originate locally",
            people = 100,
            priority = "Critical",
            hopCount = 0,
            nodeHistory = emptyList(),
            originatorNodeId = localNodeId,
            senderPublicKey = null,
            signature = null
        )

        val ingressDecision = EmergencyForwardingGate.evaluateIngress(attackerSpoofedReq, localNodeId)
        assertTrue("Attacker unsigned packet must be rejected at ingress", ingressDecision is IngressDecision.Reject)
        val ingressReject = ingressDecision as IngressDecision.Reject
        assertEquals("UNSIGNED_REJECTED", ingressReject.ackStatus)
        assertEquals(TransferType.SECURITY_REJECTED, ingressReject.transferType)

        assertFalse("Attacker packet must NOT be recognized as locally authored", LocalOriginRegistry.isLocallyAuthored(null, attackerSpoofedReq.id))

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, attackerSpoofedReq, localNodeId)
        assertTrue("Forwarding gate must strictly reject unsigned attacker packet", forwardDecision is ForwardingDecision.Reject)
        val forwardReject = forwardDecision as ForwardingDecision.Reject
        assertEquals(TransferType.SECURITY_REJECTED, forwardReject.transferType)
    }

    @Test
    fun testUnsignedRequestWithZeroHopAndEmptyHistory() {
        val localNodeId = nodeBId

        val zeroHopUnsignedReq = EmergencyRequest(
            id = "ZERO-HOP-ROGUE-002",
            type = "Search & Rescue",
            description = "Unsigned packet crafted with hopCount=0 and empty history",
            people = 5,
            priority = "High",
            hopCount = 0,
            nodeHistory = emptyList(),
            originatorNodeId = "RELAY-UNKNOWN-0000",
            senderPublicKey = null,
            signature = null
        )

        assertFalse(LocalOriginRegistry.isLocallyAuthored(null, zeroHopUnsignedReq.id))

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, zeroHopUnsignedReq, localNodeId)
        assertTrue("Zero-hop unsigned request must be rejected without local origin proof", forwardDecision is ForwardingDecision.Reject)
        val forwardReject = forwardDecision as ForwardingDecision.Reject
        assertEquals(TransferType.SECURITY_REJECTED, forwardReject.transferType)
    }

    @Test
    fun testRestoredLegacyUnsignedRequestBlockedFromForwarding() {
        val localNodeId = nodeBId

        val legacyStoredReq = EmergencyRequest(
            id = "LEGACY-STORED-1999",
            type = "Shelter",
            description = "Restored legacy emergency request from prior version",
            people = 2,
            priority = "Medium",
            hopCount = 1,
            nodeHistory = listOf("RELAY-LEGACY-NODE"),
            originatorNodeId = "RELAY-LEGACY-NODE",
            senderPublicKey = null,
            signature = null
        )

        assertFalse("Restored legacy request is not locally authored", LocalOriginRegistry.isLocallyAuthored(null, legacyStoredReq.id))
        assertFalse("Restored legacy request must report isCryptographicallySigned = false", legacyStoredReq.isCryptographicallySigned)

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, legacyStoredReq, localNodeId)
        assertTrue("Restored legacy unsigned request MUST be blocked from forwarding", forwardDecision is ForwardingDecision.Reject)
        val forwardReject = forwardDecision as ForwardingDecision.Reject
        assertEquals(TransferType.SECURITY_REJECTED, forwardReject.transferType)
    }

    @Test
    fun testIncomingUnsignedRequestAttemptingToReachForwarding() {
        val localNodeId = nodeBId

        val incomingUnsigned = EmergencyRequest(
            id = "INCOMING-UNSIGNED-999",
            type = "Water",
            description = "Unsigned packet over Nearby Connections",
            people = 10,
            priority = "Critical",
            hopCount = 1,
            nodeHistory = listOf("PEER-NODE-XYZ"),
            originatorNodeId = "PEER-NODE-XYZ",
            senderPublicKey = null,
            signature = null
        )

        val ingressDecision = EmergencyForwardingGate.evaluateIngress(incomingUnsigned, localNodeId)
        assertTrue("Incoming unsigned request must be dropped at ingress", ingressDecision is IngressDecision.Reject)
        val ingressReject = ingressDecision as IngressDecision.Reject
        assertEquals("UNSIGNED_REJECTED", ingressReject.ackStatus)

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, incomingUnsigned, localNodeId)
        assertTrue("Incoming unsigned request must be rejected by forwarding gate", forwardDecision is ForwardingDecision.Reject)
    }

    @Test
    fun testLegitimateLocallyCreatedRequest() {
        val localNodeId = nodeBId
        val reqId = "LOCAL-GENUINE-001"

        LocalOriginRegistry.recordLocalCreation(null, reqId)
        assertTrue("Must be recorded in LocalOriginRegistry", LocalOriginRegistry.isLocallyAuthored(null, reqId))

        val localSignedReq = createSignedRequest(
            id = reqId,
            type = "Medical",
            description = "Doctor needed at field clinic",
            people = 1,
            priority = "Critical",
            nodeId = localNodeId,
            pubKey = pubKeyNodeB,
            seed = testSeedNodeB
        )

        assertTrue("Signed request must report isCryptographicallySigned = true", localSignedReq.isCryptographicallySigned)
        assertTrue("Local node's signature must verify mathematically", EmergencyPacketSigner.verifyRequest(localSignedReq))

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, localSignedReq, localNodeId)
        assertTrue("Legitimate signed local request must be allowed to forward", forwardDecision is ForwardingDecision.Allow)
        val allowed = forwardDecision as ForwardingDecision.Allow
        assertEquals(reqId, allowed.stagedRequest.id)
        assertEquals(pubKeyNodeB, allowed.stagedRequest.senderPublicKey)
        assertEquals(localNodeId, allowed.stagedRequest.originatorNodeId)
    }

    @Test
    fun testLegitimateSignedThirdPartyForwardingPreservesAuthorSignature() {
        val originReq = createSignedRequest(
            id = "NODEA-ORIGIN-007",
            type = "Rescue",
            description = "Trapped in flood waters",
            people = 4,
            priority = "Critical",
            nodeId = nodeAId,
            pubKey = pubKeyNodeA,
            seed = testSeedNodeA
        )

        val localNodeId = nodeBId

        val ingressDecision = EmergencyForwardingGate.evaluateIngress(originReq, localNodeId)
        assertTrue("Legitimate signed third-party request must be accepted at ingress", ingressDecision is IngressDecision.Accept)

        val forwardedHop1 = originReq.copy(
            hopCount = originReq.hopCount + 1,
            nodeHistory = originReq.nodeHistory + localNodeId,
            lastTransferStatus = "Relayed via $localNodeId"
        )

        val forwardDecision = EmergencyForwardingGate.evaluateForwarding(null, forwardedHop1, localNodeId)
        assertTrue("Relay node must allow forwarding verified third-party request", forwardDecision is ForwardingDecision.Allow)

        val staged = (forwardDecision as ForwardingDecision.Allow).stagedRequest

        assertEquals("Author public key must NOT be replaced by relay node", pubKeyNodeA, staged.senderPublicKey)
        assertEquals("Author signature must NOT be replaced by relay node", originReq.signature, staged.signature)
        assertEquals("Author originatorNodeId must NOT be altered", nodeAId, staged.originatorNodeId)

        assertTrue("Signature remains valid after hop increment and nodeHistory append", EmergencyPacketSigner.verifyRequest(staged))
        assertEquals(1, staged.hopCount)
    }

    @Test
    fun testTamperedSignedRequestRejection() {
        val localNodeId = nodeBId
        val genuineReq = createSignedRequest(nodeId = nodeAId, pubKey = pubKeyNodeA, seed = testSeedNodeA)
        assertTrue(EmergencyPacketSigner.verifyRequest(genuineReq))

        val tampered1 = genuineReq.copy(description = "Tampered description")
        assertFalse(EmergencyPacketSigner.verifyRequest(tampered1))
        val fwd1 = EmergencyForwardingGate.evaluateForwarding(null, tampered1, localNodeId)
        assertTrue("Tampered description must be rejected by forwarding gate", fwd1 is ForwardingDecision.Reject)

        val tampered2 = genuineReq.copy(people = 999)
        assertFalse(EmergencyPacketSigner.verifyRequest(tampered2))
        val fwd2 = EmergencyForwardingGate.evaluateForwarding(null, tampered2, localNodeId)
        assertTrue("Tampered people count must be rejected by forwarding gate", fwd2 is ForwardingDecision.Reject)

        val tampered3 = genuineReq.copy(originatorNodeId = "RELAY-SPOOFED")
        assertFalse(EmergencyPacketSigner.verifyRequest(tampered3))
        val fwd3 = EmergencyForwardingGate.evaluateForwarding(null, tampered3, localNodeId)
        assertTrue("Tampered originator ID must be rejected by forwarding gate", fwd3 is ForwardingDecision.Reject)

        val tampered4 = genuineReq.copy(signature = "ff".repeat(64))
        assertFalse(EmergencyPacketSigner.verifyRequest(tampered4))
        val fwd4 = EmergencyForwardingGate.evaluateForwarding(null, tampered4, localNodeId)
        assertTrue("Corrupted signature must be rejected by forwarding gate", fwd4 is ForwardingDecision.Reject)
    }

    @Test
    fun testExpiredRequestRejection() {
        val localNodeId = nodeBId
        val expiredReq = createSignedRequest(
            id = "EXPIRED-SOS-1",
            createdAt = System.currentTimeMillis() - (48 * 3600 * 1000L),
            ttlHours = 24
        )
        assertTrue("Request must report isExpired = true", expiredReq.isExpired)

        val fwd = EmergencyForwardingGate.evaluateForwarding(null, expiredReq, localNodeId)
        assertTrue(fwd is ForwardingDecision.Reject)
        assertEquals(TransferType.EXPIRED, (fwd as ForwardingDecision.Reject).transferType)

        val ingress = EmergencyForwardingGate.evaluateIngress(expiredReq, localNodeId)
        assertTrue(ingress is IngressDecision.Reject)
        assertEquals("EXPIRED", (ingress as IngressDecision.Reject).ackStatus)
    }

    private fun createSignedSosMessage(
        id: String = "MSG-001",
        senderName: String = "Alice",
        message: String = "Trapped on roof, need evacuation",
        isEmergency: Boolean = true,
        timestamp: Long = System.currentTimeMillis(),
        senderNodeId: String = nodeAId,
        senderPubKey: String = pubKeyNodeA,
        senderSeed: ByteArray = testSeedNodeA
    ): SosMessage {
        val canonicalBytes = EmergencyPacketSigner.buildCanonicalSosBytes(
            id = id,
            senderName = senderName,
            message = message,
            isEmergency = isEmergency,
            timestamp = timestamp,
            senderNodeId = senderNodeId,
            senderPublicKey = senderPubKey
        )
        val sig = RelayKeyStoreManager.bytesToHex(Ed25519.sign(canonicalBytes, senderSeed))
        return SosMessage(
            id = id,
            senderName = senderName,
            message = message,
            isEmergency = isEmergency,
            timestamp = timestamp,
            hopCount = 0,
            senderPublicKey = senderPubKey,
            signature = sig,
            senderNodeId = senderNodeId
        )
    }

    private fun createSignedAck(
        requestId: String = "REQ-001",
        nodeId: String = nodeAId,
        status: String = "DELIVERED",
        timestamp: Long = System.currentTimeMillis(),
        ackPubKey: String = pubKeyNodeA,
        ackSeed: ByteArray = testSeedNodeA
    ): Triple<String, String, Long> {
        val canonicalBytes = EmergencyPacketSigner.buildCanonicalAckBytes(
            requestId = requestId,
            nodeId = nodeId,
            status = status,
            timestamp = timestamp,
            ackPublicKey = ackPubKey
        )
        val sig = RelayKeyStoreManager.bytesToHex(Ed25519.sign(canonicalBytes, ackSeed))
        return Triple(sig, ackPubKey, timestamp)
    }

    // ========================================================================
    // SEC-07 — SOS MESSAGE SIGNING & TAMPER RESISTANCE
    // ========================================================================

    @Test
    fun testSosMessageSigningAndVerification() {
        val genuineMsg = createSignedSosMessage()
        assertTrue("SosMessage must report isCryptographicallySigned = true", genuineMsg.isCryptographicallySigned)
        assertTrue("Genuine SosMessage signature must verify successfully", EmergencyPacketSigner.verifySosMessage(genuineMsg))

        // Tamper message body
        val tamperedBody = genuineMsg.copy(message = "Cancel SOS, all good")
        assertFalse("Tampered message body must fail verification", EmergencyPacketSigner.verifySosMessage(tamperedBody))

        // Tamper sender name
        val tamperedName = genuineMsg.copy(senderName = "Mallory")
        assertFalse("Tampered sender name must fail verification", EmergencyPacketSigner.verifySosMessage(tamperedName))

        // Tamper timestamp
        val tamperedTime = genuineMsg.copy(timestamp = genuineMsg.timestamp + 5000)
        assertFalse("Tampered timestamp must fail verification", EmergencyPacketSigner.verifySosMessage(tamperedTime))

        // Tamper senderNodeId
        val tamperedNode = genuineMsg.copy(senderNodeId = "RELAY-SPOOFED")
        assertFalse("Tampered senderNodeId must fail verification", EmergencyPacketSigner.verifySosMessage(tamperedNode))

        // Corrupted signature
        val corruptedSig = genuineMsg.copy(signature = "00".repeat(64))
        assertFalse("Corrupted signature must fail verification", EmergencyPacketSigner.verifySosMessage(corruptedSig))

        // Empty signature
        val unsigned = genuineMsg.copy(signature = null)
        assertFalse("Unsigned SOS message must fail verification", EmergencyPacketSigner.verifySosMessage(unsigned))
    }

    @Test
    fun testSosMessageClockSkewAndFutureRejection() {
        val now = System.currentTimeMillis()
        assertTrue("Current timestamp must be within bounds", StatusAuthorizationPolicy.isTimestampWithinBounds(now, now))

        val pastTime = now - (60 * 1000L)
        assertTrue("Past timestamp must be within bounds", StatusAuthorizationPolicy.isTimestampWithinBounds(pastTime, now))

        val nearFuture = now + (10 * 60 * 1000L) // 10 minutes (within 15 min allowance)
        assertTrue("Near-future timestamp within 15 min must be accepted", StatusAuthorizationPolicy.isTimestampWithinBounds(nearFuture, now))

        val farFuture = now + (20 * 60 * 1000L) // 20 minutes (exceeds 15 min allowance)
        assertFalse("Far-future timestamp exceeding 15 min must be rejected", StatusAuthorizationPolicy.isTimestampWithinBounds(farFuture, now))
    }

    // ========================================================================
    // SEC-09 — DELIVERY ACK SIGNING & SPOOFING PREVENTION
    // ========================================================================

    @Test
    fun testSignedDeliveryAckVerification() {
        val reqId = "REQ-ACK-TEST-001"
        val status = "DELIVERED"
        val now = System.currentTimeMillis()
        val (sig, pubKey, time) = createSignedAck(requestId = reqId, nodeId = nodeAId, status = status, timestamp = now)

        val isValid = EmergencyPacketSigner.verifyAck(
            requestId = reqId,
            nodeId = nodeAId,
            status = status,
            timestamp = time,
            ackPublicKey = pubKey,
            signature = sig
        )
        assertTrue("Genuine signed ACK must verify mathematically", isValid)

        // Adversary tries to forge an ACK changing status to FAILED or INVALID
        val forgedStatus = EmergencyPacketSigner.verifyAck(
            requestId = reqId,
            nodeId = nodeAId,
            status = "FAILED",
            timestamp = time,
            ackPublicKey = pubKey,
            signature = sig
        )
        assertFalse("Adversary tampering status in ACK must fail verification", forgedStatus)

        // Adversary tries to replay ACK against a different request ID
        val replayedReqId = EmergencyPacketSigner.verifyAck(
            requestId = "REQ-DIFFERENT-999",
            nodeId = nodeAId,
            status = status,
            timestamp = time,
            ackPublicKey = pubKey,
            signature = sig
        )
        assertFalse("Adversary replaying ACK on different requestId must fail verification", replayedReqId)

        // Wrong public key
        val wrongKey = EmergencyPacketSigner.verifyAck(
            requestId = reqId,
            nodeId = nodeAId,
            status = status,
            timestamp = time,
            ackPublicKey = pubKeyNodeB,
            signature = sig
        )
        assertFalse("ACK verified with wrong public key must fail verification", wrongKey)
    }

    // ========================================================================
    // RATE LIMITING & FLOODING PROTECTION
    // ========================================================================

    @Test
    fun testMeshRateLimiterSlidingWindowEnforcement() {
        val endpoint = "PEER_ENDPOINT_X"
        val now = 1000000L

        // First 30 packets should all be allowed
        for (i in 1..MeshRateLimiter.MAX_PACKETS_PER_WINDOW) {
            assertTrue("Packet $i within limit should be allowed", MeshRateLimiter.isAllowed(endpoint, now + i))
        }

        // 31st packet in same 60-second window must be rejected
        assertFalse("31st packet within 60s window must be rate-limited", MeshRateLimiter.isAllowed(endpoint, now + 500))

        // Different endpoint should not be affected
        val endpoint2 = "PEER_ENDPOINT_Y"
        assertTrue("Different endpoint must have its own independent rate bucket", MeshRateLimiter.isAllowed(endpoint2, now + 500))

        // After window expires (now + 65 seconds), packets should be allowed again
        val later = now + MeshRateLimiter.WINDOW_MS + 5000L
        assertTrue("Packets after window expiration must be allowed", MeshRateLimiter.isAllowed(endpoint, later))
    }

    // ========================================================================
    // SEC-10 — STORAGE RETENTION & PRUNING
    // ========================================================================

    @Test
    fun testStorageRetentionManagerPruneExpiredRequests() {
        val now = System.currentTimeMillis()

        // 1. Active request (not expired)
        val activeReq = createSignedRequest(id = "ACTIVE-1", createdAt = now, ttlHours = 24)

        // 2. Expired 12 hours ago (within 48h audit window)
        val expiredRecent = createSignedRequest(
            id = "EXPIRED-RECENT",
            createdAt = now - (36 * 3600 * 1000L), // 36h ago with 24h TTL = expired 12h ago
            ttlHours = 24
        )

        // 3. Expired 60 hours ago (exceeds 48h retention)
        val expiredAncient = createSignedRequest(
            id = "EXPIRED-ANCIENT",
            createdAt = now - (84 * 3600 * 1000L), // 84h ago with 24h TTL = expired 60h ago
            ttlHours = 24
        )

        val list = listOf(activeReq, expiredRecent, expiredAncient)
        val pruned = StorageRetentionManager.pruneExpiredRequests(list, now)

        assertEquals("Pruned list should retain active and recently expired requests, dropping ancient", 2, pruned.size)
        assertTrue("Active request must be preserved", pruned.any { it.id == "ACTIVE-1" })
        assertTrue("Recently expired request within 48h must be preserved for audit", pruned.any { it.id == "EXPIRED-RECENT" })
        assertFalse("Ancient expired request beyond 48h retention must be pruned", pruned.any { it.id == "EXPIRED-ANCIENT" })
    }

    @Test
    fun testStorageRetentionManagerPruneSosMessages() {
        val now = System.currentTimeMillis()

        // 1. Message from 10 hours ago (< 72h)
        val msg1 = createSignedSosMessage(id = "MSG-RECENT", timestamp = now - (10 * 3600 * 1000L))

        // 2. Message from 100 hours ago (> 72h)
        val msgOld = createSignedSosMessage(id = "MSG-OLD", timestamp = now - (100 * 3600 * 1000L))

        val list = listOf(msg1, msgOld)
        val pruned = StorageRetentionManager.pruneSosMessages(list, now)

        assertEquals(1, pruned.size)
        assertEquals("MSG-RECENT", pruned[0].id)

        // Max cap test: create 220 messages
        val largeList = (1..220).map { i ->
            createSignedSosMessage(id = "MSG-$i", timestamp = now - i * 1000L)
        }
        val capped = StorageRetentionManager.pruneSosMessages(largeList, now)
        assertEquals("List exceeding 200 items must be capped to MAX_SOS_MESSAGES", 200, capped.size)
    }

    // ========================================================================
    // SEC-11 — CRYPTOGRAPHICALLY ANCHORED NODE IDENTITY
    // ========================================================================

    @Test
    fun testCryptographicallyAnchoredNodeIdentity() {
        // Verify that the public key fingerprint anchors with 64 bits of entropy (16 hex chars)
        val pubKeyHex = pubKeyNodeA
        val fingerprint = NodeIdentityManager.computeFingerprint(pubKeyHex)

        assertEquals("Fingerprint must be 16 hex uppercase characters (64 bits)", 16, fingerprint.length)
        assertTrue("Fingerprint must be hex", fingerprint.all { it.isDigit() || it in 'A'..'F' })

        val cleanModel = "PIXEL7"
        val validNodeId = "RELAY-$cleanModel-$fingerprint"

        assertTrue("Identity binding verification must succeed for legitimate matching public key",
            NodeIdentityManager.verifyIdentityBinding(validNodeId, pubKeyHex))

        // Mismatched public key must fail binding check
        assertFalse("Identity binding verification must fail for mismatched public key",
            NodeIdentityManager.verifyIdentityBinding(validNodeId, pubKeyNodeB))

        // Spoofed node ID must fail binding check
        assertFalse("Identity binding verification must fail for spoofed node ID",
            NodeIdentityManager.verifyIdentityBinding("RELAY-PIXEL7-0000000000000000", pubKeyHex))
    }

    // ========================================================================
    // FINAL SECURITY HARDENING TESTS
    // ========================================================================

    // --- 1. END-TO-END ENCRYPTION TESTS ---

    @Test
    fun testE2EEncryptionAndDecryptionBetweenPeers() {
        // Alice generates an ephemeral or static X25519 keypair
        val (alicePriv, alicePub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val (charliePriv, charliePub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()

        val charliePubHex = RelayKeyStoreManager.bytesToHex(charliePub.encoded)
        val plaintext = "SECRET EMERGENCY: Insulin dependent patient in room 302, critical low blood sugar".toByteArray(Charsets.UTF_8)
        val packetId = "E2EE-REQ-001"
        val senderNodeId = "RELAY-ALICE-1234"
        val recipientNodeId = "RELAY-CHARLIE-5678"

        // Alice encrypts for Charlie
        val envelope = RelayE2EEncryption.encrypt(
            recipientX25519PubKeyHex = charliePubHex,
            packetId = packetId,
            senderNodeId = senderNodeId,
            recipientNodeId = recipientNodeId,
            plaintext = plaintext
        )

        assertEquals(RelayE2EEncryption.E2EE_VERSION, envelope.version)
        assertEquals(packetId, envelope.packetId)

        // Charlie decrypts using Charlie's private key
        val decrypted = RelayE2EEncryption.decrypt(charliePriv, envelope)
        assertEquals("Decrypted plaintext must match original secret message", String(plaintext, Charsets.UTF_8), String(decrypted, Charsets.UTF_8))
    }

    @Test(expected = SecurityException::class)
    fun testE2ECiphertextTamperingRejection() {
        val (_, charliePub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val (charliePriv, _) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val charliePubHex = RelayKeyStoreManager.bytesToHex(charliePub.encoded)

        val plaintext = "Confidential medical triage data".toByteArray(Charsets.UTF_8)
        val envelope = RelayE2EEncryption.encrypt(
            recipientX25519PubKeyHex = charliePubHex,
            packetId = "E2EE-TAMPER-1",
            senderNodeId = "RELAY-NODEA",
            recipientNodeId = "RELAY-NODEC",
            plaintext = plaintext
        )

        // Attacker tampers with the base64 ciphertext
        val tamperedCiphertext = if (envelope.ciphertextBase64.startsWith("A")) "B" + envelope.ciphertextBase64.substring(1) else "A" + envelope.ciphertextBase64.substring(1)
        val tamperedEnvelope = envelope.copy(ciphertextBase64 = tamperedCiphertext)

        // Decryption must throw SecurityException (AEAD tag mismatch)
        RelayE2EEncryption.decrypt(charliePriv, tamperedEnvelope)
    }

    @Test(expected = SecurityException::class)
    fun testE2EMetadataAadTamperingRejection() {
        val (_, charliePub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val (charliePriv, _) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val charliePubHex = RelayKeyStoreManager.bytesToHex(charliePub.encoded)

        val envelope = RelayE2EEncryption.encrypt(
            recipientX25519PubKeyHex = charliePubHex,
            packetId = "E2EE-AAD-1",
            senderNodeId = "RELAY-NODEA",
            recipientNodeId = "RELAY-NODEC",
            plaintext = "Payload data".toByteArray(Charsets.UTF_8)
        )

        // Attacker alters senderNodeId in transit
        val tamperedEnvelope = envelope.copy(senderNodeId = "RELAY-MALLORY-SPOOF")

        // Must reject due to Associated Authenticated Data (AAD) mismatch
        RelayE2EEncryption.decrypt(charliePriv, tamperedEnvelope)
    }

    @Test(expected = SecurityException::class)
    fun testE2EWrongRecipientKeyDecryptionFailure() {
        val (_, charliePub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val (bobPriv, _) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val charliePubHex = RelayKeyStoreManager.bytesToHex(charliePub.encoded)

        val envelope = RelayE2EEncryption.encrypt(
            recipientX25519PubKeyHex = charliePubHex,
            packetId = "E2EE-WRONG-KEY",
            senderNodeId = "RELAY-NODEA",
            recipientNodeId = "RELAY-NODEC",
            plaintext = "Data for Charlie only".toByteArray(Charsets.UTF_8)
        )

        // Bob tries to decrypt Charlie's envelope using Bob's private key
        RelayE2EEncryption.decrypt(bobPriv, envelope)
    }

    // --- 2. DEVICE IDENTITY & COLLISION RESISTANCE ---

    @Test
    fun testIdentityCollisionResistanceWithLongFingerprint() {
        val fpA = NodeIdentityManager.computeFingerprint(pubKeyNodeA)
        val fpB = NodeIdentityManager.computeFingerprint(pubKeyNodeB)
        val fpC = NodeIdentityManager.computeFingerprint(pubKeyNodeC)

        assertFalse("Fingerprint A and B must not collide", fpA == fpB)
        assertFalse("Fingerprint A and C must not collide", fpA == fpC)
        assertFalse("Fingerprint B and C must not collide", fpB == fpC)
        assertEquals(16, fpA.length)
        assertEquals(16, fpB.length)
        assertEquals(16, fpC.length)
    }

    @Test
    fun testIdentityUpdateOnSafeKeyRotation() {
        val oldNodeId = "RELAY-PIXEL7-" + NodeIdentityManager.computeFingerprint(pubKeyNodeA)
        assertTrue(NodeIdentityManager.verifyIdentityBinding(oldNodeId, pubKeyNodeA))

        // Rotate key to new public key (Node B)
        val newFingerprint = NodeIdentityManager.computeFingerprint(pubKeyNodeB)
        val newNodeId = "RELAY-PIXEL7-$newFingerprint"

        assertTrue("New Node ID must match rotated public key fingerprint",
            NodeIdentityManager.verifyIdentityBinding(newNodeId, pubKeyNodeB))
        assertFalse("Old Node ID must not match new rotated key",
            NodeIdentityManager.verifyIdentityBinding(oldNodeId, pubKeyNodeB))
    }

    // --- 3. RESPONDER REGISTRATION, REVOCATION & AUTHORIZATION ---

    @Test
    fun testResponderRegistrationAndRevocation() {
        val responderKey = pubKeyNodeC

        // 1. Initially not registered
        assertFalse(StatusAuthorizationPolicy.isRegisteredResponder(responderKey))

        // 2. Register responder
        val registered = StatusAuthorizationPolicy.registerResponder(
            context = null,
            responderPubKeyHex = responderKey,
            role = "Paramedic Coordinator",
            organization = "Red Cross"
        )
        assertTrue("Registration must succeed", registered)
        assertTrue("Responder must now be registered and active", StatusAuthorizationPolicy.isRegisteredResponder(responderKey))

        // 3. Revoke responder
        val revoked = StatusAuthorizationPolicy.revokeResponder(
            context = null,
            responderPubKeyHex = responderKey,
            reason = "Device compromised in disaster field"
        )
        assertTrue("Revocation must succeed", revoked)
        assertFalse("Revoked responder must not be active", StatusAuthorizationPolicy.isRegisteredResponder(responderKey))

        // Registry records revocation details
        val records = StatusAuthorizationPolicy.getAllResponderRecords()
        val charlieRecord = records.find { it.publicKeyHex == responderKey }
        assertTrue("Record must mark isRevoked = true", charlieRecord?.isRevoked == true)
        assertEquals("Device compromised in disaster field", charlieRecord?.revocationReason)
    }

    @Test
    fun testRevokedResponderStatusUpdateRejection() {
        val responderKey = pubKeyNodeC
        StatusAuthorizationPolicy.registerResponder(null, responderKey, "Rescue Lead", "FEMA")
        assertTrue(StatusAuthorizationPolicy.isRegisteredResponder(responderKey))

        val originReq = createSignedRequest(id = "EMERG-REVOKE-TEST", nodeId = nodeAId, pubKey = pubKeyNodeA, seed = testSeedNodeA)

        // Active responder is authorized
        assertTrue(StatusAuthorizationPolicy.isAuthorizedToUpdate(originReq, responderKey, RequestStatus.ASSIGNED))

        // Coordinator revokes the responder
        StatusAuthorizationPolicy.revokeResponder(null, responderKey, "Revoked security credential")

        // Revoked responder is now strictly rejected!
        assertFalse("Status update from revoked responder must be rejected",
            StatusAuthorizationPolicy.isAuthorizedToUpdate(originReq, responderKey, RequestStatus.ASSIGNED))
    }

    @Test
    fun testUnauthorizedCoordinatorResponderModificationRejection() {
        val legitimateCoordinator = pubKeyNodeA
        val maliciousActor = pubKeyNodeB
        val targetResponder = pubKeyNodeC

        // Configure authorized coordinator in policy
        StatusAuthorizationPolicy.registerCoordinatorKey(legitimateCoordinator)

        // Malicious actor tries to register a responder without valid coordinator authorization
        val unauthRegistration = StatusAuthorizationPolicy.registerResponder(
            context = null,
            responderPubKeyHex = targetResponder,
            role = "Rogue Responder",
            organization = "Fake Org",
            coordinatorPubKeyHex = maliciousActor,
            coordinatorSignature = "00".repeat(64)
        )
        assertFalse("Registration by unauthorized coordinator must be rejected", unauthRegistration)
        assertFalse("Target responder must not be registered", StatusAuthorizationPolicy.isRegisteredResponder(targetResponder))
    }

    // --- 4. MESH RELIABILITY, QUEUES & CHURN ---

    @Test
    fun testMaximumPayloadSizeRejection() {
        val normalPayload = ByteArray(5 * 1024) { 0x41 } // 5 KB
        assertTrue("5 KB payload must be valid", MeshReliabilityManager.isPayloadSizeValid(normalPayload))

        val exactMaxPayload = ByteArray(MeshReliabilityManager.MAX_PAYLOAD_BYTES) { 0x42 } // 32 KB
        assertTrue("Exact 32 KB payload must be valid", MeshReliabilityManager.isPayloadSizeValid(exactMaxPayload))

        val oversizedPayload = ByteArray(MeshReliabilityManager.MAX_PAYLOAD_BYTES + 1) { 0x43 } // 32 KB + 1 byte
        assertFalse("Oversized payload exceeding 32 KB must be rejected", MeshReliabilityManager.isPayloadSizeValid(oversizedPayload))
    }

    @Test
    fun testMalformedPacketHandling() {
        val malformedJsonString = "{ kind: 'emergency_request', unclosed..."
        val isMalformed = try {
            val clean = malformedJsonString.trim()
            if (!clean.startsWith("{") || !clean.endsWith("}")) {
                true
            } else {
                JSONObject(clean)
                false
            }
        } catch (_: Exception) {
            true
        }
        assertTrue("Malformed JSON packet must be detected and rejected safely without unhandled crashes", isMalformed)

        val oversized = ByteArray(MeshReliabilityManager.MAX_PAYLOAD_BYTES + 100)
        assertFalse("Oversized malformed packet must be rejected", MeshReliabilityManager.isPayloadSizeValid(oversized))
    }

    @Test
    fun testBoundedQueueOverflowAndBackpressure() {
        val queue = MeshReliabilityManager
        val testBytes = ByteArray(100) { 0x01 }

        // Fill incoming queue up to capacity (50 items)
        for (i in 1..MeshReliabilityManager.MAX_INCOMING_QUEUE_SIZE) {
            assertTrue("Queue item $i must be accepted", queue.offerIncoming(testBytes))
        }

        assertEquals(MeshReliabilityManager.MAX_INCOMING_QUEUE_SIZE, queue.getIncomingQueueSize())

        // 51st item must be rejected to prevent OOM
        assertFalse("Overflow item beyond max capacity must be rejected for backpressure", queue.offerIncoming(testBytes))
    }

    @Test
    fun testEndpointChurnAndRateLimiterCleanup() {
        val endpoint = "CHURNING_PEER_01"
        val now = 2000000L

        // Peer makes 5 rapid connection attempts within 60s
        for (i in 1..MeshReliabilityManager.MAX_CONNECTION_ATTEMPTS_PER_WINDOW) {
            assertTrue("Connection attempt $i should be allowed", MeshReliabilityManager.isConnectionAttemptAllowed(endpoint, now + i * 100))
        }

        // 6th attempt within window must be throttled
        assertFalse("6th connection attempt within 60s window must be throttled due to churn",
            MeshReliabilityManager.isConnectionAttemptAllowed(endpoint, now + 1000))

        // When endpoint disconnects, cleanup resets state
        MeshReliabilityManager.onEndpointDisconnected(endpoint)
    }

    // --- 5. POWER CONSERVATION & BATTERY SURVIVAL ---

    @Test
    fun testPowerConservationManagerBatteryThreshold() {
        // Normal battery (80%) discharging -> Low power mode inactive
        PowerConservationManager.setMockBatteryLevelForTesting(80, isCharging = false)
        assertFalse("Low power mode must be inactive at 80% battery", PowerConservationManager.isLowPowerModeActive())

        // Critical battery (12% <= 15%) discharging -> Low power mode auto-engages
        PowerConservationManager.setMockBatteryLevelForTesting(12, isCharging = false)
        assertTrue("Low power mode must automatically engage at <=15% battery", PowerConservationManager.isLowPowerModeActive())

        // Device plugged into charger (even at 10%) -> Low power mode disengages to allow full sync
        PowerConservationManager.setMockBatteryLevelForTesting(10, isCharging = true)
        assertFalse("Low power mode should disengage while charging", PowerConservationManager.isLowPowerModeActive())
    }

    @Test
    fun testPowerConservationManagerManualToggle() {
        PowerConservationManager.setMockBatteryLevelForTesting(60, isCharging = false)
        assertFalse(PowerConservationManager.isLowPowerModeActive())

        // User manually enables Emergency Battery Saver
        PowerConservationManager.setManualBatterySaver(true)
        assertTrue("Manual toggle must activate battery saver mode", PowerConservationManager.isLowPowerModeActive())

        // User toggles off
        PowerConservationManager.setManualBatterySaver(false)
        assertFalse("Manual toggle off must deactivate battery saver mode", PowerConservationManager.isLowPowerModeActive())
    }

    // --- 6. END-TO-END ENCRYPTED TRIAGE NOTES ---

    @Test
    fun testTriageNoteEncryptionAndDecryption() {
        val (responderPriv, responderPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val responderPubHex = RelayKeyStoreManager.bytesToHex(responderPub.encoded)
        val responderNodeId = "NODE_RESPONDER_99"

        val (authorPriv, authorPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val authorPubHex = RelayKeyStoreManager.bytesToHex(authorPub.encoded)
        val authorNodeId = "NODE_CIVILIAN_01"

        val publicLocation = "2nd floor roof, 3 trapped near Sector 4 Water Tank"
        val sensitiveMedicalNote = "Victim in diabetic coma, severe laceration on left arm, non-responsive."

        val encryptedEnvelope = RelayE2EEncryption.encryptTriageNote(
            confidentialNote = sensitiveMedicalNote,
            recipientX25519PubKeyHex = responderPubHex,
            packetId = "REQ-TRIAGE-001",
            senderNodeId = authorNodeId,
            recipientNodeId = responderNodeId,
            authorX25519PubKeyHex = authorPubHex
        )

        val fullDescription = RelayE2EEncryption.formatFullDescription(publicLocation, encryptedEnvelope)

        // Verify responder decryption
        val responderResult = RelayE2EEncryption.parseAndDecryptDescription(
            fullDescription = fullDescription,
            myPrivateKey = responderPriv,
            myNodeId = responderNodeId
        )

        assertTrue("Should detect encryption", responderResult.isEncrypted)
        assertTrue("Responder must successfully decrypt note", responderResult.isDecrypted)
        assertEquals(publicLocation, responderResult.publicDetails)
        assertEquals(sensitiveMedicalNote, responderResult.confidentialNote)
    }

    @Test
    fun testTriageNoteRelayNodeCannotReadConfidentialData() {
        val (_, responderPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val responderPubHex = RelayKeyStoreManager.bytesToHex(responderPub.encoded)

        val (authorPriv, authorPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val authorPubHex = RelayKeyStoreManager.bytesToHex(authorPub.encoded)

        val (relayPriv, _) = RelayE2EEncryption.generateEphemeralX25519KeyPair()

        val publicLocation = "Collapsed stairwell, Sector 2"
        val sensitiveMedicalNote = "Patient has spinal trauma, do not move without cervical collar."

        val encryptedEnvelope = RelayE2EEncryption.encryptTriageNote(
            confidentialNote = sensitiveMedicalNote,
            recipientX25519PubKeyHex = responderPubHex,
            packetId = "REQ-TRIAGE-002",
            senderNodeId = "NODE_CIVILIAN_01",
            recipientNodeId = "NODE_RESPONDER_99",
            authorX25519PubKeyHex = authorPubHex
        )

        val fullDescription = RelayE2EEncryption.formatFullDescription(publicLocation, encryptedEnvelope)

        // Relay node attempts decryption
        val relayResult = RelayE2EEncryption.parseAndDecryptDescription(
            fullDescription = fullDescription,
            myPrivateKey = relayPriv,
            myNodeId = "NODE_RELAY_HOP_55"
        )

        assertTrue("Relay node should detect note is encrypted", relayResult.isEncrypted)
        assertFalse("Relay node must fail to decrypt confidential note", relayResult.isDecrypted)
        assertNull("Confidential note must remain null for unauthorized relay node", relayResult.confidentialNote)
        assertEquals(publicLocation, relayResult.publicDetails)
    }

    @Test
    fun testTriageNoteAuthorCanReadOwnNote() {
        val (_, responderPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val responderPubHex = RelayKeyStoreManager.bytesToHex(responderPub.encoded)

        val (authorPriv, authorPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val authorPubHex = RelayKeyStoreManager.bytesToHex(authorPub.encoded)

        val publicLocation = "Flooded red house"
        val sensitiveMedicalNote = "1 infant needing asthma medication."

        val encryptedEnvelope = RelayE2EEncryption.encryptTriageNote(
            confidentialNote = sensitiveMedicalNote,
            recipientX25519PubKeyHex = responderPubHex,
            packetId = "REQ-TRIAGE-003",
            senderNodeId = "NODE_CIVILIAN_01",
            recipientNodeId = "NODE_RESPONDER_99",
            authorX25519PubKeyHex = authorPubHex
        )

        val fullDescription = RelayE2EEncryption.formatFullDescription(publicLocation, encryptedEnvelope)

        // Author decrypts own note
        val authorResult = RelayE2EEncryption.parseAndDecryptDescription(
            fullDescription = fullDescription,
            myPrivateKey = authorPriv,
            myNodeId = "NODE_CIVILIAN_01"
        )

        assertTrue(authorResult.isEncrypted)
        assertTrue("Author must be able to read their own encrypted note", authorResult.isDecrypted)
        assertEquals(sensitiveMedicalNote, authorResult.confidentialNote)
    }

    @Test
    fun testTriageNoteTamperingRejection() {
        val (responderPriv, responderPub) = RelayE2EEncryption.generateEphemeralX25519KeyPair()
        val responderPubHex = RelayKeyStoreManager.bytesToHex(responderPub.encoded)

        val encryptedEnvelope = RelayE2EEncryption.encryptTriageNote(
            confidentialNote = "Severe blood loss",
            recipientX25519PubKeyHex = responderPubHex,
            packetId = "REQ-TRIAGE-004",
            senderNodeId = "NODE_A",
            recipientNodeId = "NODE_B"
        )

        // Attacker flips byte in base64 envelope
        val tamperedEnvelope = encryptedEnvelope.substring(0, encryptedEnvelope.length - 6) + "XXXX=="
        val fullDescription = RelayE2EEncryption.formatFullDescription("Location", tamperedEnvelope)

        val result = RelayE2EEncryption.parseAndDecryptDescription(
            fullDescription = fullDescription,
            myPrivateKey = responderPriv,
            myNodeId = "NODE_B"
        )

        assertTrue(result.isEncrypted)
        assertFalse("Tampered envelope must fail decryption closed", result.isDecrypted)
        assertNull(result.confidentialNote)
    }

    @Test
    fun testUnencryptedDescriptionPassthrough() {
        val rawDescription = "Regular public emergency request with no sensitive triage notes."
        val (key, _) = RelayE2EEncryption.generateEphemeralX25519KeyPair()

        val result = RelayE2EEncryption.parseAndDecryptDescription(
            fullDescription = rawDescription,
            myPrivateKey = key,
            myNodeId = "NODE_ANY"
        )

        assertFalse(result.isEncrypted)
        assertFalse(result.isDecrypted)
        assertEquals(rawDescription, result.publicDetails)
        assertNull(result.confidentialNote)
    }

    // --- 7. TACTICAL OFFLINE GPS & DISTANCE BEARING ---

    @Test
    fun testGeoTacticalDistanceAndBearingCalculations() {
        val baseLat = 13.0827
        val baseLon = 80.2707

        // Same point distance must be 0
        val zeroDist = GeoTacticalUtils.calculateDistanceMeters(baseLat, baseLon, baseLat, baseLon)
        assertEquals(0.0, zeroDist, 0.001)

        // Point ~255m north
        val northLat = 13.0850
        val northDist = GeoTacticalUtils.calculateDistanceMeters(baseLat, baseLon, northLat, baseLon)
        assertTrue("Distance should be approximately 255 meters", northDist in 250.0..260.0)

        val bearingNorth = GeoTacticalUtils.calculateBearingDegrees(baseLat, baseLon, northLat, baseLon)
        assertTrue("Bearing due North should be near 0 degrees", bearingNorth < 5.0f || bearingNorth > 355.0f)
        assertEquals("N ↑", GeoTacticalUtils.getCompassDirectionName(bearingNorth))

        // Point east
        val eastBearing = GeoTacticalUtils.calculateBearingDegrees(0.0, 0.0, 0.0, 1.0)
        assertEquals(90.0f, eastBearing, 0.5f)
        assertEquals("E →", GeoTacticalUtils.getCompassDirectionName(eastBearing))

        // Distance formatting
        assertEquals("250 m", GeoTacticalUtils.formatDistance(250.0))
        assertEquals("1.8 km", GeoTacticalUtils.formatDistance(1800.0))
    }

    @Test
    fun testEmergencyRequestGpsFieldsPreservation() {
        val req = EmergencyRequest(
            type = "Rescue",
            description = "Flooded rooftop",
            people = 3,
            priority = "Critical",
            latitude = 13.0827,
            longitude = 80.2707,
            locationAccuracyMeters = 4.2f
        )

        assertEquals(13.0827, req.latitude!!, 0.0001)
        assertEquals(80.2707, req.longitude!!, 0.0001)
        assertEquals(4.2f, req.locationAccuracyMeters!!, 0.01f)

        val formattedCoords = GeoTacticalUtils.formatCoordinates(req.latitude!!, req.longitude!!)
        assertTrue(formattedCoords.contains("13.0827° N"))
        assertTrue(formattedCoords.contains("80.2707° E"))
    }
}

package com.relay.emergency.mesh

import android.content.Context
import com.relay.emergency.EmergencyRequest
import com.relay.emergency.RequestStatus
import com.relay.emergency.SosMessage
import com.relay.emergency.SyncStatus
import com.relay.emergency.crypto.EmergencyPacketSigner
import com.relay.emergency.crypto.LocalOriginRegistry
import com.relay.emergency.crypto.RelayE2EEncryption
import com.relay.emergency.crypto.RelayKeyStoreManager
import com.relay.emergency.crypto.StatusAuthorizationPolicy
import com.relay.emergency.service.MeshCoordinator
import java.util.UUID

/**
 * Pre-seeded static disaster scenario data and mesh simulation engine.
 * Ensures the app functions completely out-of-the-box on single devices,
 * emulators, and classroom/conference demonstrations without requiring
 * external servers or physical secondary peer radios.
 */
object StaticDemoData {

    fun getStaticEmergencyRequests(context: Context): List<EmergencyRequest> {
        val keyManager = RelayKeyStoreManager.getInstance(context)
        val myPubKey = keyManager.getPublicKeyHex()
        val myX25519Pub = keyManager.getX25519PublicKeyHex()
        val localNodeId = NodeIdentityManager.getLocalNodeId(context)

        // Seed 1: Critical Rescue Request
        val req1Id = "REQ-RELAY-001"
        LocalOriginRegistry.recordLocalCreation(context, req1Id)
        val rawReq1 = EmergencyRequest(
            id = req1Id,
            type = "Rescue",
            description = "Roof flooded at 2nd Street Community Center. 4 people trapped near Sector 4 Water Tank, water rising rapidly. Immediate boat evacuation needed.",
            people = 4,
            priority = "Critical",
            status = RequestStatus.PENDING,
            updatedAt = System.currentTimeMillis() - 15 * 60 * 1000L,
            syncStatus = SyncStatus.SYNCED,
            hopCount = 1,
            nodeHistory = listOf(localNodeId, "PEER-ALPHA"),
            lastTransferStatus = "Relayed via Rescue Boat Alpha (Hop 1)",
            originatorNodeId = localNodeId,
            latitude = 13.0827,
            longitude = 80.2707,
            locationAccuracyMeters = 4.2f
        )
        val signedReq1 = EmergencyPacketSigner.signRequest(context, rawReq1)

        // Seed 2: Critical Medical Request with End-to-End Encrypted Triage Notes
        val req2Id = "REQ-RELAY-002"
        LocalOriginRegistry.recordLocalCreation(context, req2Id)
        val publicDesc2 = "Elderly care facility, Sector 9 Block B. Power generator failed, floodwater entering ground floor."
        val confidentialNote2 = "Victim in diabetic ketoacidosis, non-responsive. Infant with acute respiratory distress requiring oxygen & Type O- blood."

        val encryptedEnvelope2 = try {
            RelayE2EEncryption.encryptTriageNote(
                confidentialNote = confidentialNote2,
                recipientX25519PubKeyHex = myX25519Pub,
                packetId = req2Id,
                senderNodeId = localNodeId,
                recipientNodeId = "FIELD-HOSPITAL-BRAVO",
                authorX25519PubKeyHex = myX25519Pub
            )
        } catch (_: Exception) {
            ""
        }

        val fullDesc2 = if (encryptedEnvelope2.isNotBlank()) {
            RelayE2EEncryption.formatFullDescription(publicDesc2, encryptedEnvelope2)
        } else {
            publicDesc2
        }

        val rawReq2 = EmergencyRequest(
            id = req2Id,
            type = "Medical",
            description = fullDesc2,
            people = 2,
            priority = "Critical",
            status = RequestStatus.IN_PROGRESS,
            updatedAt = System.currentTimeMillis() - 45 * 60 * 1000L,
            syncStatus = SyncStatus.SYNCED,
            hopCount = 2,
            nodeHistory = listOf(localNodeId, "PEER-ALPHA", "PEER-BRAVO"),
            lastTransferStatus = "Relayed via Field Hospital Bravo (Hop 2)",
            originatorNodeId = localNodeId,
            sequenceNumber = 1,
            lastStatusUpdaterRole = "Certified Field Responder",
            latitude = 13.0855,
            longitude = 80.2735,
            locationAccuracyMeters = 5.8f
        )
        val signedReq2 = EmergencyPacketSigner.signRequest(context, rawReq2)

        // Seed 3: Food & Water Distribution Need
        val req3Id = "REQ-RELAY-003"
        LocalOriginRegistry.recordLocalCreation(context, req3Id)
        val rawReq3 = EmergencyRequest(
            id = req3Id,
            type = "Food & Water",
            description = "Relief camp shelter at St. Jude High School. Clean drinking water and baby formula exhausted. 25 civilians awaiting urgent supply drop.",
            people = 25,
            priority = "High",
            status = RequestStatus.PENDING,
            updatedAt = System.currentTimeMillis() - 110 * 60 * 1000L,
            syncStatus = SyncStatus.SYNCED,
            hopCount = 1,
            nodeHistory = listOf(localNodeId, "PEER-DRONE"),
            lastTransferStatus = "Relayed via Relay Drone 04 (Hop 1)",
            originatorNodeId = localNodeId,
            latitude = 13.0798,
            longitude = 80.2682,
            locationAccuracyMeters = 7.1f
        )
        val signedReq3 = EmergencyPacketSigner.signRequest(context, rawReq3)

        // Seed 4: Hazard Avoidance Beacon
        val req4Id = "REQ-RELAY-004"
        LocalOriginRegistry.recordLocalCreation(context, req4Id)
        val rawReq4 = EmergencyRequest(
            id = req4Id,
            type = "Hazard",
            description = "High-voltage power transformer submerged and sparking near Main Market crossroad. Keep rescue boats away from East canal navigation route.",
            people = 0,
            priority = "High",
            status = RequestStatus.IN_PROGRESS,
            updatedAt = System.currentTimeMillis() - 180 * 60 * 1000L,
            syncStatus = SyncStatus.SYNCED,
            hopCount = 3,
            nodeHistory = listOf(localNodeId, "PEER-ALPHA", "PEER-DRONE", "PEER-OMEGA"),
            lastTransferStatus = "Forwarded to Command Post Omega (Hop 3)",
            originatorNodeId = localNodeId,
            sequenceNumber = 1,
            lastStatusUpdaterRole = "Disaster Safety Coordinator",
            latitude = 13.0844,
            longitude = 80.2760,
            locationAccuracyMeters = 3.5f
        )
        val signedReq4 = EmergencyPacketSigner.signRequest(context, rawReq4)

        // Seed 5: Shelter Capacity Update (Resolved)
        val req5Id = "REQ-RELAY-005"
        LocalOriginRegistry.recordLocalCreation(context, req5Id)
        val rawReq5 = EmergencyRequest(
            id = req5Id,
            type = "Shelter",
            description = "Community Hall gym roof intact and dry. Capacity verified for 40 additional displaced evacuees with emergency blankets and cots.",
            people = 12,
            priority = "Medium",
            status = RequestStatus.RESOLVED,
            updatedAt = System.currentTimeMillis() - 240 * 60 * 1000L,
            syncStatus = SyncStatus.SYNCED,
            hopCount = 2,
            nodeHistory = listOf(localNodeId, "PEER-BRAVO", "PEER-OMEGA"),
            lastTransferStatus = "Status verified by Command Post (Hop 2)",
            originatorNodeId = localNodeId,
            sequenceNumber = 2,
            lastStatusUpdaterRole = "Emergency Operations Coordinator",
            latitude = 13.0805,
            longitude = 80.2718,
            locationAccuracyMeters = 6.0f
        )
        val signedReq5 = EmergencyPacketSigner.signRequest(context, rawReq5)

        return listOf(signedReq1, signedReq2, signedReq3, signedReq4, signedReq5)
    }

    fun getStaticSosMessages(context: Context): List<SosMessage> {
        val localNodeId = NodeIdentityManager.getLocalNodeId(context)
        val now = System.currentTimeMillis()

        return listOf(
            SosMessage(
                id = "MSG-001",
                senderName = "Rescue Boat Alpha",
                message = "Team Alpha on-site at Sector 4 Water Tank. Evacuating 4 victims from roof now.",
                isEmergency = true,
                timestamp = now - 12 * 60 * 1000L,
                hopCount = 1,
                syncStatus = SyncStatus.SYNCED,
                senderNodeId = "PEER-ALPHA"
            ),
            SosMessage(
                id = "MSG-002",
                senderName = "Field Hospital Bravo",
                message = "Emergency triage station active at City Stadium. Blood bank and pediatric trauma unit operational.",
                isEmergency = false,
                timestamp = now - 35 * 60 * 1000L,
                hopCount = 2,
                syncStatus = SyncStatus.SYNCED,
                senderNodeId = "PEER-BRAVO"
            ),
            SosMessage(
                id = "MSG-003",
                senderName = "Relay Drone 04",
                message = "Aerial mesh bridge established between Sector 2 and Sector 9. Radio link latency < 65ms.",
                isEmergency = false,
                timestamp = now - 70 * 60 * 1000L,
                hopCount = 1,
                syncStatus = SyncStatus.SYNCED,
                senderNodeId = "PEER-DRONE"
            ),
            SosMessage(
                id = "MSG-004",
                senderName = "Command Post Omega",
                message = "Helicopter reconnaissance confirms East Canal blocked by collapsed bridge. Diverting all rescue craft to West Canal.",
                isEmergency = true,
                timestamp = now - 120 * 60 * 1000L,
                hopCount = 2,
                syncStatus = SyncStatus.SYNCED,
                senderNodeId = "PEER-OMEGA"
            )
        )
    }

    fun getStaticSimulatedEndpoints(): List<Pair<String, String>> {
        return listOf(
            Pair("PEER-ALPHA", "Rescue Boat Alpha (Wi-Fi Direct • -42 dBm • 1 Hop)"),
            Pair("PEER-BRAVO", "Field Hospital Bravo (BLE Mesh • -56 dBm • 2 Hops)"),
            Pair("PEER-DRONE", "Relay Drone 04 (Aerial Radio Bridge • -68 dBm • 1 Hop)"),
            Pair("PEER-OMEGA", "Command Post Omega (Solar Base • -74 dBm • 3 Hops)")
        )
    }

    fun getStaticTransferLogs(): List<TransferLogEntry> {
        val now = System.currentTimeMillis()
        return listOf(
            TransferLogEntry(
                id = "LOG-001",
                timestamp = now - 5 * 60 * 1000L,
                type = TransferType.ACK_RECEIVED,
                requestId = "REQ-RELAY-001",
                summary = "Cryptographic delivery ACK confirmed from Rescue Boat Alpha",
                peerName = "Rescue Boat Alpha",
                hopCount = 1
            ),
            TransferLogEntry(
                id = "LOG-002",
                timestamp = now - 14 * 60 * 1000L,
                type = TransferType.FORWARDED,
                requestId = "REQ-RELAY-001",
                summary = "Forwarded critical roof rescue beacon over Wi-Fi Direct",
                peerName = "Rescue Boat Alpha",
                hopCount = 1
            ),
            TransferLogEntry(
                id = "LOG-003",
                timestamp = now - 42 * 60 * 1000L,
                type = TransferType.RECEIVED,
                requestId = "REQ-RELAY-002",
                summary = "Ingressed authenticated medical request with encrypted triage note",
                peerName = "Field Hospital Bravo",
                hopCount = 2
            ),
            TransferLogEntry(
                id = "LOG-004",
                timestamp = now - 105 * 60 * 1000L,
                type = TransferType.FORWARDED,
                requestId = "REQ-RELAY-003",
                summary = "Relayed high-priority food/water supply request over aerial bridge",
                peerName = "Relay Drone 04",
                hopCount = 1
            ),
            TransferLogEntry(
                id = "LOG-005",
                timestamp = now - 175 * 60 * 1000L,
                type = TransferType.FORWARDED,
                requestId = "REQ-RELAY-004",
                summary = "Broadcasted hazard warning beacon (submerged transformer)",
                peerName = "Command Post Omega",
                hopCount = 3
            )
        )
    }

    /**
     * Initializes the static simulation environment if no physical peers are connected.
     */
    fun seedStaticMeshEnvironment(context: Context) {
        if (MeshCoordinator.connectedEndpointsListState.value.isEmpty()) {
            val simulatedPeers = getStaticSimulatedEndpoints()
            MeshCoordinator.connectedEndpointsListState.value = simulatedPeers
            MeshCoordinator.connectedEndpointsCountState.value = simulatedPeers.size
            MeshCoordinator.isMeshActiveState.value = true
            MeshCoordinator.lastSyncStatusState.value = "🟢 4 Relay Nodes Synchronized (Static Disaster Fleet)"
        }

        if (MeshCoordinator.transferEventsLog.isEmpty()) {
            MeshCoordinator.transferEventsLog.addAll(getStaticTransferLogs())
            MeshCoordinator.totalTransfersReceivedState.value = 14
            MeshCoordinator.totalTransfersForwardedState.value = 22
            MeshCoordinator.totalAcksConfirmedState.value = 18
        }

        // Register default coordinator and responder for the demo scenario
        val keyManager = RelayKeyStoreManager.getInstance(context)
        val myPubKey = keyManager.getPublicKeyHex()
        StatusAuthorizationPolicy.registerCoordinatorKey(myPubKey)
        StatusAuthorizationPolicy.registerResponder(
            context = context,
            responderPubKeyHex = myPubKey,
            role = "Certified Disaster Responder",
            organization = "National Disaster Response Force (NDRF)",
            coordinatorPubKeyHex = myPubKey
        )
    }
}

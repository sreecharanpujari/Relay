package com.relay.emergency.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import com.relay.emergency.EmergencyRequest
import com.relay.emergency.MainActivity
import com.relay.emergency.R
import com.relay.emergency.RequestStatus
import com.relay.emergency.SosMessage
import com.relay.emergency.SyncStatus
import com.relay.emergency.loadRequests
import com.relay.emergency.loadSosMessages
import com.relay.emergency.saveRequests
import com.relay.emergency.saveSosMessages
import com.relay.emergency.mesh.ACK_TIMEOUT_MS
import com.relay.emergency.mesh.DEFAULT_REQUEST_TTL_HOURS
import com.relay.emergency.mesh.MAX_STORE_FORWARD_HOPS
import com.relay.emergency.mesh.MAX_TRANSFER_RETRIES
import com.relay.emergency.mesh.NodeIdentityManager
import com.relay.emergency.mesh.PendingTransfer
import com.relay.emergency.mesh.SERVICE_ID
import com.relay.emergency.mesh.StoreAndForwardHelper
import com.relay.emergency.mesh.TransferLogEntry
import com.relay.emergency.mesh.TransferType
import com.relay.emergency.mesh.MeshRateLimiter
import com.relay.emergency.mesh.MeshReliabilityManager
import com.relay.emergency.crypto.RelayE2EEncryption

import com.relay.emergency.mesh.StorageRetentionManager
import com.relay.emergency.crypto.EmergencyPacketSigner
import com.relay.emergency.crypto.EmergencyForwardingGate
import com.relay.emergency.crypto.StatusAuthorizationPolicy
import com.relay.emergency.crypto.ForwardingDecision
import com.relay.emergency.crypto.IngressDecision
import com.relay.emergency.crypto.LocalOriginRegistry
import com.relay.emergency.crypto.RelayKeyStoreManager
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

// ============================================================================
// SHARED MESH COORDINATOR (SINGLE SOURCE OF TRUTH FOR UI & SERVICE)
// ============================================================================

object MeshCoordinator {
    val isMeshActiveState = mutableStateOf(false)
    val connectedEndpointsCountState = mutableStateOf(0)
    val connectedEndpointsListState = mutableStateOf<List<Pair<String, String>>>(emptyList())
    val lastSyncStatusState = mutableStateOf("Ready for off-grid command")

    val transferEventsLog = mutableStateListOf<TransferLogEntry>()
    val totalTransfersReceivedState = mutableStateOf(0)
    val totalTransfersForwardedState = mutableStateOf(0)
    val totalAcksConfirmedState = mutableStateOf(0)
    val pendingTransfersCountState = mutableStateOf(0)

    val connectedEndpointsMap = ConcurrentHashMap<String, String>()
    val pendingConnections = ConcurrentHashMap.newKeySet<String>()
    val pendingTransfersMap = ConcurrentHashMap<String, PendingTransfer>()

    var onRequestsReceivedListener: (() -> Unit)? = null
    var onMessagesReceivedListener: (() -> Unit)? = null

    @Volatile
    var serviceInstance: RelayMeshService? = null

    val mainHandler = Handler(Looper.getMainLooper())

    fun updateEndpointsState() {
        val list = connectedEndpointsMap.toList()
        mainHandler.post {
            connectedEndpointsListState.value = list
            connectedEndpointsCountState.value = list.size
        }
    }

    fun logTransfer(
        type: TransferType,
        requestId: String,
        summary: String,
        peerName: String,
        hopCount: Int
    ) {
        mainHandler.post {
            if (transferEventsLog.size >= 40) {
                transferEventsLog.removeLast()
            }
            transferEventsLog.add(
                0,
                TransferLogEntry(
                    type = type,
                    requestId = requestId,
                    summary = summary,
                    peerName = peerName,
                    hopCount = hopCount
                )
            )
            pendingTransfersCountState.value = pendingTransfersMap.size
        }
    }
}

// ============================================================================
// RELIABLE FOREGROUND SERVICE FOR NEARBY CONNECTIONS (ANDROID 14+ COMPLIANT)
// ============================================================================

class RelayMeshService : Service() {

    private lateinit var connectionsClient: ConnectionsClient
    private lateinit var localNodeId: String

    private val retryHandler = Handler(Looper.getMainLooper())

    private var isAdvertising = false
    private var isDiscovering = false

    companion object {
        const val TAG = "RelayMeshService"
        const val CHANNEL_ID = "relay_mesh_channel"
        const val NOTIFICATION_ID = 9110

        const val ACTION_START = "com.relay.emergency.action.START_MESH"
        const val ACTION_STOP = "com.relay.emergency.action.STOP_MESH"
        const val ACTION_SYNC_ALL = "com.relay.emergency.action.SYNC_ALL"
        const val ACTION_SEND_REQUEST = "com.relay.emergency.action.SEND_REQUEST"

        fun start(context: Context) {
            val intent = Intent(context, RelayMeshService::class.java).apply {
                action = ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ContextCompat.startForegroundService(context, intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, RelayMeshService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }

        fun syncAll(context: Context) {
            val intent = Intent(context, RelayMeshService::class.java).apply {
                action = ACTION_SYNC_ALL
            }
            context.startService(intent)
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "RelayMeshService onCreate")
        MeshCoordinator.serviceInstance = this
        connectionsClient = Nearby.getConnectionsClient(applicationContext)
        localNodeId = NodeIdentityManager.getLocalNodeId(applicationContext)

        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_START
        Log.d(TAG, "onStartCommand received action: $action")

        when (action) {
            ACTION_STOP -> {
                stopMesh()
                stopForegroundSafely()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_SYNC_ALL -> {
                syncAllNow()
                return START_STICKY
            }
            ACTION_START -> {
                startForegroundWithNotification("Initializing offline mesh beacon...")
                startMesh()
                return START_STICKY
            }
            else -> {
                startForegroundWithNotification("RELAY radio cluster active")
                startMesh()
                return START_STICKY
            }
        }
    }

    // ============================================================================
    // NOTIFICATION & FOREGROUND LIFECYCLE (ANDROID 14+ ServiceInfo HANDLING)
    // ============================================================================

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "RELAY Emergency Mesh",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Maintains offline peer discovery and store-and-forward mesh routing in background"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            this.flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, RelayMeshService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val connectedCount = MeshCoordinator.connectedEndpointsMap.size
        val title = if (connectedCount > 0) {
            "RELAY Active • $connectedCount Peer${if (connectedCount > 1) "s" else ""} Connected"
        } else {
            "RELAY Emergency Mesh Active"
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(statusText)
            .setSubText("Radio ID: $localNodeId")
            .setSmallIcon(R.drawable.ic_relay_shield_mark)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openPendingIntent)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop Mesh",
                stopPendingIntent
            )
            .build()
    }

    private fun startForegroundWithNotification(statusText: String) {
        val notification = buildNotification(statusText)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    fun updateNotification(statusText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    private fun stopForegroundSafely() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        val manager = getSystemService(NotificationManager::class.java)
        manager?.cancel(NOTIFICATION_ID)
    }

    // ============================================================================
    // PERMISSIONS CHECK
    // ============================================================================

    private fun hasRequiredPermissions(): Boolean {
        val required = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            required.addAll(
                listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE
                )
            )
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            required.add(Manifest.permission.NEARBY_WIFI_DEVICES)
        }
        return required.all {
            ContextCompat.checkSelfPermission(this, it) == PackageManager.PERMISSION_GRANTED
        }
    }

    // ============================================================================
    // MESH START & STOP (PREVENTS DUPLICATE ADVERTISING / DISCOVERY SESSIONS)
    // ============================================================================

    fun startMesh() {
        if (!hasRequiredPermissions()) {
            Log.e(TAG, "Required permissions missing to start Nearby Connections")
            MeshCoordinator.lastSyncStatusState.value = "Permissions missing for mesh operation"
            updateNotification("Permissions missing for mesh")
            return
        }

        MeshCoordinator.mainHandler.post {
            MeshCoordinator.isMeshActiveState.value = true
            MeshCoordinator.lastSyncStatusState.value = "Starting nearby advertising & discovery..."
        }

        startAdvertisingSafe()
        startDiscoverySafe()
    }

    fun stopMesh() {
        try {
            if (isAdvertising) {
                connectionsClient.stopAdvertising()
                isAdvertising = false
            }
            if (isDiscovering) {
                connectionsClient.stopDiscovery()
                isDiscovering = false
            }
            connectionsClient.stopAllEndpoints()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping Nearby Connections", e)
        }

        MeshCoordinator.connectedEndpointsMap.clear()
        MeshCoordinator.pendingConnections.clear()
        MeshCoordinator.pendingTransfersMap.clear()
        retryHandler.removeCallbacksAndMessages(null)

        MeshCoordinator.mainHandler.post {
            MeshCoordinator.isMeshActiveState.value = false
            MeshCoordinator.updateEndpointsState()
            MeshCoordinator.pendingTransfersCountState.value = 0
            MeshCoordinator.lastSyncStatusState.value = "Nearby offline mesh stopped."
        }
        Log.d(TAG, "Nearby mesh stopped completely")
    }

    private fun startAdvertisingSafe() {
        if (isAdvertising) {
            Log.d(TAG, "Advertising session already active, skipping duplicate call")
            return
        }

        val localEndpointName = "RELAY - " + Build.MODEL.take(12)
        val options = AdvertisingOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        connectionsClient.startAdvertising(
            localEndpointName,
            SERVICE_ID,
            connectionLifecycleCallback,
            options
        ).addOnSuccessListener {
            isAdvertising = true
            Log.d(TAG, "Advertising started successfully as $localEndpointName")
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "Broadcasting beacon: $localEndpointName"
            }
            updateNotification("Beacon active: $localEndpointName")
        }.addOnFailureListener {
            isAdvertising = false
            Log.e(TAG, "Advertising failed", it)
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "Advertising failed: ${it.localizedMessage}"
            }
            updateNotification("Beacon failed: ${it.localizedMessage}")
        }
    }

    private fun startDiscoverySafe() {
        if (isDiscovering) {
            Log.d(TAG, "Discovery session already active, skipping duplicate call")
            return
        }

        val options = DiscoveryOptions.Builder()
            .setStrategy(Strategy.P2P_CLUSTER)
            .build()

        connectionsClient.startDiscovery(
            SERVICE_ID,
            endpointDiscoveryCallback,
            options
        ).addOnSuccessListener {
            isDiscovering = true
            Log.d(TAG, "Discovery started successfully")
        }.addOnFailureListener {
            isDiscovering = false
            Log.e(TAG, "Discovery failed", it)
        }
    }

    // ============================================================================
    // CONNECTION LIFECYCLE & DISCOVERY CALLBACKS
    // ============================================================================

    private val endpointDiscoveryCallback = object : EndpointDiscoveryCallback() {
        override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
            Log.d(TAG, "Nearby device found: ${info.endpointName} ($endpointId)")
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "Discovered peer: ${info.endpointName}"
            }

            if (!MeshReliabilityManager.isConnectionAttemptAllowed(endpointId)) {
                Log.w(TAG, "Connection attempt throttled to $endpointId due to rapid connection churn")
                return
            }

            if (!MeshCoordinator.connectedEndpointsMap.containsKey(endpointId) &&
                !MeshCoordinator.pendingConnections.contains(endpointId)
            ) {
                MeshCoordinator.pendingConnections.add(endpointId)
                val localEndpointName = "RELAY - " + Build.MODEL.take(12)

                connectionsClient.requestConnection(
                    localEndpointName,
                    endpointId,
                    connectionLifecycleCallback
                ).addOnSuccessListener {
                    Log.d(TAG, "Connection request sent to ${info.endpointName}")
                }.addOnFailureListener {
                    MeshCoordinator.pendingConnections.remove(endpointId)
                    Log.e(TAG, "Connection request failed to $endpointId", it)
                }
            }
        }

        override fun onEndpointLost(endpointId: String) {
            Log.d(TAG, "Nearby device lost: $endpointId")
            MeshCoordinator.pendingConnections.remove(endpointId)
        }
    }

    private val connectionLifecycleCallback = object : ConnectionLifecycleCallback() {
        override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
            Log.d(TAG, "Connection initiated with: ${info.endpointName} ($endpointId)")
            connectionsClient.acceptConnection(endpointId, payloadCallback)
                .addOnSuccessListener {
                    Log.d(TAG, "Connection accepted with $endpointId")
                }.addOnFailureListener {
                    MeshCoordinator.pendingConnections.remove(endpointId)
                    Log.e(TAG, "Failed accepting connection from $endpointId", it)
                }
        }

        override fun onConnectionResult(endpointId: String, result: ConnectionResolution) {
            MeshCoordinator.pendingConnections.remove(endpointId)
            when (result.status.statusCode) {
                ConnectionsStatusCodes.STATUS_OK -> {
                    val peerName = "Peer-${endpointId.take(4)}"
                    MeshCoordinator.connectedEndpointsMap[endpointId] = peerName
                    MeshCoordinator.updateEndpointsState()

                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.lastSyncStatusState.value = "Connected to $peerName"
                    }
                    updateNotification("Connected to $peerName • Exchanging emergencies")
                    Log.d(TAG, "Connected to $endpointId ($peerName)")

                    // 1. Establish authenticated E2EE keys with peer
                    sendKeyExchangeHello(endpointId)

                    // 2. Automatically exchange stored emergency requests with new peer
                    exchangeStoredRequestsWithPeer(endpointId, peerName)
                }
                ConnectionsStatusCodes.STATUS_CONNECTION_REJECTED -> {
                    Log.d(TAG, "Connection rejected by $endpointId")
                }
                ConnectionsStatusCodes.STATUS_ERROR -> {
                    Log.e(TAG, "Connection error with $endpointId")
                }
            }
        }

        override fun onDisconnected(endpointId: String) {
            Log.d(TAG, "Disconnected from $endpointId")
            MeshReliabilityManager.onEndpointDisconnected(endpointId)
            MeshCoordinator.connectedEndpointsMap.remove(endpointId)
            MeshCoordinator.pendingConnections.remove(endpointId)

            val iterator = MeshCoordinator.pendingTransfersMap.entries.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                if (entry.value.endpointId == endpointId) {
                    iterator.remove()
                }
            }
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                MeshCoordinator.updateEndpointsState()
                MeshCoordinator.lastSyncStatusState.value = "Peer disconnected: $endpointId"
            }
            updateNotification("Active • ${MeshCoordinator.connectedEndpointsMap.size} peers connected")
        }
    }

    // ============================================================================
    // PAYLOAD CALLBACK (AUTOMATIC SAVING, ACKS, DEDUPLICATION & LOOP PREVENTION)
    // ============================================================================

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            if (!MeshRateLimiter.isAllowed(endpointId)) {
                Log.w(TAG, "[RATE_LIMITED] Dropping payload from $endpointId: exceeded sliding-window rate limit")
                return
            }
            if (payload.type != Payload.Type.BYTES) return
            val bytes = payload.asBytes() ?: return

            // Mesh Reliability: Maximum payload size enforcement (32 KB limit)
            if (!MeshReliabilityManager.isPayloadSizeValid(bytes)) {
                Log.w(TAG, "[RELIABILITY_REJECTED] Dropping oversized payload from $endpointId: size ${bytes.size} exceeds ${MeshReliabilityManager.MAX_PAYLOAD_BYTES} limit")
                return
            }

            try {
                val json = JSONObject(String(bytes, Charsets.UTF_8))
                val kind = json.optString("kind")

                // 0. Handle Authenticated Peer Key Exchange (E2EE Key Establishment)
                if (kind == "key_exchange_hello") {
                    val peerNodeId = json.optString("nodeId")
                    val edPubKey = json.optString("ed25519PublicKey")
                    val xPubKey = json.optString("x25519PublicKey")
                    val ts = json.optLong("timestamp")
                    val sig = json.optString("signature")

                    if (NodeIdentityManager.verifyIdentityBinding(peerNodeId, edPubKey)) {
                        val registered = RelayE2EEncryption.registerPeerEncryptionKey(
                            nodeId = peerNodeId,
                            ed25519PubKeyHex = edPubKey,
                            x25519PubKeyHex = xPubKey,
                            timestamp = ts,
                            signature = sig
                        )
                        if (registered) {
                            Log.d(TAG, "Established authenticated E2EE keys with peer $peerNodeId")
                        }
                    }
                    return
                }

                // 1. Handle Request Delivery ACK
                if (kind == "ack") {
                    val ackRequestId = json.optString("requestId")
                    val ackStatus = json.optString("status", "DELIVERED")
                    val ackNodeId = json.optString("nodeId", "")
                    val ackPublicKey = json.optString("ackPublicKey", "").ifBlank { null }
                    val ackSignature = json.optString("ackSignature", "").ifBlank { null }
                    val ackTimestamp = json.optLong("timestamp", 0L)
                    val peerName = MeshCoordinator.connectedEndpointsMap[endpointId] ?: "Peer-${endpointId.take(4)}"

                    if (!ackPublicKey.isNullOrBlank() && !ackSignature.isNullOrBlank()) {
                        val isAckValid = EmergencyPacketSigner.verifyAck(
                            requestId = ackRequestId,
                            nodeId = ackNodeId,
                            status = ackStatus,
                            timestamp = ackTimestamp,
                            ackPublicKey = ackPublicKey,
                            signature = ackSignature
                        )
                        if (!isAckValid) {
                            Log.w(TAG, "[SECURITY_REJECTED] ACK digital signature verification failed for request $ackRequestId from $peerName")
                            MeshCoordinator.logTransfer(
                                TransferType.SECURITY_REJECTED,
                                ackRequestId,
                                "Forged ACK Rejected",
                                peerName,
                                0
                            )
                            return
                        }
                    }

                    // Clear matching pending transfers & stop retry
                    val transferKey = "${ackRequestId}_$endpointId"
                    MeshCoordinator.pendingTransfersMap.remove(transferKey)
                    val iterator = MeshCoordinator.pendingTransfersMap.entries.iterator()
                    while (iterator.hasNext()) {
                        val entry = iterator.next()
                        if (entry.value.requestId == ackRequestId && entry.value.endpointId == endpointId) {
                            iterator.remove()
                        }
                    }
                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                    }

                    val current = loadRequests(applicationContext)
                    val idx = current.indexOfFirst { it.id == ackRequestId }
                    if (idx != -1) {
                        val target = current[idx]
                        val isRejected = ackStatus.contains("REJECTED") || ackStatus.contains("INVALID")
                        val updatedTarget = target.copy(
                            syncStatus = if (isRejected) SyncStatus.FAILED else SyncStatus.SYNCED,
                            lastTransferStatus = if (isRejected) "Rejected by $peerName ($ackStatus)" else "Delivered to $peerName (ACK confirmed)"
                        )
                        val updatedList = current.toMutableList().apply {
                            set(idx, updatedTarget)
                        }
                        saveRequests(applicationContext, updatedList)
                        MeshCoordinator.mainHandler.post {
                            MeshCoordinator.onRequestsReceivedListener?.invoke()
                        }
                    }

                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.totalAcksConfirmedState.value++
                    }
                    MeshCoordinator.logTransfer(
                        TransferType.ACK_RECEIVED,
                        ackRequestId,
                        "Status: $ackStatus",
                        peerName,
                        0
                    )
                    return
                }

                // 2. Handle Message Delivery ACK
                if (kind == "ack_message") {
                    val ackMessageId = json.optString("messageId")
                    val current = loadSosMessages(applicationContext)
                    val idx = current.indexOfFirst { it.id == ackMessageId }
                    if (idx != -1 && current[idx].syncStatus != SyncStatus.SYNCED) {
                        val updated = current.toMutableList().apply {
                            set(idx, current[idx].copy(syncStatus = SyncStatus.SYNCED))
                        }
                        saveSosMessages(applicationContext, updated)
                        MeshCoordinator.mainHandler.post {
                            MeshCoordinator.onMessagesReceivedListener?.invoke()
                        }
                    }
                    return
                }

                // 3. Handle SOS Distress & Offline Messages (SEC-07 Authenticated)
                if (kind == "sos_message") {
                    val msgJson = json.getJSONObject("message")
                    val incomingMsg = SosMessage(
                        id = msgJson.getString("id"),
                        senderName = msgJson.optString("senderName", "Nearby Device"),
                        message = msgJson.getString("message"),
                        isEmergency = msgJson.optBoolean("isEmergency", true),
                        timestamp = msgJson.optLong("timestamp", System.currentTimeMillis()),
                        hopCount = msgJson.optInt("hopCount", 0) + 1,
                        syncStatus = SyncStatus.SYNCED,
                        senderPublicKey = msgJson.optString("senderPublicKey", "").ifBlank { null },
                        signature = msgJson.optString("signature", "").ifBlank { null },
                        senderNodeId = msgJson.optString("senderNodeId", "")
                    )

                    // Verify digital signature of SOS message
                    if (!EmergencyPacketSigner.verifySosMessage(incomingMsg)) {
                        Log.w(TAG, "[SECURITY_REJECTED] SOS message signature verification failed for ${incomingMsg.id} from $endpointId")
                        return
                    }

                    // Enforce timestamp bounds (prevent far-future DoS)
                    if (!StatusAuthorizationPolicy.isTimestampWithinBounds(incomingMsg.timestamp)) {
                        Log.w(TAG, "[SECURITY_REJECTED] SOS message timestamp drift out of bounds for ${incomingMsg.id}")
                        return
                    }

                    if (incomingMsg.hopCount > MAX_STORE_FORWARD_HOPS) return

                    val existingMsgs = loadSosMessages(applicationContext)
                    if (existingMsgs.none { it.id == incomingMsg.id }) {
                        val updatedList = StorageRetentionManager.pruneSosMessages(existingMsgs + incomingMsg)
                        saveSosMessages(applicationContext, updatedList)
                        MeshCoordinator.mainHandler.post {
                            MeshCoordinator.onMessagesReceivedListener?.invoke()
                            MeshCoordinator.lastSyncStatusState.value = "SOS broadcast from ${incomingMsg.senderName}"
                        }
                        sendAckForMessage(endpointId, incomingMsg.id)
                        relayMessageToOtherPeers(incomingMsg, excludeEndpoint = endpointId)
                    } else {
                        sendAckForMessage(endpointId, incomingMsg.id)
                    }
                    return
                }

                // 4. Handle Emergency Coordination Requests (Automatic Store-and-Forward)
                if (kind == "emergency_request") {
                    val requestJson = json.getJSONObject("request")
                    val reqId = requestJson.getString("id")
                    val peerName = MeshCoordinator.connectedEndpointsMap[endpointId] ?: "Peer-${endpointId.take(4)}"

                    val incomingHistory = StoreAndForwardHelper.parseNodeHistory(requestJson.optJSONArray("nodeHistory"))
                    val incomingHopCount = requestJson.optInt("hopCount", 0) + 1
                    val incomingCreatedAt = requestJson.optLong("createdAt", System.currentTimeMillis())
                    val incomingTtl = requestJson.optInt("ttlHours", DEFAULT_REQUEST_TTL_HOURS)
                    val incomingPublicKey = requestJson.optString("senderPublicKey", "").ifBlank { null }
                    val incomingSignature = requestJson.optString("signature", "").ifBlank { null }
                    val incomingOriginatorNodeId = requestJson.optString("originatorNodeId", "")

                    val incomingSeq = requestJson.optInt("sequenceNumber", 0)
                    val incomingStatusSig = requestJson.optString("lastStatusSignature", "").ifBlank { null }
                    val incomingStatusUpdaterPubKey = requestJson.optString("lastStatusUpdaterPublicKey", "").ifBlank { null }
                    val incomingStatusUpdaterRole = requestJson.optString("lastStatusUpdaterRole", "").ifBlank { null }
                    val incomingLat = if (requestJson.has("latitude") && !requestJson.isNull("latitude")) requestJson.optDouble("latitude") else null
                    val incomingLng = if (requestJson.has("longitude") && !requestJson.isNull("longitude")) requestJson.optDouble("longitude") else null
                    val incomingAcc = if (requestJson.has("accuracy") && !requestJson.isNull("accuracy")) requestJson.optDouble("accuracy").toFloat() else null

                    val incomingRequest = EmergencyRequest(
                        id = reqId,
                        type = requestJson.getString("type"),
                        description = requestJson.getString("description"),
                        people = requestJson.getInt("people"),
                        priority = requestJson.getString("priority"),
                        status = requestJson.optString("status", RequestStatus.PENDING),
                        updatedAt = requestJson.optLong("updatedAt", System.currentTimeMillis()),
                        syncStatus = SyncStatus.SYNCED,
                        hopCount = incomingHopCount,
                        createdAt = incomingCreatedAt,
                        ttlHours = incomingTtl,
                        nodeHistory = if (incomingHistory.contains(localNodeId)) incomingHistory else incomingHistory + localNodeId,
                        lastTransferStatus = "Received from $peerName (hop $incomingHopCount)",
                        senderPublicKey = incomingPublicKey,
                        signature = incomingSignature,
                        originatorNodeId = incomingOriginatorNodeId,
                        sequenceNumber = incomingSeq,
                        lastStatusSignature = incomingStatusSig,
                        lastStatusUpdaterPublicKey = incomingStatusUpdaterPubKey,
                        lastStatusUpdaterRole = incomingStatusUpdaterRole,
                        latitude = incomingLat,
                        longitude = incomingLng,
                        locationAccuracyMeters = incomingAcc
                    )

                    // Unified Security Ingress Gate: Validates Author Signature, Expiry, Hop Count & Authenticated Status Updates
                    val ingressDecision = EmergencyForwardingGate.evaluateIngress(incomingRequest, localNodeId)
                    if (ingressDecision is IngressDecision.Reject) {
                        Log.w(TAG, "SECURITY REJECTION: Dropping request ${incomingRequest.id} from $peerName (${ingressDecision.reason})")
                        MeshCoordinator.logTransfer(
                            ingressDecision.transferType,
                            incomingRequest.id,
                            "${incomingRequest.type} (${ingressDecision.reason})",
                            peerName,
                            incomingHopCount
                        )
                        sendAck(endpointId, incomingRequest.id, status = ingressDecision.ackStatus)
                        return
                    }

                    // C. Loop Prevention: Self in Node History (Echo suppression)
                    if (incomingHistory.contains(localNodeId)) {
                        MeshCoordinator.logTransfer(
                            TransferType.LOOP_PREVENTED,
                            incomingRequest.id,
                            "${incomingRequest.type} (Echo prevented: local node in history)",
                            peerName,
                            incomingHopCount
                        )
                        sendAck(endpointId, incomingRequest.id, status = "LOOP_DETECTED")
                        return
                    }

                    // D. Conflict Resolution, Monotonic Sequence Enforcement & Replay Prevention
                    val existing = loadRequests(applicationContext)
                    val existingIndex = existing.indexOfFirst { it.id == incomingRequest.id }
                    val updatedList: List<EmergencyRequest>
                    var isNewOrUpdated = false

                    if (existingIndex != -1) {
                        val currentRecord = existing[existingIndex]

                        // Rollback / Replay Prevention: reject duplicate or lower sequence numbers
                        if (incomingRequest.sequenceNumber <= currentRecord.sequenceNumber) {
                            Log.d(TAG, "Dropping request ${incomingRequest.id}: sequenceNumber ${incomingRequest.sequenceNumber} <= current ${currentRecord.sequenceNumber} (Rollback / Duplicate)")
                            sendAck(endpointId, incomingRequest.id, status = "DELIVERED")
                            return
                        }

                        // State Machine Transition Enforcement:
                        if (!StatusAuthorizationPolicy.isValidTransition(currentRecord.status, incomingRequest.status)) {
                            Log.w(TAG, "SECURITY REJECTION: Dropping illegal state transition from ${currentRecord.status} to ${incomingRequest.status} for ${incomingRequest.id}")
                            MeshCoordinator.logTransfer(
                                TransferType.SECURITY_REJECTED,
                                incomingRequest.id,
                                "${incomingRequest.type} (Illegal transition ${currentRecord.status}->${incomingRequest.status})",
                                peerName,
                                incomingHopCount
                            )
                            sendAck(endpointId, incomingRequest.id, status = "INVALID_TRANSITION")
                            return
                        }

                        isNewOrUpdated = true
                        updatedList = existing.toMutableList().apply {
                            set(existingIndex, incomingRequest)
                        }
                    } else {
                        isNewOrUpdated = true
                        updatedList = existing + incomingRequest
                    }

                    // Automatically save locally (Atomic permanent commit)
                    saveRequests(applicationContext, updatedList)
                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.totalTransfersReceivedState.value++
                    }
                    MeshCoordinator.logTransfer(
                        TransferType.RECEIVED,
                        incomingRequest.id,
                        "${incomingRequest.type} (${incomingRequest.priority})",
                        peerName,
                        incomingHopCount
                    )

                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.onRequestsReceivedListener?.invoke()
                        MeshCoordinator.lastSyncStatusState.value = "Request received: ${incomingRequest.type} from $peerName"
                    }
                    updateNotification("Received: ${incomingRequest.type} (${incomingRequest.priority})")

                    // Send delivery acknowledgement
                    sendAck(endpointId, incomingRequest.id, status = "DELIVERED")

                    // Automatically forward/relay to all other connected peers
                    if (isNewOrUpdated) {
                        relayToOtherPeers(incomingRequest, excludeEndpoint = endpointId)
                    }
                    return
                }

            } catch (e: Exception) {
                Log.e(TAG, "Could not process received payload", e)
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {
            when (update.status) {
                PayloadTransferUpdate.Status.SUCCESS -> {
                    Log.d(TAG, "Payload successfully transferred to $endpointId")
                }
                PayloadTransferUpdate.Status.FAILURE -> {
                    Log.e(TAG, "Payload failed to transfer to $endpointId")
                }
            }
        }
    }

    // ============================================================================
    // STORE-AND-FORWARD DISPATCHING & RETRY ENGINE
    // ============================================================================

    fun exchangeStoredRequestsWithPeer(endpointId: String, peerName: String) {
        val requests = loadRequests(applicationContext)
        val validRequests = requests.filter { !it.isExpired }

        var dispatchedCount = 0
        for (request in validRequests) {
            // Prevent looping: do not send back to a peer that is already in nodeHistory
            if (request.nodeHistory.contains(peerName)) {
                Log.d(TAG, "Skipping request ${request.id} for $peerName: already in node history")
                continue
            }

            forwardSingleRequestToEndpoint(request, endpointId, peerName)
            dispatchedCount++
        }

        // Also exchange stored SOS messages
        val messages = loadSosMessages(applicationContext)
        messages.forEach { msg ->
            try {
                val json = JSONObject().apply {
                    put("kind", "sos_message")
                    put("message", JSONObject().apply {
                        put("id", msg.id)
                        put("senderName", msg.senderName)
                        put("message", msg.message)
                        put("isEmergency", msg.isEmergency)
                        put("timestamp", msg.timestamp)
                        put("hopCount", msg.hopCount)
                        put("senderPublicKey", msg.senderPublicKey ?: "")
                        put("signature", msg.signature ?: "")
                        put("senderNodeId", msg.senderNodeId)
                    })
                }
                val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
                connectionsClient.sendPayload(endpointId, payload)
            } catch (e: Exception) {
                Log.e(TAG, "Error syncing SOS to $endpointId", e)
            }
        }

        MeshCoordinator.mainHandler.post {
            MeshCoordinator.lastSyncStatusState.value = "Exchanged $dispatchedCount stored requests with $peerName"
        }
    }

    fun forwardSingleRequestToEndpoint(request: EmergencyRequest, endpointId: String, peerName: String) {
        val decision = EmergencyForwardingGate.evaluateForwarding(applicationContext, request, localNodeId)
        val stagedRequest = when (decision) {
            is ForwardingDecision.Reject -> {
                Log.w(TAG, "SECURITY ENFORCEMENT: ${decision.reason} for request ${request.id} to $peerName")
                MeshCoordinator.logTransfer(
                    decision.transferType,
                    request.id,
                    "${request.type} (${decision.reason.take(35)})",
                    peerName,
                    request.hopCount
                )
                return
            }
            is ForwardingDecision.Allow -> decision.stagedRequest
        }

        try {

            val updatedHistory = if (stagedRequest.nodeHistory.contains(localNodeId)) {
                stagedRequest.nodeHistory
            } else {
                stagedRequest.nodeHistory + localNodeId
            }

            val json = JSONObject().apply {
                put("kind", "emergency_request")
                put("request", JSONObject().apply {
                    put("id", stagedRequest.id)
                    put("type", stagedRequest.type)
                    put("description", stagedRequest.description)
                    put("people", stagedRequest.people)
                    put("priority", stagedRequest.priority)
                    put("status", stagedRequest.status)
                    put("updatedAt", stagedRequest.updatedAt)
                    put("createdAt", stagedRequest.createdAt)
                    put("ttlHours", stagedRequest.ttlHours)
                    put("hopCount", stagedRequest.hopCount)
                    put("nodeHistory", StoreAndForwardHelper.serializeNodeHistory(updatedHistory))
                    put("senderNodeId", localNodeId) // Hop forwarder identity
                    put("senderPublicKey", stagedRequest.senderPublicKey ?: "")
                    put("signature", stagedRequest.signature ?: "")
                    put("originatorNodeId", stagedRequest.originatorNodeId) // Author identity preserved
                    put("sequenceNumber", stagedRequest.sequenceNumber)
                    put("lastStatusSignature", stagedRequest.lastStatusSignature ?: "")
                    put("lastStatusUpdaterPublicKey", stagedRequest.lastStatusUpdaterPublicKey ?: "")
                    put("lastStatusUpdaterRole", stagedRequest.lastStatusUpdaterRole ?: "")
                    stagedRequest.latitude?.let { put("latitude", it) }
                    stagedRequest.longitude?.let { put("longitude", it) }
                    stagedRequest.locationAccuracyMeters?.let { put("accuracy", it.toDouble()) }
                })
            }

            val payloadBytes = json.toString().toByteArray(Charsets.UTF_8)
            val payload = Payload.fromBytes(payloadBytes)

            val transferKey = "${request.id}_$endpointId"
            val pending = PendingTransfer(
                requestId = request.id,
                endpointId = endpointId,
                peerName = peerName,
                payloadBytes = payloadBytes,
                attempts = 1
            )
            MeshCoordinator.pendingTransfersMap[transferKey] = pending
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
            }

            connectionsClient.sendPayload(endpointId, payload).addOnSuccessListener {
                MeshCoordinator.mainHandler.post {
                    MeshCoordinator.totalTransfersForwardedState.value++
                }
                MeshCoordinator.logTransfer(
                    TransferType.FORWARDED,
                    request.id,
                    "${request.type} (${request.priority})",
                    peerName,
                    request.hopCount
                )
                scheduleRetryCheck(transferKey)
            }.addOnFailureListener {
                MeshCoordinator.pendingTransfersMap.remove(transferKey)
                MeshCoordinator.mainHandler.post {
                    MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                }
                Log.e(TAG, "Failed sending request ${request.id} to $peerName", it)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error packaging request for $peerName", e)
        }
    }

    private fun scheduleRetryCheck(transferKey: String) {
        retryHandler.postDelayed({
            val pending = MeshCoordinator.pendingTransfersMap[transferKey] ?: return@postDelayed

            if (!MeshCoordinator.connectedEndpointsMap.containsKey(pending.endpointId)) {
                MeshCoordinator.pendingTransfersMap.remove(transferKey)
                MeshCoordinator.mainHandler.post {
                    MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                }
                return@postDelayed
            }

            if (pending.attempts < MAX_TRANSFER_RETRIES) {
                pending.attempts++
                MeshCoordinator.logTransfer(
                    TransferType.RETRY,
                    pending.requestId,
                    "Attempt ${pending.attempts}/$MAX_TRANSFER_RETRIES",
                    pending.peerName,
                    0
                )
                val retryPayload = Payload.fromBytes(pending.payloadBytes)
                connectionsClient.sendPayload(pending.endpointId, retryPayload).addOnSuccessListener {
                    scheduleRetryCheck(transferKey)
                }.addOnFailureListener {
                    MeshCoordinator.pendingTransfersMap.remove(transferKey)
                    MeshCoordinator.mainHandler.post {
                        MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                    }
                }
            } else {
                MeshCoordinator.pendingTransfersMap.remove(transferKey)
                MeshCoordinator.mainHandler.post {
                    MeshCoordinator.pendingTransfersCountState.value = MeshCoordinator.pendingTransfersMap.size
                }
                Log.w(TAG, "Max retries reached for transfer $transferKey to ${pending.peerName}")
            }
        }, ACK_TIMEOUT_MS)
    }

    private fun sendAck(endpointId: String, requestId: String, status: String = "DELIVERED") {
        try {
            val (ackSig, ackPubKey, ackTime) = EmergencyPacketSigner.signAck(applicationContext, requestId, status)
            val json = JSONObject().apply {
                put("kind", "ack")
                put("requestId", requestId)
                put("nodeId", localNodeId)
                put("status", status)
                put("ackPublicKey", ackPubKey)
                put("ackSignature", ackSig)
                put("timestamp", ackTime)
            }
            val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
            connectionsClient.sendPayload(endpointId, payload).addOnSuccessListener {
                val peerName = MeshCoordinator.connectedEndpointsMap[endpointId] ?: "Peer-${endpointId.take(4)}"
                MeshCoordinator.logTransfer(
                    TransferType.ACK_SENT,
                    requestId,
                    "ACK ($status)",
                    peerName,
                    0
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending ACK to $endpointId", e)
        }
    }

    private fun sendAckForMessage(endpointId: String, messageId: String) {
        try {
            val json = JSONObject().apply {
                put("kind", "ack_message")
                put("messageId", messageId)
            }
            val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
            connectionsClient.sendPayload(endpointId, payload)
        } catch (e: Exception) {
            Log.e(TAG, "Error sending ACK for message to $endpointId", e)
        }
    }

    private fun relayToOtherPeers(request: EmergencyRequest, excludeEndpoint: String) {
        if (request.isExpired) return
        if (request.hopCount >= MAX_STORE_FORWARD_HOPS) return

        val peers = MeshCoordinator.connectedEndpointsMap.filter { it.key != excludeEndpoint }
        if (peers.isEmpty()) return

        for ((peerEndpointId, peerName) in peers) {
            if (request.nodeHistory.contains(peerName)) {
                continue
            }
            forwardSingleRequestToEndpoint(request, peerEndpointId, peerName)
        }
    }

    private fun relayMessageToOtherPeers(msg: SosMessage, excludeEndpoint: String) {
        if (msg.hopCount >= MAX_STORE_FORWARD_HOPS) return
        val peers = MeshCoordinator.connectedEndpointsMap.keys.filter { it != excludeEndpoint }
        if (peers.isEmpty()) return

        try {
            val json = JSONObject().apply {
                put("kind", "sos_message")
                put("message", JSONObject().apply {
                    put("id", msg.id)
                    put("senderName", msg.senderName)
                    put("message", msg.message)
                    put("isEmergency", msg.isEmergency)
                    put("timestamp", msg.timestamp)
                    put("hopCount", msg.hopCount)
                    put("senderPublicKey", msg.senderPublicKey ?: "")
                    put("signature", msg.signature ?: "")
                    put("senderNodeId", msg.senderNodeId)
                })
            }
            val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
            peers.forEach { peerId ->
                connectionsClient.sendPayload(peerId, payload)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error relaying SOS message across mesh", e)
        }
    }

    fun syncAllNow() {
        if (MeshCoordinator.connectedEndpointsMap.isEmpty()) {
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "No peers in direct range to sync."
            }
            return
        }
        MeshCoordinator.mainHandler.post {
            MeshCoordinator.lastSyncStatusState.value = "Exchanging stored emergency requests with peers..."
        }
        MeshCoordinator.connectedEndpointsMap.forEach { (endpointId, peerName) ->
            exchangeStoredRequestsWithPeer(endpointId, peerName)
        }
    }

    fun sendRequestToConnectedDevices(request: EmergencyRequest) {
        if (!MeshCoordinator.isMeshActiveState.value) {
            startMesh()
        }
        if (MeshCoordinator.connectedEndpointsMap.isEmpty()) {
            Log.d(TAG, "No connected devices. Request saved locally (Pending Sync).")
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "Saved locally. Will sync when peer comes in range."
            }
            return
        }

        MeshCoordinator.connectedEndpointsMap.forEach { (endpointId, peerName) ->
            forwardSingleRequestToEndpoint(request, endpointId, peerName)
        }
        MeshCoordinator.mainHandler.post {
            MeshCoordinator.lastSyncStatusState.value = "Forwarded ${request.type} request to ${MeshCoordinator.connectedEndpointsMap.size} peers"
        }
    }

    fun sendSosMessageToConnectedDevices(msg: SosMessage) {
        val signedMsg = if (msg.isCryptographicallySigned) {
            msg
        } else {
            EmergencyPacketSigner.signSosMessage(applicationContext, msg)
        }

        if (!MeshCoordinator.isMeshActiveState.value) {
            startMesh()
        }
        if (MeshCoordinator.connectedEndpointsMap.isEmpty()) {
            Log.d(TAG, "No connected peers. SOS saved locally (Pending Sync).")
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "SOS saved locally. Auto-broadcasting when peers detected."
            }
            return
        }

        try {
            val json = JSONObject().apply {
                put("kind", "sos_message")
                put("message", JSONObject().apply {
                    put("id", signedMsg.id)
                    put("senderName", signedMsg.senderName)
                    put("message", signedMsg.message)
                    put("isEmergency", signedMsg.isEmergency)
                    put("timestamp", signedMsg.timestamp)
                    put("hopCount", signedMsg.hopCount)
                    put("senderPublicKey", signedMsg.senderPublicKey ?: "")
                    put("signature", signedMsg.signature ?: "")
                    put("senderNodeId", signedMsg.senderNodeId)
                })
            }
            val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
            MeshCoordinator.connectedEndpointsMap.keys.forEach { endpointId ->
                connectionsClient.sendPayload(endpointId, payload)
            }
            MeshCoordinator.mainHandler.post {
                MeshCoordinator.lastSyncStatusState.value = "SOS sent to ${MeshCoordinator.connectedEndpointsMap.size} nearby peers"
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error sending SOS payload", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.d(TAG, "RelayMeshService onDestroy")
        stopMesh()
        stopForegroundSafely()
        MeshCoordinator.serviceInstance = null
    }

    private fun sendKeyExchangeHello(endpointId: String) {
        try {
            val keyManager = RelayKeyStoreManager.getInstance(applicationContext)
            val ed25519Pub = keyManager.getPublicKeyHex()
            val x25519Pub = keyManager.getX25519PublicKeyHex()
            val now = System.currentTimeMillis()
            val canonicalBytes = RelayE2EEncryption.buildKeyBindingCanonicalBytes(localNodeId, ed25519Pub, x25519Pub, now)
            val sig = keyManager.sign(canonicalBytes)

            val json = JSONObject().apply {
                put("kind", "key_exchange_hello")
                put("nodeId", localNodeId)
                put("ed25519PublicKey", ed25519Pub)
                put("x25519PublicKey", x25519Pub)
                put("timestamp", now)
                put("signature", sig)
            }
            val payload = Payload.fromBytes(json.toString().toByteArray(Charsets.UTF_8))
            connectionsClient.sendPayload(endpointId, payload)
        } catch (e: Exception) {
            Log.e(TAG, "Failed sending KeyExchangeHello to $endpointId", e)
        }
    }

}
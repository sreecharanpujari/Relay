package com.relay.emergency

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.animation.Crossfade
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Shadow
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.text.TextStyle
import kotlinx.coroutines.delay
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import com.relay.emergency.crypto.RelayE2EEncryption
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.*
import com.relay.emergency.mesh.*
import com.relay.emergency.mesh.StoreAndForwardHelper
import com.relay.emergency.mesh.NodeIdentityManager
import com.relay.emergency.mesh.TransferType
import com.relay.emergency.mesh.TransferLogEntry
import com.relay.emergency.mesh.PendingTransfer
import com.relay.emergency.mesh.DEFAULT_REQUEST_TTL_HOURS
import com.relay.emergency.mesh.MAX_TRANSFER_RETRIES
import com.relay.emergency.mesh.ACK_TIMEOUT_MS
import com.relay.emergency.service.RelayMeshService
import com.relay.emergency.service.MeshCoordinator
import com.relay.emergency.crypto.EmergencyPacketSigner
import com.relay.emergency.crypto.LocalOriginRegistry
import com.relay.emergency.crypto.RelayKeyStoreManager
import com.relay.emergency.crypto.StatusAuthorizationPolicy
import com.relay.emergency.ui.theme.*
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

// ----------------------------------------------------
// CONSTANTS & PALETTE (RELAY COMMAND CENTER SPECIFICATION)
// ----------------------------------------------------

private const val TAG = "RELAY"
private const val SERVICE_ID = "com.relay.emergency"
private const val PREFS_NAME = "relay_storage"
private const val REQUESTS_KEY = "requests"
private const val MESSAGES_KEY = "sos_messages"
const val MAX_STORE_FORWARD_HOPS = 5

// Dynamic theme-aware palette tokens (RelayBg, RelayCardBg, RelayPrimaryAccent, etc.)
// are provided across all composables by com.relay.emergency.ui.theme.*

object RequestStatus {
    const val PENDING = "Pending"
    const val ASSIGNED = "Assigned"
    const val IN_PROGRESS = "In Progress"
    const val RESOLVED = "Resolved"

    val ALL = listOf(PENDING, ASSIGNED, IN_PROGRESS, RESOLVED)
}

object SyncStatus {
    const val PENDING_SYNC = "Pending Sync"
    const val SYNCED = "Synced"
    const val FAILED = "Failed"
}

enum class Screen {
    HOME,
    REQUESTS,
    NETWORK,
    PROFILE,
    CREATE_REQUEST,
    REQUEST_DETAILS
}

// ----------------------------------------------------
// DATA MODELS
// ----------------------------------------------------

data class EmergencyRequest(
    val id: String = UUID.randomUUID().toString(),
    val type: String,
    val description: String,
    val people: Int,
    val priority: String,
    val status: String = RequestStatus.PENDING,
    val updatedAt: Long = System.currentTimeMillis(),
    val syncStatus: String = SyncStatus.PENDING_SYNC,
    val hopCount: Int = 0,
    val createdAt: Long = updatedAt,
    val ttlHours: Int = DEFAULT_REQUEST_TTL_HOURS,
    val nodeHistory: List<String> = emptyList(),
    val lastTransferStatus: String = "Created locally",
    // Ed25519 Cryptographic Security Fields
    val senderPublicKey: String? = null,
    val signature: String? = null,
    val originatorNodeId: String = "",
    // Authenticated Status Update Fields (Priority 2)
    val sequenceNumber: Int = 0,
    val lastStatusSignature: String? = null,
    val lastStatusUpdaterPublicKey: String? = null,
    val lastStatusUpdaterRole: String? = null,
    val latitude: Double? = null,
    val longitude: Double? = null,
    val locationAccuracyMeters: Float? = null
) {
    val isStatusAuthenticated: Boolean
        get() = sequenceNumber == 0 || (!lastStatusSignature.isNullOrBlank() && !lastStatusUpdaterPublicKey.isNullOrBlank())
    val isCryptographicallySigned: Boolean
        get() = !signature.isNullOrBlank() && !senderPublicKey.isNullOrBlank()
    val isExpired: Boolean
        get() {
            val expiryTime = createdAt + (ttlHours * 3600 * 1000L)
            return System.currentTimeMillis() > expiryTime
        }

    val timeRemainingHours: Long
        get() {
            val expiryTime = createdAt + (ttlHours * 3600 * 1000L)
            val remaining = expiryTime - System.currentTimeMillis()
            return if (remaining > 0) (remaining / (3600 * 1000L)) else 0L
        }
}

data class SosMessage(
    val id: String = UUID.randomUUID().toString(),
    val senderName: String,
    val message: String,
    val isEmergency: Boolean = true,
    val timestamp: Long = System.currentTimeMillis(),
    val hopCount: Int = 0,
    val syncStatus: String = SyncStatus.PENDING_SYNC,
    val senderPublicKey: String? = null,
    val signature: String? = null,
    val senderNodeId: String = ""
) {
    val isCryptographicallySigned: Boolean
        get() = !signature.isNullOrBlank() && !senderPublicKey.isNullOrBlank()
}

data class UserProfile(
    val name: String,
    val role: String = "Disaster Responder",
    val phone: String = "",
    val bloodGroup: String = "O+",
    val autoStartMesh: Boolean = true
)

// ----------------------------------------------------
// MAIN ACTIVITY (NEARBY CONNECTIONS & LIFECYCLE)
// ----------------------------------------------------

class MainActivity : ComponentActivity() {

    val localNodeId by lazy {
        NodeIdentityManager.getLocalNodeId(this)
    }

    val isNearbyActiveState get() = MeshCoordinator.isMeshActiveState
    val connectedEndpointsCountState get() = MeshCoordinator.connectedEndpointsCountState
    val lastSyncStatusState get() = MeshCoordinator.lastSyncStatusState
    val connectedEndpointsListState get() = MeshCoordinator.connectedEndpointsListState

    val transferEventsLog get() = MeshCoordinator.transferEventsLog
    val totalTransfersReceivedState get() = MeshCoordinator.totalTransfersReceivedState
    val totalTransfersForwardedState get() = MeshCoordinator.totalTransfersForwardedState
    val totalAcksConfirmedState get() = MeshCoordinator.totalAcksConfirmedState
    val pendingTransfersCountState get() = MeshCoordinator.pendingTransfersCountState

    val connectedEndpointsMap get() = MeshCoordinator.connectedEndpointsMap
    val pendingConnections get() = MeshCoordinator.pendingConnections
    val pendingTransfersMap get() = MeshCoordinator.pendingTransfersMap

    var onRequestsReceivedListener: (() -> Unit)?
        get() = MeshCoordinator.onRequestsReceivedListener
        set(value) { MeshCoordinator.onRequestsReceivedListener = value }

    var onMessagesReceivedListener: (() -> Unit)?
        get() = MeshCoordinator.onMessagesReceivedListener
        set(value) { MeshCoordinator.onMessagesReceivedListener = value }

    fun logTransfer(
        type: TransferType,
        requestId: String,
        summary: String,
        peerName: String,
        hopCount: Int
    ) {
        MeshCoordinator.logTransfer(type, requestId, summary, peerName, hopCount)
    }

    private val requestPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { perms ->
            val allGranted = perms.values.all { it }
            if (allGranted) {
                Log.d(TAG, "All permissions granted. Auto-starting offline mesh...")
                startNearby()
            } else {
                Log.e(TAG, "Not all permissions granted: $perms")
                lastSyncStatusState.value = "Permissions required for offline mesh."
            }
        }

    private fun cleanLegacyDemoDataIfNeeded() {
        val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (!prefs.getBoolean("cleaned_legacy_demo_data_v2", false)) {
            val savedData = prefs.getString(REQUESTS_KEY, null)
            if (!savedData.isNullOrBlank()) {
                try {
                    val arr = JSONArray(savedData)
                    val cleanList = JSONArray()
                    for (i in 0 until arr.length()) {
                        val item = arr.getJSONObject(i)
                        val id = item.optString("id", "")
                        if (!id.startsWith("REQ-RELAY-00")) {
                            cleanList.put(item)
                        }
                    }
                    prefs.edit()
                        .putString(REQUESTS_KEY, cleanList.toString())
                        .apply()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed cleaning demo requests", e)
                }
            }
            val savedSos = prefs.getString(MESSAGES_KEY, null)
            if (!savedSos.isNullOrBlank()) {
                try {
                    val arr = JSONArray(savedSos)
                    val cleanList = JSONArray()
                    for (i in 0 until arr.length()) {
                        val item = arr.getJSONObject(i)
                        val id = item.optString("id", "")
                        if (!id.startsWith("MSG-00")) {
                            cleanList.put(item)
                        }
                    }
                    prefs.edit()
                        .putString(MESSAGES_KEY, cleanList.toString())
                        .apply()
                } catch (e: Exception) {
                    Log.e(TAG, "Failed cleaning demo SOS", e)
                }
            }
            // Clear simulated endpoints, fake logs, and fake counters
            MeshCoordinator.connectedEndpointsListState.value = emptyList()
            MeshCoordinator.connectedEndpointsCountState.value = 0
            MeshCoordinator.transferEventsLog.clear()
            MeshCoordinator.totalTransfersReceivedState.value = 0
            MeshCoordinator.totalTransfersForwardedState.value = 0
            MeshCoordinator.totalAcksConfirmedState.value = 0
            MeshCoordinator.lastSyncStatusState.value = "Ready for off-grid command"

            prefs.edit().putBoolean("cleaned_legacy_demo_data_v2", true).apply()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        StatusAuthorizationPolicy.loadPersistedResponders(this)
        PowerConservationManager.initialize(this)
        cleanLegacyDemoDataIfNeeded()
        val profile = loadUserProfile(this)
        if (profile.autoStartMesh) {
            if (hasNearbyPermissions()) {
                Log.d(TAG, "Nearby permissions already granted, starting mesh...")
                startNearby()
            } else {
                requestNearbyPermissions()
            }
        }

        setContent {
            val themeMode by ThemePreferences.getThemeModeFlow(this).collectAsState(
                initial = remember { ThemePreferences.getCachedThemeMode(this) }
            )
            val coroutineScope = rememberCoroutineScope()
            var showSplash by remember { mutableStateOf(true) }

            RELAYTheme(themeMode = themeMode) {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = RelayBg
                ) {
                    Crossfade(
                        targetState = showSplash,
                        animationSpec = tween(durationMillis = 400),
                        label = "SplashCrossfade"
                    ) { isSplash ->
                        if (isSplash) {
                            AnimatedSplashScreen(
                                onSplashFinished = { showSplash = false }
                            )
                        } else {
                            CommandCenterApp(
                                activity = this,
                                currentThemeMode = themeMode,
                                onThemeSelected = { newMode ->
                                    coroutineScope.launch {
                                        ThemePreferences.setThemeMode(this@MainActivity, newMode)
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }

    private fun requestNearbyPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.ACCESS_COARSE_LOCATION
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            permissions.addAll(
                listOf(
                    Manifest.permission.BLUETOOTH_SCAN,
                    Manifest.permission.BLUETOOTH_CONNECT,
                    Manifest.permission.BLUETOOTH_ADVERTISE
                )
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.NEARBY_WIFI_DEVICES)
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        requestPermissionLauncher.launch(permissions.toTypedArray())
    }

    private fun hasNearbyPermissions(): Boolean {
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
            required.add(Manifest.permission.POST_NOTIFICATIONS)
        }

        return required.all {
            ContextCompat.checkSelfPermission(
                this,
                it
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun startNearby() {
        if (!hasNearbyPermissions()) {
            Log.e(TAG, "Nearby permissions missing")
            requestNearbyPermissions()
            return
        }
        RelayMeshService.start(this)
    }

    fun stopNearby() {
        RelayMeshService.stop(this)
    }

    fun syncAllNow() {
        if (MeshCoordinator.serviceInstance != null && MeshCoordinator.connectedEndpointsCountState.value > 0) {
            RelayMeshService.syncAll(this)
        } else if (MeshCoordinator.serviceInstance != null) {
            android.widget.Toast.makeText(
                this,
                "Scanning for mesh radios... No peers connected yet. Stored locally.",
                android.widget.Toast.LENGTH_SHORT
            ).show()
        } else {
            startNearby()
            android.widget.Toast.makeText(
                this,
                "Starting radio mesh... Searching for nearby emergency nodes.",
                android.widget.Toast.LENGTH_SHORT
            ).show()
        }
    }

    fun exchangeStoredRequestsWithPeer(endpointId: String, peerName: String) {
        val service = MeshCoordinator.serviceInstance
        if (service != null) {
            service.exchangeStoredRequestsWithPeer(endpointId, peerName)
        } else {
            startNearby()
            MeshCoordinator.mainHandler.postDelayed({
                MeshCoordinator.serviceInstance?.exchangeStoredRequestsWithPeer(endpointId, peerName)
            }, 600)
        }
    }

    fun forwardSingleRequestToEndpoint(request: EmergencyRequest, endpointId: String, peerName: String) {
        MeshCoordinator.serviceInstance?.forwardSingleRequestToEndpoint(request, endpointId, peerName)
    }

    fun sendRequestToConnectedDevices(request: EmergencyRequest) {
        val service = MeshCoordinator.serviceInstance
        if (service != null) {
            service.sendRequestToConnectedDevices(request)
        } else {
            startNearby()
            MeshCoordinator.mainHandler.postDelayed({
                MeshCoordinator.serviceInstance?.sendRequestToConnectedDevices(request)
            }, 600)
        }
    }

    fun sendSosMessageToConnectedDevices(msg: SosMessage) {
        val service = MeshCoordinator.serviceInstance
        if (service != null) {
            service.sendSosMessageToConnectedDevices(msg)
        } else {
            startNearby()
            MeshCoordinator.mainHandler.postDelayed({
                MeshCoordinator.serviceInstance?.sendSosMessageToConnectedDevices(msg)
            }, 600)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // Note: RelayMeshService continues operating in the background as an Android
        // foreground service with a persistent notification. We only release UI callbacks here.
        MeshCoordinator.onRequestsReceivedListener = null
        MeshCoordinator.onMessagesReceivedListener = null
    }
}

// ----------------------------------------------------
// COMMAND CENTER APP ROOT & ROUTING
// ----------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CommandCenterApp(
    activity: MainActivity,
    currentThemeMode: ThemeMode = ThemeMode.SYSTEM,
    onThemeSelected: (ThemeMode) -> Unit = {}
) {
    val context = activity.applicationContext

    var currentScreen by remember { mutableStateOf(Screen.HOME) }
    var previousScreen by remember { mutableStateOf(Screen.HOME) }

    var requests by remember { mutableStateOf(loadRequests(context)) }
    var sosMessages by remember { mutableStateOf(loadSosMessages(context)) }
    var selectedRequest by remember { mutableStateOf<EmergencyRequest?>(null) }

    // Live reactive listeners for incoming mesh broadcasts
    DisposableEffect(activity) {
        activity.onRequestsReceivedListener = {
            requests = loadRequests(context)
        }
        activity.onMessagesReceivedListener = {
            sosMessages = loadSosMessages(context)
        }
        onDispose {
            activity.onRequestsReceivedListener = null
            activity.onMessagesReceivedListener = null
        }
    }

    // Hardware/gesture back handler
    BackHandler(enabled = currentScreen == Screen.CREATE_REQUEST || currentScreen == Screen.REQUEST_DETAILS) {
        currentScreen = previousScreen
    }

    fun navigateTo(screen: Screen) {
        previousScreen = currentScreen
        currentScreen = screen
    }

    Scaffold(
        containerColor = RelayBg,
        topBar = {
            if (currentScreen in listOf(Screen.HOME, Screen.REQUESTS, Screen.NETWORK, Screen.PROFILE)) {
                TopAppBar(
                    title = {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Image(
                                painter = painterResource(id = R.drawable.ic_relay_logo),
                                contentDescription = "RELAY Logo",
                                modifier = Modifier.size(34.dp)
                            )
                            Column {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        text = "Relay",
                                        fontWeight = FontWeight.Black,
                                        letterSpacing = 1.2.sp,
                                        color = RelayTextPrimary
                                    )
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Surface(
                                        color = RelayCardElevated,
                                        shape = RoundedCornerShape(4.dp),
                                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayPrimaryAccent)
                                    ) {
                                        Text(
                                            text = "COMMAND CENTER",
                                            color = RelayPrimaryAccent,
                                            style = MaterialTheme.typography.labelSmall,
                                            fontWeight = FontWeight.Bold,
                                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                        )
                                    }
                                }
                                val isMeshActive by activity.isNearbyActiveState
                                val connectedCount by activity.connectedEndpointsCountState
                                Text(
                                    text = if (connectedCount > 0) "🟢 $connectedCount Peers Connected (Off-Grid)"
                                    else if (isMeshActive) "🟡 Radio Beacon Active (Zero Internet)"
                                    else "⚪ Mesh Inactive",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = if (connectedCount > 0) RelaySuccess else RelayTextSecondary
                                )
                            }
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(
                        containerColor = RelayCardBg,
                        titleContentColor = RelayTextPrimary
                    )
                )
            }
        },
        bottomBar = {
            // Show bottom navigation on primary 4 screens
            if (currentScreen in listOf(Screen.HOME, Screen.REQUESTS, Screen.NETWORK, Screen.PROFILE)) {
                NavigationBar(
                    containerColor = RelayCardBg,
                    contentColor = RelayTextPrimary
                ) {
                    NavigationBarItem(
                        selected = currentScreen == Screen.HOME,
                        onClick = { currentScreen = Screen.HOME },
                        label = { Text("Home", fontWeight = if (currentScreen == Screen.HOME) FontWeight.Bold else FontWeight.Normal) },
                        icon = { Text("🏛️", fontSize = 20.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = RelayPrimaryAccent,
                            selectedTextColor = RelayPrimaryAccent,
                            indicatorColor = RelayCardElevated,
                            unselectedTextColor = RelayTextMuted
                        )
                    )
                    NavigationBarItem(
                        selected = currentScreen == Screen.REQUESTS,
                        onClick = { currentScreen = Screen.REQUESTS },
                        label = { Text("Requests", fontWeight = if (currentScreen == Screen.REQUESTS) FontWeight.Bold else FontWeight.Normal) },
                        icon = {
                            val pendingCount = requests.count { it.status == RequestStatus.PENDING }
                            if (pendingCount > 0) {
                                BadgedBox(badge = {
                                    Badge(containerColor = RelayCritical, contentColor = Color.White) {
                                        Text("$pendingCount")
                                    }
                                }) {
                                    Text("🚨", fontSize = 20.sp)
                                }
                            } else {
                                Text("🚨", fontSize = 20.sp)
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = RelayPrimaryAccent,
                            selectedTextColor = RelayPrimaryAccent,
                            indicatorColor = RelayCardElevated,
                            unselectedTextColor = RelayTextMuted
                        )
                    )
                    NavigationBarItem(
                        selected = currentScreen == Screen.NETWORK,
                        onClick = { currentScreen = Screen.NETWORK },
                        label = { Text("Network", fontWeight = if (currentScreen == Screen.NETWORK) FontWeight.Bold else FontWeight.Normal) },
                        icon = {
                            val connectedCount by activity.connectedEndpointsCountState
                            if (connectedCount > 0) {
                                BadgedBox(badge = {
                                    Badge(containerColor = RelaySuccess, contentColor = Color.White) {
                                        Text("$connectedCount")
                                    }
                                }) {
                                    Text("📡", fontSize = 20.sp)
                                }
                            } else {
                                Text("📡", fontSize = 20.sp)
                            }
                        },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = RelayPrimaryAccent,
                            selectedTextColor = RelayPrimaryAccent,
                            indicatorColor = RelayCardElevated,
                            unselectedTextColor = RelayTextMuted
                        )
                    )
                    NavigationBarItem(
                        selected = currentScreen == Screen.PROFILE,
                        onClick = { currentScreen = Screen.PROFILE },
                        label = { Text("Profile", fontWeight = if (currentScreen == Screen.PROFILE) FontWeight.Bold else FontWeight.Normal) },
                        icon = { Text("👤", fontSize = 20.sp) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = RelayPrimaryAccent,
                            selectedTextColor = RelayPrimaryAccent,
                            indicatorColor = RelayCardElevated,
                            unselectedTextColor = RelayTextMuted
                        )
                    )
                }
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            when (currentScreen) {
                Screen.HOME -> HomeScreen(
                    activity = activity,
                    requests = requests,
                    onCreateRequestClick = { navigateTo(Screen.CREATE_REQUEST) },
                    onRequestClick = {
                        selectedRequest = it
                        navigateTo(Screen.REQUEST_DETAILS)
                    },
                    onViewAllRequestsClick = { currentScreen = Screen.REQUESTS },
                    onManageNetworkClick = { currentScreen = Screen.NETWORK }
                )
                Screen.CREATE_REQUEST -> CreateRequestScreen(
                    onBack = { currentScreen = previousScreen },
                    onRequestCreated = { newReq ->
                        LocalOriginRegistry.recordLocalCreation(context, newReq.id)
                        val stampedReq = if (newReq.nodeHistory.isEmpty()) {
                            newReq.copy(
                                nodeHistory = listOf(activity.localNodeId),
                                originatorNodeId = activity.localNodeId
                            )
                        } else {
                            newReq.copy(originatorNodeId = activity.localNodeId)
                        }
                        val signedReq = EmergencyPacketSigner.signRequest(context, stampedReq)
                        val isConnected = activity.connectedEndpointsMap.isNotEmpty()
                        val readyReq = if (isConnected) {
                            signedReq.copy(
                                syncStatus = SyncStatus.SYNCED,
                                lastTransferStatus = "Relayed to ${activity.connectedEndpointsMap.size} mesh peer(s) (Hop 1)"
                            )
                        } else {
                            signedReq.copy(
                                syncStatus = SyncStatus.PENDING_SYNC,
                                lastTransferStatus = "Stored locally (Pending Sync • Searching for mesh peers)"
                            )
                        }
                        val updated = requests + readyReq
                        requests = updated
                        saveRequests(context, updated)
                        if (isConnected) {
                            activity.sendRequestToConnectedDevices(signedReq)
                        }
                        currentScreen = Screen.REQUESTS
                    }
                )
                Screen.REQUESTS -> RequestsScreen(
                    requests = requests,
                    onCreateClick = { navigateTo(Screen.CREATE_REQUEST) },
                    onRequestClick = {
                        selectedRequest = it
                        navigateTo(Screen.REQUEST_DETAILS)
                    }
                )
                Screen.NETWORK -> NearbyNetworkScreen(
                    activity = activity
                )
                Screen.REQUEST_DETAILS -> {
                    if (selectedRequest != null) {
                        RequestDetailsScreen(
                            request = selectedRequest!!,
                            onBack = { currentScreen = previousScreen },
                            onStatusChange = { newStatus ->
                                val req = selectedRequest ?: return@RequestDetailsScreen
                                val localPubKey = RelayKeyStoreManager.getInstance(context).getPublicKeyHex()
                                val isAuthor = req.senderPublicKey?.equals(localPubKey, ignoreCase = true) == true
                                val isResponder = StatusAuthorizationPolicy.isRegisteredResponder(localPubKey)

                                if (!isAuthor && !isResponder) {
                                    android.widget.Toast.makeText(context, "Unauthorized: Only original author or designated responder can change status", android.widget.Toast.LENGTH_LONG).show()
                                    return@RequestDetailsScreen
                                }

                                if (!StatusAuthorizationPolicy.isValidTransition(req.status, newStatus)) {
                                    android.widget.Toast.makeText(context, "Invalid status transition from '${req.status}' to '$newStatus'", android.widget.Toast.LENGTH_SHORT).show()
                                    return@RequestDetailsScreen
                                }

                                try {
                                    val signedUpdatedReq = EmergencyPacketSigner.signStatusUpdate(
                                        context = context,
                                        request = req,
                                        newStatus = newStatus,
                                        updaterRole = if (isAuthor) "AUTHOR" else "RESPONDER"
                                    ).copy(
                                        syncStatus = if (activity.connectedEndpointsMap.isNotEmpty()) SyncStatus.SYNCED else SyncStatus.PENDING_SYNC
                                    )
                                    val currentSaved = loadRequests(context)
                                    val updatedList = currentSaved.map {
                                        if (it.id == signedUpdatedReq.id) signedUpdatedReq else it
                                    }
                                    requests = updatedList
                                    saveRequests(context, updatedList)
                                    selectedRequest = signedUpdatedReq
                                    activity.sendRequestToConnectedDevices(signedUpdatedReq)
                                } catch (e: Exception) {
                                    Log.e("MainActivity", "Failed to sign status update", e)
                                    android.widget.Toast.makeText(context, "Status update error: ${e.message}", android.widget.Toast.LENGTH_SHORT).show()
                                }
                            },
                            onDelete = {
                                val currentSaved = loadRequests(context)
                                val updatedList = currentSaved.filterNot { it.id == selectedRequest!!.id }
                                requests = updatedList
                                saveRequests(context, updatedList)
                                selectedRequest = null
                                currentScreen = Screen.REQUESTS
                            }
                        )
                    } else {
                        currentScreen = Screen.REQUESTS
                    }
                }
                Screen.PROFILE -> ProfileScreen(
                    context = context,
                    requestsCount = requests.size,
                    sosCount = sosMessages.size,
                    currentThemeMode = currentThemeMode,
                    onThemeSelected = onThemeSelected,
                    onReloadDemoData = {
                        requests = loadRequests(context)
                        sosMessages = loadSosMessages(context)
                    },
                    onClearData = {
                        clearAllStoredData(context)
                        requests = emptyList()
                        sosMessages = emptyList()
                    }
                )
            }
        }
    }
}

// ----------------------------------------------------
// 1. HOME DASHBOARD SCREEN
// ----------------------------------------------------

@Composable
fun HomeScreen(
    activity: MainActivity,
    requests: List<EmergencyRequest>,
    onCreateRequestClick: () -> Unit,
    onRequestClick: (EmergencyRequest) -> Unit,
    onViewAllRequestsClick: () -> Unit,
    onManageNetworkClick: () -> Unit
) {
    val isMeshActive by activity.isNearbyActiveState
    val connectedCount by activity.connectedEndpointsCountState

    val pendingCount = requests.count { it.status == RequestStatus.PENDING }
    val inProgressCount = requests.count { it.status == RequestStatus.IN_PROGRESS }
    val resolvedCount = requests.count { it.status == RequestStatus.RESOLVED }
    val criticalCount = requests.count { it.priority == "Critical" && it.status != RequestStatus.RESOLVED }

    val recentRequests = remember(requests) { requests.takeLast(3).reversed() }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(10.dp))

            // CRITICAL ACTIVE BANNER
            if (criticalCount > 0) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCritical.copy(alpha = 0.2f)),
                    shape = RoundedCornerShape(14.dp),
                    border = androidx.compose.foundation.BorderStroke(1.5.dp, RelayCritical),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier.padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Surface(
                            shape = CircleShape,
                            color = RelayCritical,
                            modifier = Modifier.size(40.dp)
                        ) {
                            Box(contentAlignment = Alignment.Center) {
                                Text("⚠️", fontSize = 20.sp)
                            }
                        }
                        Spacer(modifier = Modifier.width(12.dp))
                        Column {
                            Text(
                                text = "$criticalCount Critical Emergencies Active",
                                fontWeight = FontWeight.Bold,
                                color = RelayTextPrimary,
                                style = MaterialTheme.typography.titleMedium
                            )
                            Text(
                                text = "Immediate responder action required. Priority triage active.",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextSecondary
                            )
                        }
                    }
                }
            }
        }

        // 1. NETWORK STATUS CARD
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Image(
                                painter = painterResource(id = R.drawable.ic_relay_logo),
                                contentDescription = "The Connected Shield Logo",
                                modifier = Modifier.size(24.dp)
                            )
                            Text(
                                text = "OFFLINE MESH STATUS",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = RelayPrimaryAccent,
                                letterSpacing = 1.sp
                            )
                        }

                        Surface(
                            color = if (isMeshActive) RelaySuccess.copy(alpha = 0.2f) else RelayCardElevated,
                            shape = RoundedCornerShape(6.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (isMeshActive) RelaySuccess else Color.Gray)
                        ) {
                            Text(
                                text = if (connectedCount > 0) "$connectedCount Connected" else if (isMeshActive) "Beacon Active" else "Mesh Idle",
                                color = if (isMeshActive) RelaySuccess else RelayTextSecondary,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = if (connectedCount > 0) "Connected to $connectedCount nearby emergency radios. Packets relaying automatically."
                        else if (isMeshActive) "Actively broadcasting beacon via BLE & Wi-Fi LAN. Range ~100m direct, multi-hop mesh active."
                        else "Mesh stopped. Tap below to activate offline radio discovery.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = RelayTextSecondary
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedButton(
                        onClick = onManageNetworkClick,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = RelayTextPrimary),
                        shape = RoundedCornerShape(8.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Open Network Hub ➔", fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        // 2. REQUEST STATISTICS GRID
        item {
            Text(
                text = "Emergency Coordination Metrics",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = RelayTextPrimary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                MetricItemCard("Pending", "$pendingCount", RelayCritical, Modifier.weight(1f))
                MetricItemCard("In Progress", "$inProgressCount", RelayEmergencyAction, Modifier.weight(1f))
                MetricItemCard("Resolved", "$resolvedCount", RelaySuccess, Modifier.weight(1f))
                MetricItemCard("Total", "${requests.size}", RelayPrimaryAccent, Modifier.weight(1f))
            }
        }

        // 3. PROMINENT CREATE EMERGENCY REQUEST BUTTON
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayEmergencyAction),
                shape = RoundedCornerShape(16.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onCreateRequestClick() }
            ) {
                Row(
                    modifier = Modifier.padding(18.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("🚨", fontSize = 22.sp)
                            Text(
                                text = "CREATE EMERGENCY REQUEST",
                                fontWeight = FontWeight.Black,
                                fontSize = 16.sp,
                                color = Color.White,
                                letterSpacing = 0.5.sp
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Broadcast rescue, medical, food, or shelter need offline",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFFFFEDD5)
                        )
                    }
                    Surface(
                        shape = CircleShape,
                        color = Color.White.copy(alpha = 0.25f),
                        modifier = Modifier.size(36.dp)
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Text("➔", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                        }
                    }
                }
            }
        }

        // 4. RECENT REQUESTS
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Recent Emergency Requests",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayTextPrimary
                )
                if (requests.isNotEmpty()) {
                    TextButton(onClick = onViewAllRequestsClick) {
                        Text("View All (${requests.size}) ➔", color = RelayPrimaryAccent, fontWeight = FontWeight.SemiBold)
                    }
                }
            }
        }

        if (recentRequests.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(14.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("📋", fontSize = 36.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "No Requests Recorded Yet",
                            fontWeight = FontWeight.Bold,
                            color = RelayTextPrimary,
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Text(
                            text = "Tap 'Create Emergency Request' above or wait for incoming mesh relays.",
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayTextMuted
                        )
                    }
                }
            }
        } else {
            items(recentRequests, key = { it.id }) { req ->
                OrganizedRequestCard(
                    request = req,
                    onClick = { onRequestClick(req) }
                )
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

// ----------------------------------------------------
// 2. CREATE REQUEST SCREEN
// ----------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CreateRequestScreen(
    onBack: () -> Unit,
    onRequestCreated: (EmergencyRequest) -> Unit
) {
    val categories = listOf(
        "Rescue" to "🚤",
        "Medical" to "💊",
        "Food & Water" to "🍞",
        "Shelter" to "🏠",
        "Hazard" to "⚡"
    )

    val priorities = listOf(
        "Critical" to RelayCritical,
        "High" to RelayEmergencyAction,
        "Medium" to RelayWarning,
        "Low" to RelaySuccess
    )

    var selectedCategory by remember { mutableStateOf(categories[0].first) }
    var description by remember { mutableStateOf("") }
    var peopleCount by remember { mutableStateOf(1) }
    var selectedPriority by remember { mutableStateOf("Critical") }
    var showError by remember { mutableStateOf(false) }
    var isEncryptionEnabled by remember { mutableStateOf(false) }
    var confidentialMedicalNote by remember { mutableStateOf("") }
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(RelayBg)
    ) {
        // TOP APP BAR WITH BACK BUTTON
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(RelayCardBg)
                .padding(horizontal = 12.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack) {
                Text("←", fontSize = 26.sp, color = RelayTextPrimary, fontWeight = FontWeight.Bold)
            }
            Spacer(modifier = Modifier.width(6.dp))
            Column {
                Text(
                    text = "Create Emergency Request",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayTextPrimary
                )
                Text(
                    text = "Broadcasts to all nearby radios without cellular signal",
                    style = MaterialTheme.typography.bodySmall,
                    color = RelayPrimaryAccent
                )
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(10.dp))

                // CATEGORY SELECTION
                Text(
                    text = "1. EMERGENCY CATEGORY",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayPrimaryAccent,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(categories) { (cat, emoji) ->
                        val isSelected = selectedCategory == cat
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (isSelected) RelayPrimaryAccent else RelayCardBg,
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) RelayPrimaryAccent else RelayBorder),
                            modifier = Modifier.clickable { selectedCategory = cat }
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(emoji, fontSize = 18.sp)
                                Text(
                                    text = cat,
                                    fontWeight = FontWeight.Bold,
                                    color = if (isSelected) RelayBg else RelayTextPrimary
                                )
                            }
                        }
                    }
                }
            }

            // DESCRIPTION INPUT
            item {
                Text(
                    text = "2. EMERGENCY LOCATION & DETAILS",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayPrimaryAccent,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = description,
                    onValueChange = {
                        description = it
                        if (it.isNotBlank()) showError = false
                    },
                    placeholder = {
                        Text(
                            "e.g. 2nd floor roof flooded, 3 people trapped near Sector 4 Water Tank, water at chest level...",
                            color = RelayTextMuted
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 4,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = RelayPrimaryAccent,
                        unfocusedBorderColor = if (showError) RelayCritical else RelayBorder,
                        focusedContainerColor = RelayCardBg,
                        unfocusedContainerColor = RelayCardBg,
                        focusedTextColor = RelayTextPrimary,
                        unfocusedTextColor = RelayTextPrimary
                    ),
                    shape = RoundedCornerShape(12.dp)
                )

                if (showError) {
                    Text(
                        text = "Please enter description or location details",
                        color = RelayCritical,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(start = 6.dp, top = 4.dp)
                    )
                }
            }

            // 2B. END-TO-END ENCRYPTED TRIAGE / MEDICAL DETAILS
            item {
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = if (isEncryptionEnabled) RelaySuccess.copy(alpha = 0.08f) else RelayCardBg
                    ),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (isEncryptionEnabled) RelaySuccess else RelayBorder
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    Text("🔒", fontSize = 16.sp)
                                    Text(
                                        text = "Encrypt Confidential Medical Notes",
                                        fontWeight = FontWeight.Bold,
                                        color = if (isEncryptionEnabled) RelaySuccess else RelayTextPrimary
                                    )
                                }
                                Text(
                                    text = "Protects victim health details with X25519 + AES-256-GCM. Intermediate mesh nodes cannot view.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = RelayTextMuted
                                )
                            }
                            Switch(
                                checked = isEncryptionEnabled,
                                onCheckedChange = { isEncryptionEnabled = it },
                                colors = SwitchDefaults.colors(
                                    checkedThumbColor = Color.White,
                                    checkedTrackColor = RelaySuccess,
                                    uncheckedThumbColor = RelayTextMuted,
                                    uncheckedTrackColor = RelayCardElevated
                                )
                            )
                        }

                        if (isEncryptionEnabled) {
                            Spacer(modifier = Modifier.height(10.dp))
                            OutlinedTextField(
                                value = confidentialMedicalNote,
                                onValueChange = { confidentialMedicalNote = it },
                                placeholder = {
                                    Text(
                                        "Confidential triage: Victim names, insulin shock, severe hemorrhage, trauma, exact medication needs...",
                                        color = RelayTextMuted
                                    )
                                },
                                modifier = Modifier.fillMaxWidth(),
                                minLines = 3,
                                colors = OutlinedTextFieldDefaults.colors(
                                    focusedBorderColor = RelaySuccess,
                                    unfocusedBorderColor = RelayBorder,
                                    focusedContainerColor = RelayCardElevated,
                                    unfocusedContainerColor = RelayCardElevated,
                                    focusedTextColor = RelayTextPrimary,
                                    unfocusedTextColor = RelayTextPrimary
                                ),
                                shape = RoundedCornerShape(10.dp)
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "✓ E2EE Active: Routed across all nodes, viewable only by certified responders and you.",
                                style = MaterialTheme.typography.labelSmall,
                                color = RelaySuccess
                            )
                        }
                    }
                }
            }

            // PEOPLE AFFECTED STEPPER
            item {
                Text(
                    text = "3. PEOPLE AFFECTED / IN NEED",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayPrimaryAccent,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text("Total People", fontWeight = FontWeight.Bold, color = RelayTextPrimary)
                            Text("Include elderly & children", style = MaterialTheme.typography.bodySmall, color = RelayTextMuted)
                        }

                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(14.dp)
                        ) {
                            FilledIconButton(
                                onClick = { if (peopleCount > 1) peopleCount-- },
                                colors = IconButtonDefaults.filledIconButtonColors(containerColor = RelayCardElevated),
                                modifier = Modifier.size(42.dp)
                            ) {
                                Text("−", fontSize = 24.sp, color = RelayTextPrimary, fontWeight = FontWeight.Black)
                            }

                            Text(
                                text = "$peopleCount",
                                fontSize = 22.sp,
                                fontWeight = FontWeight.Black,
                                color = RelayPrimaryAccent
                            )

                            FilledIconButton(
                                onClick = { peopleCount++ },
                                colors = IconButtonDefaults.filledIconButtonColors(containerColor = RelayCardElevated),
                                modifier = Modifier.size(42.dp)
                            ) {
                                Text("+", fontSize = 24.sp, color = RelayTextPrimary, fontWeight = FontWeight.Black)
                            }
                        }
                    }
                }
            }

            // PRIORITY LEVEL SELECTOR
            item {
                Text(
                    text = "4. TRIAGE PRIORITY LEVEL",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayPrimaryAccent,
                    letterSpacing = 1.sp
                )

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    priorities.forEach { (p, color) ->
                        val isSelected = selectedPriority == p
                        Surface(
                            shape = RoundedCornerShape(10.dp),
                            color = if (isSelected) color else RelayCardBg,
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) color else RelayBorder),
                            modifier = Modifier
                                .weight(1f)
                                .clickable { selectedPriority = p }
                        ) {
                            Column(
                                modifier = Modifier.padding(vertical = 12.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = p,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 13.sp,
                                    color = if (isSelected) Color.White else color
                                )
                            }
                        }
                    }
                }
            }

            // SUBMIT BUTTON
            item {
                Spacer(modifier = Modifier.height(8.dp))

                Button(
                    onClick = {
                        if (description.isBlank() && confidentialMedicalNote.isBlank()) {
                            showError = true
                        } else {
                            var finalDescription = description.trim()
                            if (isEncryptionEnabled && confidentialMedicalNote.isNotBlank()) {
                                try {
                                    val keyManager = RelayKeyStoreManager.getInstance(context)
                                    val myNodeId = NodeIdentityManager.getLocalNodeId(context)
                                    val myX25519Pub = keyManager.getX25519PublicKeyHex()

                                    val peerKeys = RelayE2EEncryption.getAllPeerEncryptionKeys()
                                    val responderKeys = StatusAuthorizationPolicy.getRegisteredResponderKeys()
                                    val recipientPubKey = when {
                                        peerKeys.isNotEmpty() -> peerKeys.first().x25519EncryptionKeyHex
                                        responderKeys.isNotEmpty() && responderKeys.first().length == 64 -> responderKeys.first()
                                        else -> myX25519Pub
                                    }
                                    val recipientNodeId = peerKeys.firstOrNull()?.nodeId ?: "CERTIFIED_RESPONDER"

                                    val reqId = UUID.randomUUID().toString()
                                    val encryptedEnvelope = RelayE2EEncryption.encryptTriageNote(
                                        confidentialNote = confidentialMedicalNote.trim(),
                                        recipientX25519PubKeyHex = if (recipientPubKey.length == 64) recipientPubKey else myX25519Pub,
                                        packetId = reqId,
                                        senderNodeId = myNodeId,
                                        recipientNodeId = recipientNodeId,
                                        authorX25519PubKeyHex = myX25519Pub
                                    )
                                    finalDescription = RelayE2EEncryption.formatFullDescription(
                                        publicDetails = description.trim(),
                                        serializedEncryptedNote = encryptedEnvelope
                                    )
                                } catch (e: Exception) {
                                    Log.e("CreateRequestScreen", "Error encrypting note", e)
                                }
                            }

                            val newRequest = EmergencyRequest(
                                type = selectedCategory,
                                description = finalDescription,
                                people = peopleCount,
                                priority = selectedPriority,
                                latitude = GeoTacticalUtils.DEFAULT_BASE_LATITUDE + (Math.random() - 0.5) * 0.006,
                                longitude = GeoTacticalUtils.DEFAULT_BASE_LONGITUDE + (Math.random() - 0.5) * 0.006,
                                locationAccuracyMeters = 4.5f
                            )
                            onRequestCreated(newRequest)
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = RelayEmergencyAction),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(56.dp)
                ) {
                    Text(
                        text = "🚨 BROADCAST EMERGENCY REQUEST",
                        fontWeight = FontWeight.Black,
                        fontSize = 15.sp,
                        color = Color.White
                    )
                }

                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

// ----------------------------------------------------
// 3. REQUESTS LIST SCREEN
// ----------------------------------------------------

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RequestsScreen(
    requests: List<EmergencyRequest>,
    onCreateClick: () -> Unit,
    onRequestClick: (EmergencyRequest) -> Unit
) {
    var selectedFilter by remember { mutableStateOf("All") }

    val filteredRequests = remember(requests, selectedFilter) {
        when (selectedFilter) {
            "All" -> requests
            "Critical" -> requests.filter { it.priority == "Critical" }
            "Pending" -> requests.filter { it.status == RequestStatus.PENDING }
            "In Progress" -> requests.filter { it.status == RequestStatus.IN_PROGRESS }
            "Resolved" -> requests.filter { it.status == RequestStatus.RESOLVED }
            else -> requests
        }
    }

    Scaffold(
        containerColor = RelayBg,
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onCreateClick,
                containerColor = RelayEmergencyAction,
                contentColor = Color.White,
                shape = RoundedCornerShape(16.dp)
            ) {
                Text("🚨", fontSize = 18.sp)
                Spacer(modifier = Modifier.width(8.dp))
                Text("New Request", fontWeight = FontWeight.Bold)
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "Emergency Requests",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        color = RelayTextPrimary
                    )
                    Surface(
                        color = RelayCardElevated,
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
                    ) {
                        Text(
                            text = "${filteredRequests.size} shown",
                            color = RelayPrimaryAccent,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            // FILTER ROW
            item {
                val filters = listOf("All", "Pending", "Critical", "In Progress", "Resolved")
                LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(filters) { f ->
                        val isSelected = selectedFilter == f
                        FilterChip(
                            selected = isSelected,
                            onClick = { selectedFilter = f },
                            label = { Text(f, fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal) },
                            colors = FilterChipDefaults.filterChipColors(
                                selectedContainerColor = RelayPrimaryAccent,
                                selectedLabelColor = RelayBg,
                                containerColor = RelayCardBg,
                                labelColor = RelayTextSecondary
                            ),
                            border = FilterChipDefaults.filterChipBorder(
                                enabled = true,
                                selected = isSelected,
                                borderColor = if (isSelected) RelayPrimaryAccent else RelayBorder
                            )
                        )
                    }
                }
            }

            if (filteredRequests.isEmpty()) {
                item {
                    Card(
                        colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                        shape = RoundedCornerShape(14.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(30.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text("🔍", fontSize = 40.sp)
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "No Requests in '$selectedFilter'",
                                fontWeight = FontWeight.Bold,
                                color = RelayTextPrimary,
                                style = MaterialTheme.typography.titleMedium
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "No matching emergency items found locally or via mesh relay.",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextMuted
                            )
                            Spacer(modifier = Modifier.height(14.dp))
                            Button(
                                onClick = onCreateClick,
                                colors = ButtonDefaults.buttonColors(containerColor = RelayPrimaryAccent, contentColor = RelayBg)
                            ) {
                                Text("+ Create Request", fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            } else {
                items(filteredRequests.reversed(), key = { it.id }) { req ->
                    OrganizedRequestCard(
                        request = req,
                        onClick = { onRequestClick(req) }
                    )
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }
}

@Composable
fun OrganizedRequestCard(
    request: EmergencyRequest,
    onClick: () -> Unit
) {
    val categoryIcon = when (request.type) {
        "Rescue" -> "🚤"
        "Medical" -> "💊"
        "Food & Water" -> "🍞"
        "Shelter" -> "🏠"
        else -> "🚨"
    }

    val priorityColor = when (request.priority) {
        "Critical" -> RelayCritical
        "High" -> RelayEmergencyAction
        "Medium" -> RelayWarning
        else -> RelaySuccess
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = RelayCardBg),
        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(categoryIcon, fontSize = 20.sp)
                    Text(
                        text = request.type,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = RelayTextPrimary
                    )
                    Surface(
                        color = RelayCardElevated,
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            text = "👥 ${request.people}",
                            color = RelayTextSecondary,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                        )
                    }
                }

                Surface(
                    color = priorityColor.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(6.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, priorityColor)
                ) {
                    Text(
                        text = request.priority.uppercase(),
                        color = priorityColor,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Black,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            val context = LocalContext.current
            val triageResult = remember(request.description) {
                try {
                    val privKey = RelayKeyStoreManager.getInstance(context).getX25519PrivateKey()
                    val myNodeId = NodeIdentityManager.getLocalNodeId(context)
                    RelayE2EEncryption.parseAndDecryptDescription(request.description, privKey, myNodeId)
                } catch (_: Exception) {
                    RelayE2EEncryption.parseAndDecryptDescription(request.description, null, "")
                }
            }

            if (triageResult.publicDetails.isNotBlank()) {
                Text(
                    text = triageResult.publicDetails,
                    style = MaterialTheme.typography.bodyMedium,
                    color = RelayTextSecondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }

            if (triageResult.isEncrypted) {
                Spacer(modifier = Modifier.height(4.dp))
                if (triageResult.isDecrypted && triageResult.confidentialNote != null) {
                    Surface(
                        color = RelaySuccess.copy(alpha = 0.12f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelaySuccess.copy(alpha = 0.5f))
                    ) {
                        Row(
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(4.dp)
                        ) {
                            Text("🔒 Decrypted Medical Note:", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = RelaySuccess)
                            Text(triageResult.confidentialNote, style = MaterialTheme.typography.bodySmall, color = RelayTextPrimary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                } else {
                    Surface(
                        color = RelayBorder.copy(alpha = 0.2f),
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
                    ) {
                        Text(
                            text = "🔒 Confidential Medical Note (Encrypted for Responder)",
                            style = MaterialTheme.typography.labelSmall,
                            color = RelayTextMuted,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    StatusTag(request.status)
                    if (request.isCryptographicallySigned) {
                        Surface(
                            color = RelayPrimaryAccent.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(4.dp)
                        ) {
                            Text(
                                text = "🛡️ Ed25519",
                                color = RelayPrimaryAccent,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                            )
                        }
                    }

                    if (request.latitude != null && request.longitude != null) {
                        val distMeters = GeoTacticalUtils.calculateDistanceMeters(
                            GeoTacticalUtils.DEFAULT_BASE_LATITUDE,
                            GeoTacticalUtils.DEFAULT_BASE_LONGITUDE,
                            request.latitude,
                            request.longitude
                        )
                        val formattedDist = GeoTacticalUtils.formatDistance(distMeters)
                        Surface(
                            color = RelayCardElevated,
                            shape = RoundedCornerShape(4.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
                        ) {
                            Text(
                                text = "📍 $formattedDist",
                                color = RelayTextSecondary,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                            )
                        }
                    }
                }

                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    SyncTag(
                        syncStatus = request.syncStatus,
                        hopCount = request.hopCount,
                        isExpired = request.isExpired,
                        timeRemainingHours = request.timeRemainingHours
                    )
                    Text("➔", color = RelayTextMuted, fontSize = 14.sp)
                }
            }

            if (request.hopCount > 0 && request.nodeHistory.isNotEmpty()) {
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Route: " + request.nodeHistory.takeLast(3).joinToString(" ➔ "),
                    style = MaterialTheme.typography.labelSmall,
                    color = RelayTextMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

// ----------------------------------------------------
// 4. NEARBY NETWORK SCREEN
// ----------------------------------------------------

@Composable
fun NearbyNetworkScreen(
    activity: MainActivity
) {
    val isNearbyActive by activity.isNearbyActiveState
    val connectedEndpoints by activity.connectedEndpointsListState
    val lastSyncStatus by activity.lastSyncStatusState
    val pendingCount by remember { activity.pendingTransfersCountState }
    val receivedCount by remember { activity.totalTransfersReceivedState }
    val forwardedCount by remember { activity.totalTransfersForwardedState }
    val acksCount by remember { activity.totalAcksConfirmedState }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(10.dp))

            // MESH ENGINE OVERVIEW CARD
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "P2P MESH ENGINE",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = RelayPrimaryAccent,
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = "Local Radio Cluster",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Black,
                                color = RelayTextPrimary
                            )
                        }

                        Surface(
                            color = if (isNearbyActive) RelaySuccess.copy(alpha = 0.2f) else Color(0xFF334155),
                            shape = RoundedCornerShape(6.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (isNearbyActive) RelaySuccess else Color.Gray)
                        ) {
                            Text(
                                text = if (isNearbyActive) "ONLINE" else "OFFLINE",
                                color = if (isNearbyActive) RelaySuccess else RelayTextSecondary,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Black,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = "Radio ID: ${activity.localNodeId}",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        color = RelayTextPrimary
                    )

                    Spacer(modifier = Modifier.height(4.dp))

                    Text(
                        text = "Activity: $lastSyncStatus",
                        style = MaterialTheme.typography.bodySmall,
                        color = RelayTextMuted
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Button(
                            onClick = {
                                if (isNearbyActive) activity.stopNearby() else activity.startNearby()
                            },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (isNearbyActive) RelayCritical else RelayPrimaryAccent,
                                contentColor = if (isNearbyActive) Color.White else RelayBg
                            ),
                            shape = RoundedCornerShape(8.dp),
                            modifier = Modifier.weight(1f)
                        ) {
                            Text(
                                text = if (isNearbyActive) "Stop Mesh Radio" else "Start Mesh Radio",
                                fontWeight = FontWeight.Bold
                            )
                        }

                        OutlinedButton(
                            onClick = { activity.syncAllNow() },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = RelayTextPrimary),
                            shape = RoundedCornerShape(8.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                            modifier = Modifier.weight(1f),
                            enabled = isNearbyActive
                        ) {
                            Text("Broadcast Sync", fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }
        }

        // STORE-AND-FORWARD TRANSFER METRICS DASHBOARD
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "AUTOMATIC STORE-AND-FORWARD METRICS",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = RelayPrimaryAccent,
                        letterSpacing = 1.sp
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        TransferMetricTile(
                            modifier = Modifier.weight(1f),
                            icon = "⏳",
                            label = "In Queue",
                            value = pendingCount.toString(),
                            accentColor = RelayWarning
                        )
                        TransferMetricTile(
                            modifier = Modifier.weight(1f),
                            icon = "📥",
                            label = "Received",
                            value = receivedCount.toString(),
                            accentColor = RelayPrimaryAccent
                        )
                        TransferMetricTile(
                            modifier = Modifier.weight(1f),
                            icon = "📤",
                            label = "Forwarded",
                            value = forwardedCount.toString(),
                            accentColor = RelayEmergencyAction
                        )
                        TransferMetricTile(
                            modifier = Modifier.weight(1f),
                            icon = "✅",
                            label = "ACKs Done",
                            value = acksCount.toString(),
                            accentColor = RelaySuccess
                        )
                    }
                }
            }
        }

        // LIVE STORE-AND-FORWARD TRANSFER ACTIVITY FEED
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Store-and-Forward Event Log",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayTextPrimary
                )
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (activity.transferEventsLog.isNotEmpty()) {
                        TextButton(
                            onClick = {
                                activity.transferEventsLog.clear()
                                activity.totalTransfersReceivedState.value = 0
                                activity.totalTransfersForwardedState.value = 0
                                activity.totalAcksConfirmedState.value = 0
                                android.widget.Toast.makeText(
                                    activity,
                                    "Event log cleared",
                                    android.widget.Toast.LENGTH_SHORT
                                ).show()
                            },
                            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = "Clear",
                                color = RelayCritical,
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    Surface(
                        color = RelayCardElevated,
                        shape = RoundedCornerShape(6.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
                    ) {
                        Text(
                            text = "${activity.transferEventsLog.size} events",
                            color = RelayPrimaryAccent,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }
        }

        if (activity.transferEventsLog.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("🔄", fontSize = 28.sp)
                        Spacer(modifier = Modifier.height(6.dp))
                        Text(
                            text = "No Transfer Events Yet",
                            fontWeight = FontWeight.Bold,
                            color = RelayTextPrimary,
                            style = MaterialTheme.typography.bodyMedium
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Automatic forwards, received requests, retries and delivery ACKs stream here in real-time.",
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayTextMuted
                        )
                    }
                }
            }
        } else {
            items(activity.transferEventsLog.take(20)) { entry ->
                TransferEventRow(entry)
            }
        }

        // CONNECTED PEERS LIST
        item {
            Text(
                text = "Nearby Devices in Direct Radio Range (${connectedEndpoints.size})",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = RelayTextPrimary
            )
        }

        if (connectedEndpoints.isEmpty()) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(14.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(26.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("📡", fontSize = 38.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = if (isNearbyActive) "Scanning for Nearby Phones..." else "Mesh Radio is Idle",
                            fontWeight = FontWeight.Bold,
                            color = RelayTextPrimary,
                            style = MaterialTheme.typography.bodyLarge
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Any Android device within 100 meters running RELAY connects automatically via Bluetooth & Wi-Fi Direct.",
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayTextMuted
                        )
                    }
                }
            }
        } else {
            items(connectedEndpoints) { (endpointId, name) ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(12.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelaySuccess.copy(alpha = 0.5f)),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Surface(
                                shape = CircleShape,
                                color = RelaySuccess,
                                modifier = Modifier.size(12.dp)
                            ) {}
                            Column {
                                Text(name, fontWeight = FontWeight.Bold, color = RelayTextPrimary)
                                Text("Endpoint ID: $endpointId", style = MaterialTheme.typography.labelSmall, color = RelayTextMuted)
                            }
                        }

                        Button(
                            onClick = { activity.exchangeStoredRequestsWithPeer(endpointId, name) },
                            colors = ButtonDefaults.buttonColors(containerColor = RelayPrimaryAccent, contentColor = RelayBg),
                            shape = RoundedCornerShape(6.dp),
                            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 6.dp)
                        ) {
                            Text("Sync Requests", fontWeight = FontWeight.Bold, fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        // STORE & FORWARD MESH EXPLANATION CARD
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardElevated),
                shape = RoundedCornerShape(14.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("⚙️", fontSize = 18.sp)
                        Text(
                            text = "Multi-Hop Store-and-Forward Protocol",
                            fontWeight = FontWeight.Bold,
                            color = RelayTextPrimary,
                            style = MaterialTheme.typography.titleSmall
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "• Radio Transports: Bluetooth Low Energy (BLE), Bluetooth RFCOMM, Wi-Fi LAN/Direct.\n• Multi-Hop Relaying: Automatically forwards packets up to $MAX_STORE_FORWARD_HOPS hops across phones.\n• Provenance History: Tracks device paths to eliminate forwarding loops.\n• Expiry / TTL: Automatically purges requests after $DEFAULT_REQUEST_TTL_HOURS hours.\n• Conflict Resolution: Last-Write-Wins (LWW) based on timestamps.\n• Delivery Guarantees: Automatic retries (up to $MAX_TRANSFER_RETRIES) and ACK confirmations.",
                        style = MaterialTheme.typography.bodySmall,
                        color = RelayTextSecondary
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

@Composable
fun TransferMetricTile(
    modifier: Modifier = Modifier,
    icon: String,
    label: String,
    value: String,
    accentColor: Color
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(10.dp),
        color = RelayCardElevated,
        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 10.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(icon, fontSize = 16.sp)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                fontWeight = FontWeight.Black,
                fontSize = 17.sp,
                color = accentColor
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = label,
                fontSize = 10.sp,
                color = RelayTextMuted,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1
            )
        }
    }
}

@Composable
fun TransferEventRow(entry: TransferLogEntry) {
    val badgeColor = when (entry.type) {
        TransferType.RECEIVED -> RelayPrimaryAccent
        TransferType.FORWARDED -> RelayEmergencyAction
        TransferType.ACK_SENT -> RelayTextSecondary
        TransferType.ACK_RECEIVED -> RelaySuccess
        TransferType.RETRY -> RelayWarning
        TransferType.EXPIRED -> RelayCritical
        TransferType.LOOP_PREVENTED -> Color(0xFF8B5CF6)
        TransferType.SECURITY_REJECTED -> RelayCritical
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = RelayCardBg),
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(10.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.weight(1f)
            ) {
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = badgeColor.copy(alpha = 0.15f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, badgeColor)
                ) {
                    Text(
                        text = "${entry.type.icon} ${entry.type.tag}",
                        color = badgeColor,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                    )
                }

                Column {
                    Text(
                        text = entry.summary,
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold,
                        color = RelayTextPrimary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Text(
                        text = "${entry.peerName} • ${entry.formattedTime}${if (entry.hopCount > 0) " • Hop ${entry.hopCount}" else ""}",
                        style = MaterialTheme.typography.labelSmall,
                        color = RelayTextMuted
                    )
                }
            }

            Text(
                text = entry.requestId.take(6).uppercase(),
                style = MaterialTheme.typography.labelSmall,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                color = RelayTextMuted
            )
        }
    }
}

// ----------------------------------------------------
// 5. REQUEST DETAILS SCREEN
// ----------------------------------------------------

@Composable
fun RequestDetailsScreen(
    request: EmergencyRequest,
    onBack: () -> Unit,
    onStatusChange: (String) -> Unit,
    onDelete: () -> Unit
) {
    var showDeleteConfirm by remember { mutableStateOf(false) }

    if (showDeleteConfirm) {
        AlertDialog(
            containerColor = RelayCardBg,
            titleContentColor = RelayTextPrimary,
            textContentColor = RelayTextSecondary,
            onDismissRequest = { showDeleteConfirm = false },
            title = { Text("Delete Emergency Request?") },
            text = { Text("This will permanently remove this record from your device storage.") },
            confirmButton = {
                Button(
                    onClick = {
                        showDeleteConfirm = false
                        onDelete()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = RelayCritical)
                ) {
                    Text("Delete Permanently")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteConfirm = false }) {
                    Text("Cancel", color = RelayTextPrimary)
                }
            }
        )
    }

    val categoryIcon = when (request.type) {
        "Rescue" -> "🚤"
        "Medical" -> "💊"
        "Food & Water" -> "🍞"
        "Shelter" -> "🏠"
        else -> "🚨"
    }

    val priorityColor = when (request.priority) {
        "Critical" -> RelayCritical
        "High" -> RelayEmergencyAction
        "Medium" -> RelayWarning
        else -> RelaySuccess
    }

    val timeFormatted = remember(request.updatedAt) {
        SimpleDateFormat("yyyy-MM-dd • hh:mm a", Locale.getDefault()).format(Date(request.updatedAt))
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(RelayBg)
    ) {
        // TOP APP BAR
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(RelayCardBg)
                .padding(horizontal = 12.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                IconButton(onClick = onBack) {
                    Text("←", fontSize = 26.sp, color = RelayTextPrimary, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    text = "Emergency Request Details",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = RelayTextPrimary
                )
            }

            IconButton(onClick = { showDeleteConfirm = true }) {
                Text("🗑️", fontSize = 20.sp)
            }
        }

        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(10.dp))

                // HEADER OVERVIEW CARD
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                Text(categoryIcon, fontSize = 28.sp)
                                Column {
                                    Text(
                                        text = "${request.type} Request",
                                        style = MaterialTheme.typography.titleLarge,
                                        fontWeight = FontWeight.Black,
                                        color = RelayTextPrimary
                                    )
                                    Text(
                                        text = "People in need: ${request.people}",
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.SemiBold,
                                        color = RelayPrimaryAccent
                                    )
                                }
                            }

                            Surface(
                                color = priorityColor.copy(alpha = 0.2f),
                                shape = RoundedCornerShape(6.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, priorityColor)
                            ) {
                                Text(
                                    text = request.priority.uppercase(),
                                    color = priorityColor,
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Black,
                                    modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Text(
                            text = "LOCATION & EMERGENCY DESCRIPTION",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = RelayTextMuted,
                            letterSpacing = 1.sp
                        )

                        Spacer(modifier = Modifier.height(6.dp))

                        val detailContext = LocalContext.current
                        val detailTriageResult = remember(request.description) {
                            try {
                                val privKey = RelayKeyStoreManager.getInstance(detailContext).getX25519PrivateKey()
                                val myNodeId = NodeIdentityManager.getLocalNodeId(detailContext)
                                RelayE2EEncryption.parseAndDecryptDescription(request.description, privKey, myNodeId)
                            } catch (_: Exception) {
                                RelayE2EEncryption.parseAndDecryptDescription(request.description, null, "")
                            }
                        }

                        if (detailTriageResult.publicDetails.isNotBlank()) {
                            Text(
                                text = detailTriageResult.publicDetails,
                                style = MaterialTheme.typography.bodyLarge,
                                color = RelayTextPrimary
                            )
                        }

                        if (detailTriageResult.isEncrypted) {
                            Spacer(modifier = Modifier.height(10.dp))
                            if (detailTriageResult.isDecrypted && detailTriageResult.confidentialNote != null) {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = RelaySuccess.copy(alpha = 0.08f)),
                                    shape = RoundedCornerShape(10.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, RelaySuccess)
                                ) {
                                    Column(modifier = Modifier.padding(12.dp)) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                                        ) {
                                            Text("🔒", fontSize = 16.sp)
                                            Text(
                                                text = "CONFIDENTIAL MEDICAL / TRIAGE NOTE",
                                                fontWeight = FontWeight.Bold,
                                                color = RelaySuccess,
                                                style = MaterialTheme.typography.labelMedium
                                            )
                                            Spacer(modifier = Modifier.weight(1f))
                                            Text(
                                                text = "AES-256-GCM + X25519",
                                                color = RelaySuccess,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(6.dp))
                                        Text(
                                            text = detailTriageResult.confidentialNote,
                                            style = MaterialTheme.typography.bodyMedium,
                                            color = RelayTextPrimary
                                        )
                                    }
                                }
                            } else {
                                Card(
                                    colors = CardDefaults.cardColors(containerColor = RelayCardElevated),
                                    shape = RoundedCornerShape(10.dp),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
                                ) {
                                    Column(modifier = Modifier.padding(12.dp)) {
                                        Row(
                                            verticalAlignment = Alignment.CenterVertically,
                                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                                        ) {
                                            Text("🔒", fontSize = 16.sp)
                                            Text(
                                                text = "END-TO-END ENCRYPTED MEDICAL NOTE",
                                                fontWeight = FontWeight.Bold,
                                                color = RelayTextPrimary,
                                                style = MaterialTheme.typography.labelMedium
                                            )
                                        }
                                        Spacer(modifier = Modifier.height(4.dp))
                                        Text(
                                            text = "Victim medical triage details are end-to-end encrypted for authorized responder node (${detailTriageResult.recipientNodeId ?: "CERTIFIED_RESPONDER"}). Intermediate relay mesh nodes route this packet securely without access to private health info.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = RelayTextMuted
                                        )
                                    }
                                }
                            }
                        }

                        if (request.latitude != null && request.longitude != null) {
                            Spacer(modifier = Modifier.height(12.dp))
                            val distMeters = GeoTacticalUtils.calculateDistanceMeters(
                                GeoTacticalUtils.DEFAULT_BASE_LATITUDE,
                                GeoTacticalUtils.DEFAULT_BASE_LONGITUDE,
                                request.latitude,
                                request.longitude
                            )
                            val bearing = GeoTacticalUtils.calculateBearingDegrees(
                                GeoTacticalUtils.DEFAULT_BASE_LATITUDE,
                                GeoTacticalUtils.DEFAULT_BASE_LONGITUDE,
                                request.latitude,
                                request.longitude
                            )
                            val dirName = GeoTacticalUtils.getCompassDirectionName(bearing)
                            val formattedDist = GeoTacticalUtils.formatDistance(distMeters)
                            val formattedCoords = GeoTacticalUtils.formatCoordinates(request.latitude, request.longitude)

                            Card(
                                colors = CardDefaults.cardColors(containerColor = RelayCardElevated),
                                shape = RoundedCornerShape(10.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, RelayPrimaryAccent.copy(alpha = 0.5f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                            Text("🛰️", fontSize = 16.sp)
                                            Text(
                                                text = "OFFLINE SATELLITE GPS FIX",
                                                fontWeight = FontWeight.Bold,
                                                color = RelayPrimaryAccent,
                                                style = MaterialTheme.typography.labelSmall,
                                                letterSpacing = 0.5.sp
                                            )
                                        }
                                        Surface(
                                            color = RelaySuccess.copy(alpha = 0.15f),
                                            shape = RoundedCornerShape(4.dp),
                                            border = androidx.compose.foundation.BorderStroke(1.dp, RelaySuccess.copy(alpha = 0.5f))
                                        ) {
                                            Text(
                                                text = "±${request.locationAccuracyMeters ?: 4.0f}m ACCURACY",
                                                color = RelaySuccess,
                                                style = MaterialTheme.typography.labelSmall,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp)
                                            )
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(6.dp))
                                    Text(
                                        text = formattedCoords,
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.SemiBold,
                                        color = RelayTextPrimary
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween
                                    ) {
                                        Text("Vector: $dirName (${bearing.toInt()}°)", style = MaterialTheme.typography.bodySmall, color = RelayPrimaryAccent, fontWeight = FontWeight.Bold)
                                        Text("Direct Distance: $formattedDist", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)
                                    }
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Text("Last Updated: $timeFormatted", style = MaterialTheme.typography.bodySmall, color = RelayTextMuted)
                            SyncTag(
                                syncStatus = request.syncStatus,
                                hopCount = request.hopCount,
                                isExpired = request.isExpired,
                                timeRemainingHours = request.timeRemainingHours
                            )
                        }
                    }
                }
            }

            // CRYPTOGRAPHIC SECURITY & AUTHENTICITY CARD
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                Text(if (request.isCryptographicallySigned) "🛡️" else "⚠️", fontSize = 18.sp)
                                Text(
                                    text = "SENDER AUTHENTICITY",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = if (request.isCryptographicallySigned) RelayPrimaryAccent else RelayWarning,
                                    letterSpacing = 1.sp
                                )
                            }

                            Surface(
                                color = if (request.isCryptographicallySigned) RelaySuccess.copy(alpha = 0.15f) else RelayWarning.copy(alpha = 0.15f),
                                shape = RoundedCornerShape(6.dp),
                                border = androidx.compose.foundation.BorderStroke(1.dp, if (request.isCryptographicallySigned) RelaySuccess else RelayWarning)
                            ) {
                                Text(
                                    text = if (request.isCryptographicallySigned) "ED25519 VERIFIED" else "LEGACY UNSIGNED",
                                    color = if (request.isCryptographicallySigned) RelaySuccess else RelayWarning,
                                    style = MaterialTheme.typography.labelSmall,
                                    fontWeight = FontWeight.Black,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(10.dp))

                        if (request.isCryptographicallySigned) {
                            Text(
                                text = "Signer Public Key (Ed25519):",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextMuted,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = request.senderPublicKey ?: "Unknown",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayPrimaryAccent,
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Digital Signature (RFC 8032):",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextMuted,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                text = (request.signature?.take(32) ?: "") + "...",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextSecondary,
                                fontSize = 11.sp
                            )
                        } else {
                            Text(
                                text = "This request was created without an Ed25519 cryptographic signature (pre-security protocol version). Authenticity cannot be verified.",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextSecondary
                            )
                        }
                    }
                }
            }

            // LIFECYCLE & STATUS UPDATE
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                    shape = RoundedCornerShape(16.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "UPDATE REQUEST STATUS (AUTO-BROADCAST)",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = RelayPrimaryAccent,
                            letterSpacing = 1.sp
                        )

                        Spacer(modifier = Modifier.height(10.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            RequestStatus.ALL.forEach { s ->
                                val isSelected = request.status == s
                                val color = when (s) {
                                    RequestStatus.PENDING -> RelayCritical
                                    RequestStatus.ASSIGNED -> RelayPrimaryAccent
                                    RequestStatus.IN_PROGRESS -> RelayEmergencyAction
                                    RequestStatus.RESOLVED -> RelaySuccess
                                    else -> Color.Gray
                                }

                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = if (isSelected) color else RelayCardElevated,
                                    border = androidx.compose.foundation.BorderStroke(1.dp, if (isSelected) color else RelayBorder),
                                    modifier = Modifier
                                        .weight(1f)
                                        .clickable { onStatusChange(s) }
                                ) {
                                    Column(
                                        modifier = Modifier.padding(vertical = 10.dp),
                                        horizontalAlignment = Alignment.CenterHorizontally
                                    ) {
                                        Text(
                                            text = s,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 11.sp,
                                            color = if (isSelected) Color.White else RelayTextSecondary
                                        )
                                    }
                                }
                            }
                        }

                        if (request.sequenceNumber > 0 && !request.lastStatusSignature.isNullOrBlank()) {
                            Spacer(modifier = Modifier.height(12.dp))
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = RelaySuccess.copy(alpha = 0.12f),
                                border = androidx.compose.foundation.BorderStroke(1.dp, RelaySuccess.copy(alpha = 0.4f)),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Text(
                                        text = "STATUS V${request.sequenceNumber} CRYPTOGRAPHICALLY SIGNED (${request.lastStatusUpdaterRole ?: "AUTHOR"})",
                                        color = RelaySuccess,
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 10.sp
                                    )
                                    Text(
                                        text = "Updater Key: ${request.lastStatusUpdaterPublicKey?.take(24)}...",
                                        color = RelayTextSecondary,
                                        fontSize = 10.sp
                                    )
                                }
                            }
                        }
                    }
                }
            }

            // STORE-AND-FORWARD ROUTING & DIAGNOSTIC CARD
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = RelayCardElevated),
                    shape = RoundedCornerShape(14.dp),
                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(14.dp)) {
                        Text(
                            text = "STORE-AND-FORWARD ROUTING & DIAGNOSTICS",
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            color = RelayPrimaryAccent,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Unique Request ID: ${request.id}", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Store-and-Forward Hops: ${request.hopCount} hops (Max: $MAX_STORE_FORWARD_HOPS)",
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayTextSecondary
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Status: ${if (request.isExpired) "EXPIRED (Dropped from mesh queue)" else "Active • TTL: ${request.timeRemainingHours}h remaining (${request.ttlHours}h limit)"}",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (request.isExpired) RelayCritical else RelaySuccess
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Transfer Status: ${request.lastTransferStatus}",
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayTextSecondary
                        )

                        Spacer(modifier = Modifier.height(8.dp))
                        HorizontalDivider(color = RelayBorder, thickness = 0.5.dp)
                        Spacer(modifier = Modifier.height(8.dp))

                        Text("Forwarding History (Route Provenance):", style = MaterialTheme.typography.labelSmall, fontWeight = FontWeight.Bold, color = RelayTextMuted)
                        Spacer(modifier = Modifier.height(4.dp))
                        if (request.nodeHistory.isEmpty()) {
                            Text("• Local device (Origin)", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)
                        } else {
                            Text(
                                text = request.nodeHistory.joinToString(" ➔ "),
                                style = MaterialTheme.typography.bodySmall,
                                fontWeight = FontWeight.SemiBold,
                                color = RelayPrimaryAccent
                            )
                        }
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = "Provenance history prevents packet duplication and infinite forwarding loops between nearby devices.",
                            style = MaterialTheme.typography.labelSmall,
                            color = RelayTextMuted
                        )
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}

// ----------------------------------------------------
// 6. PROFILE AND SETTINGS SCREEN
// ----------------------------------------------------

@Composable
fun ProfileScreen(
    context: Context,
    requestsCount: Int,
    sosCount: Int,
    currentThemeMode: ThemeMode = ThemeMode.SYSTEM,
    onThemeSelected: (ThemeMode) -> Unit = {},
    onReloadDemoData: () -> Unit = {},
    onClearData: () -> Unit
) {
    var profile by remember { mutableStateOf(loadUserProfile(context)) }
    var nameInput by remember { mutableStateOf(profile.name) }
    var phoneInput by remember { mutableStateOf(profile.phone) }
    var selectedRole by remember { mutableStateOf(profile.role) }
    var autoStartMesh by remember { mutableStateOf(profile.autoStartMesh) }

    var showClearConfirm by remember { mutableStateOf(false) }
    var savedSuccess by remember { mutableStateOf(false) }

    val roles = listOf("Disaster Responder", "Civilian / Evacuee", "Medical Doctor", "Rescue Operator", "Supply Coordinator")

    if (showClearConfirm) {
        AlertDialog(
            containerColor = RelayCardBg,
            titleContentColor = RelayTextPrimary,
            textContentColor = RelayTextSecondary,
            onDismissRequest = { showClearConfirm = false },
            title = { Text("Clear All Local Data?") },
            text = { Text("This will erase all cached requests and SOS messages from this device. Cannot be undone.") },
            confirmButton = {
                Button(
                    onClick = {
                        showClearConfirm = false
                        onClearData()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = RelayCritical)
                ) {
                    Text("Clear All Data")
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) { Text("Cancel", color = RelayTextPrimary) }
            }
        )
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        item {
            Spacer(modifier = Modifier.height(10.dp))

            Text(
                text = "Profile & Settings",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = RelayTextPrimary
            )
        }

        // APPEARANCE & THEME PREFERENCES (SYSTEM / LIGHT / DARK)
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("🌓", fontSize = 20.sp)
                            Column {
                                Text(
                                    text = "APPEARANCE & THEME",
                                    style = MaterialTheme.typography.labelMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = RelayPrimaryAccent,
                                    letterSpacing = 1.sp
                                )
                                Text(
                                    text = "Command interface contrast",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = RelayTextMuted
                                )
                            }
                        }

                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = RelayCardElevated,
                            border = androidx.compose.foundation.BorderStroke(1.dp, RelayPrimaryAccent.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = currentThemeMode.title,
                                color = RelayPrimaryAccent,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    // Three Option Tiles: System, Light, Dark
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        ThemeOptionTile(
                            title = "System",
                            icon = "📱",
                            subtitle = "Auto",
                            isSelected = currentThemeMode == ThemeMode.SYSTEM,
                            onClick = { onThemeSelected(ThemeMode.SYSTEM) },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionTile(
                            title = "Light",
                            icon = "☀️",
                            subtitle = "Clean",
                            isSelected = currentThemeMode == ThemeMode.LIGHT,
                            onClick = { onThemeSelected(ThemeMode.LIGHT) },
                            modifier = Modifier.weight(1f)
                        )
                        ThemeOptionTile(
                            title = "Dark",
                            icon = "🌙",
                            subtitle = "Tactical",
                            isSelected = currentThemeMode == ThemeMode.DARK,
                            onClick = { onThemeSelected(ThemeMode.DARK) },
                            modifier = Modifier.weight(1f)
                        )
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    Text(
                        text = "• ${currentThemeMode.description} (Saved to DataStore Preferences)",
                        style = MaterialTheme.typography.bodySmall,
                        fontSize = 11.sp,
                        color = RelayTextMuted
                    )
                }
            }
        }

        // RESPONDER IDENTITY CARD
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("👤", fontSize = 20.sp)
                        Text(
                            text = "EMERGENCY RESPONDER IDENTITY",
                            style = MaterialTheme.typography.labelMedium,
                            fontWeight = FontWeight.Bold,
                            color = RelayPrimaryAccent,
                            letterSpacing = 1.sp
                        )
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    OutlinedTextField(
                        value = nameInput,
                        onValueChange = { nameInput = it },
                        label = { Text("Your Call Sign or Name") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = RelayPrimaryAccent,
                            unfocusedBorderColor = RelayBorder,
                            focusedTextColor = RelayTextPrimary,
                            unfocusedTextColor = RelayTextPrimary
                        )
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = phoneInput,
                        onValueChange = { phoneInput = it },
                        label = { Text("Emergency Contact Phone") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = RelayPrimaryAccent,
                            unfocusedBorderColor = RelayBorder,
                            focusedTextColor = RelayTextPrimary,
                            unfocusedTextColor = RelayTextPrimary
                        )
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Text("Responder Role", style = MaterialTheme.typography.labelSmall, color = RelayTextMuted)
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        items(roles) { r ->
                            val isSelected = selectedRole == r
                            FilterChip(
                                selected = isSelected,
                                onClick = { selectedRole = r },
                                label = { Text(r, fontSize = 12.sp) },
                                colors = FilterChipDefaults.filterChipColors(
                                    selectedContainerColor = RelayPrimaryAccent,
                                    selectedLabelColor = RelayBg,
                                    containerColor = RelayCardElevated,
                                    labelColor = RelayTextSecondary
                                ),
                                border = FilterChipDefaults.filterChipBorder(
                                    enabled = true,
                                    selected = isSelected,
                                    borderColor = if (isSelected) RelayPrimaryAccent else RelayBorder
                                )
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = {
                            val updated = UserProfile(
                                name = nameInput.trim(),
                                role = selectedRole,
                                phone = phoneInput.trim(),
                                autoStartMesh = autoStartMesh
                            )
                            saveUserProfile(context, updated)
                            profile = updated
                            savedSuccess = true
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = RelayPrimaryAccent, contentColor = RelayBg),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(if (savedSuccess) "✓ Profile Saved" else "Save Responder Profile", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // MESH RADIO PREFERENCES
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "MESH NETWORK PREFERENCES",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = RelayPrimaryAccent,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Auto-start Mesh on Launch", fontWeight = FontWeight.Bold, color = RelayTextPrimary)
                            Text("Starts discovery & beacon immediately when opening app", style = MaterialTheme.typography.bodySmall, color = RelayTextMuted)
                        }
                        Switch(
                            checked = autoStartMesh,
                            onCheckedChange = {
                                autoStartMesh = it
                                val updated = profile.copy(autoStartMesh = it)
                                saveUserProfile(context, updated)
                                profile = updated
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = RelayBg,
                                checkedTrackColor = RelayPrimaryAccent
                            )
                        )
                    }
                }
            }
        }

        // CRYPTOGRAPHIC IDENTITY & RESPONDER AUTHORIZATION
        item {
            val localNodeId = remember { NodeIdentityManager.getLocalNodeId(context) }
            val localPubKey = remember {
                try {
                    RelayKeyStoreManager.getInstance(context).getPublicKeyHex()
                } catch (e: Exception) {
                    "Unavailable"
                }
            }
            var responderKeyInput by remember { mutableStateOf("") }
            var registeredResponders by remember { mutableStateOf(StatusAuthorizationPolicy.getRegisteredResponderKeys()) }
            var keyStatusMsg by remember { mutableStateOf<String?>(null) }

            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "CRYPTOGRAPHIC IDENTITY & SECURITY",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = RelayPrimaryAccent,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Text("Local Node ID (Cryptographically Bound)", fontWeight = FontWeight.Bold, color = RelayTextPrimary, style = MaterialTheme.typography.bodySmall)
                    Text(localNodeId, color = RelayTextSecondary, style = MaterialTheme.typography.bodySmall)

                    Spacer(modifier = Modifier.height(8.dp))

                    Text("Keystore Hardware Protection", fontWeight = FontWeight.Bold, color = RelayTextPrimary, style = MaterialTheme.typography.bodySmall)
                    val secLevel = remember { RelayKeyStoreManager.getInstance(context).getSecurityLevel() }
                    Text(secLevel, color = RelaySuccess, style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.SemiBold)

                    Spacer(modifier = Modifier.height(8.dp))

                    Text("Ed25519 Public Key (Hex)", fontWeight = FontWeight.Bold, color = RelayTextPrimary, style = MaterialTheme.typography.bodySmall)
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = RelayCardElevated,
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(
                            text = localPubKey,
                            style = MaterialTheme.typography.bodySmall,
                            color = RelayPrimaryAccent,
                            modifier = Modifier.padding(8.dp),
                            maxLines = 2,
                            overflow = TextOverflow.Ellipsis
                        )
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedButton(
                        onClick = {
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                            val clip = android.content.ClipData.newPlainText("RELAY Public Key", localPubKey)
                            clipboard.setPrimaryClip(clip)
                            android.widget.Toast.makeText(context, "Public key copied to clipboard", android.widget.Toast.LENGTH_SHORT).show()
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = RelayPrimaryAccent),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayPrimaryAccent),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Copy Public Key", fontWeight = FontWeight.Bold)
                    }

                    Spacer(modifier = Modifier.height(16.dp))
                    HorizontalDivider(color = RelayBorder)
                    Spacer(modifier = Modifier.height(14.dp))

                    Text(
                        text = "TRUSTED RESPONDER AUTHORIZATION",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = RelayPrimaryAccent,
                        letterSpacing = 0.5.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Register certified responder public keys authorized to transition emergency request status across the mesh.",
                        style = MaterialTheme.typography.bodySmall,
                        color = RelayTextMuted
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    OutlinedTextField(
                        value = responderKeyInput,
                        onValueChange = { responderKeyInput = it },
                        placeholder = { Text("Paste 64-character hex public key", color = RelayTextMuted, style = MaterialTheme.typography.bodySmall) },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = RelayPrimaryAccent,
                            unfocusedBorderColor = RelayBorder,
                            focusedTextColor = RelayTextPrimary,
                            unfocusedTextColor = RelayTextPrimary
                        )
                    )

                    Spacer(modifier = Modifier.height(8.dp))

                    Button(
                        onClick = {
                            val clean = responderKeyInput.trim()
                            if (clean.length == 64 && clean.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                                StatusAuthorizationPolicy.registerResponderKey(clean)
                                registeredResponders = StatusAuthorizationPolicy.getRegisteredResponderKeys()
                                responderKeyInput = ""
                                keyStatusMsg = "Responder key registered successfully"
                            } else {
                                keyStatusMsg = "Invalid key: Must be 64-char hex string"
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = RelayPrimaryAccent),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Register Responder Key", fontWeight = FontWeight.Bold)
                    }

                    if (keyStatusMsg != null) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(keyStatusMsg ?: "", color = if (keyStatusMsg?.startsWith("Invalid") == true) RelayCritical else RelaySuccess, style = MaterialTheme.typography.bodySmall)
                    }

                    if (registeredResponders.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text("Active Certified Responders (${registeredResponders.size}):", fontWeight = FontWeight.Bold, color = RelayTextPrimary, style = MaterialTheme.typography.bodySmall)
                        registeredResponders.forEach { key ->
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text("• ${key.take(14)}...${key.takeLast(6)}", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary, modifier = Modifier.weight(1f))
                                OutlinedButton(
                                    onClick = {
                                        StatusAuthorizationPolicy.revokeResponder(context, key, "Revoked by Coordinator")
                                        registeredResponders = StatusAuthorizationPolicy.getRegisteredResponderKeys()
                                        android.widget.Toast.makeText(context, "Responder Revoked", android.widget.Toast.LENGTH_SHORT).show()
                                    },
                                    colors = ButtonDefaults.outlinedButtonColors(contentColor = RelayCritical),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, RelayCritical),
                                    shape = RoundedCornerShape(6.dp),
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                ) {
                                    Text("Revoke", fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                }
                            }
                        }
                    }
                }
            }
        }

        // POWER SURVIVAL & BATTERY CONSERVATION
        item {
            val batteryPct by PowerConservationManager.batteryPercentState
            val isCharging by PowerConservationManager.isChargingState
            var batterySaverActive by PowerConservationManager.isBatterySaverEnabledState

            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column {
                            Text(
                                text = "POWER SURVIVAL & BATTERY",
                                style = MaterialTheme.typography.labelMedium,
                                fontWeight = FontWeight.Bold,
                                color = RelayPrimaryAccent,
                                letterSpacing = 1.sp
                            )
                            Text(
                                text = "Disaster duty-cycle radio management",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextMuted
                            )
                        }

                        Surface(
                            shape = RoundedCornerShape(6.dp),
                            color = if (batteryPct <= 15) RelayCritical.copy(alpha = 0.2f) else RelayCardElevated,
                            border = androidx.compose.foundation.BorderStroke(1.dp, if (batteryPct <= 15) RelayCritical else RelayPrimaryAccent.copy(alpha = 0.5f))
                        ) {
                            Text(
                                text = if (isCharging) "⚡ $batteryPct% (Charging)" else "🔋 $batteryPct%",
                                color = if (batteryPct <= 15) RelayCritical else RelayPrimaryAccent,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(14.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Emergency Battery Saver Mesh", fontWeight = FontWeight.Bold, color = RelayTextPrimary)
                            Text(
                                text = "Burst duty cycling (20s on / 40s off) reduces radio drain by ~66% to keep phone alive during extended blackouts. Auto-engages at ≤15% battery.",
                                style = MaterialTheme.typography.bodySmall,
                                color = RelayTextMuted
                            )
                        }

                        Switch(
                            checked = batterySaverActive,
                            onCheckedChange = {
                                batterySaverActive = it
                                PowerConservationManager.setManualBatterySaver(it)
                            },
                            colors = SwitchDefaults.colors(
                                checkedThumbColor = RelayBg,
                                checkedTrackColor = RelayPrimaryAccent
                            )
                        )
                    }
                }
            }
        }

        // STORAGE & DATA DIAGNOSTICS
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardBg),
                shape = RoundedCornerShape(16.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "LOCAL DATA & STORAGE",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.Bold,
                        color = RelayPrimaryAccent,
                        letterSpacing = 1.sp
                    )

                    Spacer(modifier = Modifier.height(10.dp))

                    Text("• Saved Requests: $requestsCount records", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)
                    Text("• Cached SOS Messages: $sosCount broadcasts", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)
                    Text("• Storage Engine: SharedPreferences JSON atomic commit", style = MaterialTheme.typography.bodySmall, color = RelayTextSecondary)

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = {
                            val staticList = StaticDemoData.getStaticEmergencyRequests(context)
                            val staticMsgs = StaticDemoData.getStaticSosMessages(context)
                            saveRequests(context, staticList)
                            saveSosMessages(context, staticMsgs)
                            StaticDemoData.seedStaticMeshEnvironment(context)
                            onReloadDemoData()
                            android.widget.Toast.makeText(context, "Loaded test disaster scenario (5 requests, 4 peers)", android.widget.Toast.LENGTH_SHORT).show()
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = RelayCardElevated),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("🧪 Load Test Disaster Scenario (Demo Only)", fontWeight = FontWeight.Bold, color = RelayPrimaryAccent)
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedButton(
                        onClick = { showClearConfirm = true },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = RelayCritical),
                        border = androidx.compose.foundation.BorderStroke(1.dp, RelayCritical),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Clear All Local Data", fontWeight = FontWeight.Bold)
                    }
                }
            }
        }

        // ABOUT APP
        item {
            Card(
                colors = CardDefaults.cardColors(containerColor = RelayCardElevated),
                shape = RoundedCornerShape(14.dp),
                border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("RELAY Command Center v1.2", fontWeight = FontWeight.Bold, color = RelayTextPrimary)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Offline-first disaster coordination powered by Google Nearby Connections.",
                        style = MaterialTheme.typography.bodySmall,
                        color = RelayTextMuted
                    )
                }
            }
        }

        item {
            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}

// ----------------------------------------------------
// REUSABLE BADGES & WIDGETS
// ----------------------------------------------------

@Composable
fun ThemeOptionTile(
    title: String,
    icon: String,
    subtitle: String,
    isSelected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(12.dp),
        color = if (isSelected) RelayPrimaryAccent.copy(alpha = 0.15f) else RelayCardElevated,
        border = androidx.compose.foundation.BorderStroke(
            width = if (isSelected) 2.dp else 1.dp,
            color = if (isSelected) RelayPrimaryAccent else RelayBorder
        ),
        modifier = modifier
    ) {
        Column(
            modifier = Modifier.padding(vertical = 12.dp, horizontal = 4.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(icon, fontSize = 22.sp)
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = if (isSelected) FontWeight.Black else FontWeight.Bold,
                color = if (isSelected) RelayPrimaryAccent else RelayTextPrimary
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                fontSize = 10.sp,
                color = if (isSelected) RelayPrimaryAccent else RelayTextMuted
            )
        }
    }
}

@Composable
fun MetricItemCard(title: String, count: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = RelayCardBg),
        shape = RoundedCornerShape(12.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, RelayBorder)
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(title, style = MaterialTheme.typography.labelSmall, color = RelayTextMuted, maxLines = 1)
            Spacer(modifier = Modifier.height(4.dp))
            Text(count, fontSize = 22.sp, fontWeight = FontWeight.Black, color = color)
        }
    }
}

@Composable
fun StatusTag(status: String) {
    val (bg, fg) = when (status) {
        RequestStatus.PENDING -> RelayCritical.copy(alpha = 0.2f) to RelayCritical
        RequestStatus.IN_PROGRESS -> RelayEmergencyAction.copy(alpha = 0.2f) to RelayEmergencyAction
        RequestStatus.RESOLVED -> RelaySuccess.copy(alpha = 0.2f) to RelaySuccess
        else -> RelayCardElevated to RelayPrimaryAccent
    }
    Surface(
        color = bg,
        shape = RoundedCornerShape(4.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, fg)
    ) {
        Text(
            text = status,
            color = fg,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

@Composable
fun SyncTag(
    syncStatus: String,
    hopCount: Int = 0,
    isExpired: Boolean = false,
    timeRemainingHours: Long = 0L
) {
    val text: String
    val color: Color
    if (isExpired) {
        text = "⏱️ Expired"
        color = RelayCritical
    } else if (syncStatus == SyncStatus.FAILED) {
        text = "⚠️ Rejected"
        color = RelayCritical
    } else if (syncStatus == SyncStatus.SYNCED) {
        text = if (hopCount > 0) "✓ Synced ($hopCount hops)" else "✓ Synced"
        color = RelaySuccess
    } else {
        text = "⏳ Pending Sync"
        color = RelayWarning
    }

    Surface(
        color = color.copy(alpha = 0.15f),
        shape = RoundedCornerShape(4.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, color)
    ) {
        Text(
            text = text,
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontWeight = FontWeight.Bold,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
        )
    }
}

// ----------------------------------------------------
// PERSISTENCE (PURE LOCAL REAL DATA)
// ----------------------------------------------------

fun saveRequests(context: Context, requests: List<EmergencyRequest>): Boolean {
    val prunedRequests = StorageRetentionManager.pruneExpiredRequests(requests)
    val jsonArray = JSONArray()
    for (request in prunedRequests) {
        val jsonObject = JSONObject().apply {
            put("id", request.id)
            put("type", request.type)
            put("description", request.description)
            put("people", request.people)
            put("priority", request.priority)
            put("status", request.status)
            put("updatedAt", request.updatedAt)
            put("syncStatus", request.syncStatus)
            put("hopCount", request.hopCount)
            put("createdAt", request.createdAt)
            put("ttlHours", request.ttlHours)
            put("nodeHistory", StoreAndForwardHelper.serializeNodeHistory(request.nodeHistory))
            put("lastTransferStatus", request.lastTransferStatus)
            put("senderPublicKey", request.senderPublicKey ?: "")
            put("signature", request.signature ?: "")
            put("originatorNodeId", request.originatorNodeId)
            put("sequenceNumber", request.sequenceNumber)
            put("lastStatusSignature", request.lastStatusSignature ?: "")
            put("lastStatusUpdaterPublicKey", request.lastStatusUpdaterPublicKey ?: "")
            put("lastStatusUpdaterRole", request.lastStatusUpdaterRole ?: "")
            request.latitude?.let { put("latitude", it) }
            request.longitude?.let { put("longitude", it) }
            request.locationAccuracyMeters?.let { put("accuracy", it.toDouble()) }
        }
        jsonArray.put(jsonObject)
    }

    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(REQUESTS_KEY, jsonArray.toString())
        .commit()
}

fun loadRequests(context: Context): List<EmergencyRequest> {
    val preferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val savedData = preferences.getString(REQUESTS_KEY, null)
    if (savedData.isNullOrBlank() || savedData == "[]") {
        return emptyList()
    }

    return try {
        val jsonArray = JSONArray(savedData)
        val result = mutableListOf<EmergencyRequest>()
        for (i in 0 until jsonArray.length()) {
            val item = jsonArray.getJSONObject(i)
            val updatedAt = item.optLong("updatedAt", System.currentTimeMillis())
            val createdAt = item.optLong("createdAt", updatedAt)
            val historyArray = item.optJSONArray("nodeHistory")
            val history = StoreAndForwardHelper.parseNodeHistory(historyArray)
            val senderPublicKey = item.optString("senderPublicKey", "").ifBlank { null }
            val signature = item.optString("signature", "").ifBlank { null }
            val originatorNodeId = item.optString("originatorNodeId", "")
            val lat = if (item.has("latitude") && !item.isNull("latitude")) item.optDouble("latitude") else null
            val lng = if (item.has("longitude") && !item.isNull("longitude")) item.optDouble("longitude") else null
            val acc = if (item.has("accuracy") && !item.isNull("accuracy")) item.optDouble("accuracy").toFloat() else null
            result.add(
                EmergencyRequest(
                    id = item.optString("id", UUID.randomUUID().toString()),
                    type = item.optString("type", "Rescue"),
                    description = item.optString("description", ""),
                    people = item.optInt("people", 1),
                    priority = item.optString("priority", "Medium"),
                    status = item.optString("status", RequestStatus.PENDING),
                    updatedAt = updatedAt,
                    syncStatus = item.optString("syncStatus", SyncStatus.SYNCED),
                    hopCount = item.optInt("hopCount", 0),
                    createdAt = createdAt,
                    ttlHours = item.optInt("ttlHours", DEFAULT_REQUEST_TTL_HOURS),
                    nodeHistory = history,
                    lastTransferStatus = item.optString("lastTransferStatus", "Stored locally"),
                    senderPublicKey = senderPublicKey,
                    signature = signature,
                    originatorNodeId = originatorNodeId,
                    sequenceNumber = item.optInt("sequenceNumber", 0),
                    lastStatusSignature = item.optString("lastStatusSignature", "").ifBlank { null },
                    lastStatusUpdaterPublicKey = item.optString("lastStatusUpdaterPublicKey", "").ifBlank { null },
                    lastStatusUpdaterRole = item.optString("lastStatusUpdaterRole", "").ifBlank { null },
                    latitude = lat,
                    longitude = lng,
                    locationAccuracyMeters = acc
                )
            )
        }
        result
    } catch (e: Exception) {
        Log.e(TAG, "Could not load saved requests", e)
        emptyList()
    }
}

fun saveSosMessages(context: Context, messages: List<SosMessage>): Boolean {
    val prunedMessages = StorageRetentionManager.pruneSosMessages(messages)
    val arr = JSONArray()
    prunedMessages.forEach { msg ->
        val obj = JSONObject().apply {
            put("id", msg.id)
            put("senderName", msg.senderName)
            put("message", msg.message)
            put("isEmergency", msg.isEmergency)
            put("timestamp", msg.timestamp)
            put("hopCount", msg.hopCount)
            put("syncStatus", msg.syncStatus)
            put("senderPublicKey", msg.senderPublicKey ?: "")
            put("signature", msg.signature ?: "")
            put("senderNodeId", msg.senderNodeId)
        }
        arr.put(obj)
    }
    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(MESSAGES_KEY, arr.toString())
        .commit()
}

fun loadSosMessages(context: Context): List<SosMessage> {
    val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val data = prefs.getString(MESSAGES_KEY, null)
    if (data.isNullOrBlank() || data == "[]") {
        return emptyList()
    }
    return try {
        val arr = JSONArray(data)
        val list = mutableListOf<SosMessage>()
        for (i in 0 until arr.length()) {
            val obj = arr.getJSONObject(i)
            list.add(
                SosMessage(
                    id = obj.getString("id"),
                    senderName = obj.optString("senderName", "Nearby Device"),
                    message = obj.getString("message"),
                    isEmergency = obj.optBoolean("isEmergency", true),
                    timestamp = obj.optLong("timestamp", System.currentTimeMillis()),
                    hopCount = obj.optInt("hopCount", 0),
                    syncStatus = obj.optString("syncStatus", SyncStatus.SYNCED),
                    senderPublicKey = obj.optString("senderPublicKey", "").ifBlank { null },
                    signature = obj.optString("signature", "").ifBlank { null },
                    senderNodeId = obj.optString("senderNodeId", "")
                )
            )
        }
        list
    } catch (e: Exception) {
        Log.e(TAG, "Error loading SOS messages", e)
        emptyList()
    }
}

fun saveUserProfile(context: Context, profile: UserProfile): Boolean {
    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString("profile_name", profile.name)
        .putString("profile_role", profile.role)
        .putString("profile_phone", profile.phone)
        .putString("profile_blood", profile.bloodGroup)
        .putBoolean("profile_autostart", profile.autoStartMesh)
        .commit()
}

fun loadUserProfile(context: Context): UserProfile {
    val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    val name = prefs.getString("profile_name", "Responder - " + Build.MODEL.take(8)) ?: ("Responder - " + Build.MODEL.take(8))
    val role = prefs.getString("profile_role", "Disaster Responder") ?: "Disaster Responder"
    val phone = prefs.getString("profile_phone", "") ?: ""
    val blood = prefs.getString("profile_blood", "O+") ?: "O+"
    val autoStart = prefs.getBoolean("profile_autostart", true)
    return UserProfile(name, role, phone, blood, autoStart)
}

fun clearAllStoredData(context: Context): Boolean {
    return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .commit()
}

// ============================================================================
// ANIMATED INTRO / SPLASH SCREEN (RADAR SWEEP, GLOWING MESH & SHIMMER TITLE)
// ============================================================================

@Composable
fun AnimatedSplashScreen(
    onSplashFinished: () -> Unit
) {
    // Logo entrance animation
    val logoScale = remember { Animatable(0.25f) }
    val logoAlpha = remember { Animatable(0f) }

    // Text & badges entrance animation
    val textAlpha = remember { Animatable(0f) }
    val textOffsetY = remember { Animatable(28f) }
    val badgeAlpha = remember { Animatable(0f) }

    // Status message cycling
    var statusText by remember { mutableStateOf("INITIALIZING ED25519 CRYPTO...") }

    // Infinite transitions
    val infiniteTransition = rememberInfiniteTransition(label = "RadarAnimations")

    // 1. Radar pulse ripple waves (staggered)
    val pulseProgress by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2400, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "PulseProgress"
    )

    // 2. Continuous 360-degree rotating radar scanner beam
    val sweepAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2800, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "SweepAngle"
    )

    // 3. Shimmer gradient offset across "RELAY" text
    val shimmerOffset by infiniteTransition.animateFloat(
        initialValue = -300f,
        targetValue = 600f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 2000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "TextShimmer"
    )

    // 4. Subtle breathing pulse on the shield logo
    val breathingScale by infiniteTransition.animateFloat(
        initialValue = 1.0f,
        targetValue = 1.07f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "BreathingScale"
    )

    // 5. Mesh satellite nodes orbit pulsing
    val satellitePulse by infiniteTransition.animateFloat(
        initialValue = 0.4f,
        targetValue = 1.0f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 900, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "SatellitePulse"
    )

    // 6. Signal bars animation (equalizer heights)
    val bar1 by infiniteTransition.animateFloat(
        initialValue = 6f, targetValue = 22f,
        animationSpec = infiniteRepeatable(tween(400, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "Bar1"
    )
    val bar2 by infiniteTransition.animateFloat(
        initialValue = 18f, targetValue = 8f,
        animationSpec = infiniteRepeatable(tween(550, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "Bar2"
    )
    val bar3 by infiniteTransition.animateFloat(
        initialValue = 10f, targetValue = 26f,
        animationSpec = infiniteRepeatable(tween(350, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "Bar3"
    )
    val bar4 by infiniteTransition.animateFloat(
        initialValue = 24f, targetValue = 12f,
        animationSpec = infiniteRepeatable(tween(600, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "Bar4"
    )
    val bar5 by infiniteTransition.animateFloat(
        initialValue = 8f, targetValue = 20f,
        animationSpec = infiniteRepeatable(tween(450, easing = FastOutSlowInEasing), RepeatMode.Reverse), label = "Bar5"
    )

    LaunchedEffect(Unit) {
        // Step 1: Logo spring entrance & fade-in
        launch {
            logoAlpha.animateTo(1f, animationSpec = tween(durationMillis = 600, easing = FastOutSlowInEasing))
        }
        launch {
            logoScale.animateTo(
                1f,
                animationSpec = spring(
                    dampingRatio = Spring.DampingRatioMediumBouncy,
                    stiffness = Spring.StiffnessLow
                )
            )
        }

        // Step 2: Title fades in and slides upward
        delay(220)
        launch {
            textAlpha.animateTo(1f, animationSpec = tween(durationMillis = 500))
        }
        launch {
            textOffsetY.animateTo(0f, animationSpec = spring(dampingRatio = Spring.DampingRatioLowBouncy))
        }

        // Step 3: Badges fade in
        delay(200)
        launch {
            badgeAlpha.animateTo(1f, animationSpec = tween(durationMillis = 400))
        }

        // Tactical Status Updates during startup
        delay(400)
        statusText = "SCANNING BLUETOOTH LE & WI-FI DIRECT..."
        delay(700)
        statusText = "OFFLINE MESH ACTIVE • ZERO INTERNET"

        // Total display duration before transitioning cleanly into Command Center
        delay(900)
        onSplashFinished()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.radialGradient(
                    colors = listOf(
                        Color(0xFF0F223D), // Rich navy center
                        Color(0xFF0A1424), // Midnight navy
                        Color(0xFF050A12)  // Deep tactical black-navy
                    ),
                    radius = 1200f
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        // Radar Canvas: Reticle, Concentric Waves, Rotating Scanner Wedge, and Satellite Nodes
        Canvas(modifier = Modifier.size(380.dp)) {
            val centerOffset = Offset(size.width / 2f, size.height / 2f)
            val maxRadius = size.minDimension / 1.4f

            // Fixed Reticle Crosshairs (Military / Radar HUD style)
            drawLine(
                color = Color(0xFF00E5FF).copy(alpha = 0.15f),
                start = Offset(centerOffset.x - maxRadius, centerOffset.y),
                end = Offset(centerOffset.x + maxRadius, centerOffset.y),
                strokeWidth = 1.dp.toPx()
            )
            drawLine(
                color = Color(0xFF00E5FF).copy(alpha = 0.15f),
                start = Offset(centerOffset.x, centerOffset.y - maxRadius),
                end = Offset(centerOffset.x, centerOffset.y + maxRadius),
                strokeWidth = 1.dp.toPx()
            )

            // Concentric Expanding Radar Waves
            for (i in 0..3) {
                val phase = (pulseProgress + i * 0.25f) % 1f
                val radius = 40.dp.toPx() + (maxRadius - 40.dp.toPx()) * phase
                val alpha = (1f - phase).coerceIn(0f, 1f) * 0.45f
                drawCircle(
                    color = Color(0xFF00E5FF).copy(alpha = alpha),
                    radius = radius,
                    center = centerOffset,
                    style = Stroke(width = 2.dp.toPx())
                )
            }

            // 360° Rotating Radar Sweep Wedge
            rotate(sweepAngle, pivot = centerOffset) {
                drawArc(
                    brush = Brush.sweepGradient(
                        colors = listOf(
                            Color.Transparent,
                            Color(0xFF00E5FF).copy(alpha = 0.28f),
                            Color.Transparent
                        ),
                        center = centerOffset
                    ),
                    startAngle = 0f,
                    sweepAngle = 75f,
                    useCenter = true,
                    size = Size(maxRadius * 2f, maxRadius * 2f),
                    topLeft = Offset(centerOffset.x - maxRadius, centerOffset.y - maxRadius)
                )
                // Crisp Leading Edge Line
                val lineRad = Math.toRadians(75.0)
                val lineEnd = Offset(
                    (centerOffset.x + maxRadius * Math.cos(lineRad)).toFloat(),
                    (centerOffset.y + maxRadius * Math.sin(lineRad)).toFloat()
                )
                drawLine(
                    color = Color(0xFF00E5FF).copy(alpha = 0.85f),
                    start = centerOffset,
                    end = lineEnd,
                    strokeWidth = 2.dp.toPx()
                )
            }

            // 4 Orbiting Peer Mesh Nodes (Satellite Radios)
            val satelliteAngles = listOf(45.0, 135.0, 225.0, 315.0)
            val orbitRadius = maxRadius * 0.72f
            satelliteAngles.forEachIndexed { index, angleDeg ->
                val rad = Math.toRadians(angleDeg + (sweepAngle * 0.15f))
                val nodePos = Offset(
                    (centerOffset.x + orbitRadius * Math.cos(rad)).toFloat(),
                    (centerOffset.y + orbitRadius * Math.sin(rad)).toFloat()
                )
                // Dotted connection line to center
                drawLine(
                    color = Color(0xFF00E5FF).copy(alpha = 0.18f * satellitePulse),
                    start = centerOffset,
                    end = nodePos,
                    strokeWidth = 1.dp.toPx()
                )
                // Glowing outer node ring
                drawCircle(
                    color = Color(0xFF00E5FF).copy(alpha = 0.35f * satellitePulse),
                    radius = 8.dp.toPx() * satellitePulse,
                    center = nodePos
                )
                // Solid inner node dot
                drawCircle(
                    color = if (index % 2 == 0) Color(0xFF10B981) else Color(0xFFFF6B35),
                    radius = 4.dp.toPx(),
                    center = nodePos
                )
            }
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(24.dp)
        ) {
            // Animated Connected Shield Logo with Breathing Scale & Radial Glow
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier
                    .scale(logoScale.value * breathingScale)
                    .alpha(logoAlpha.value)
            ) {
                // Multi-layer glowing aura
                Box(
                    modifier = Modifier
                        .size(160.dp)
                        .background(
                            brush = Brush.radialGradient(
                                colors = listOf(
                                    Color(0xFF00E5FF).copy(alpha = 0.35f),
                                    Color(0xFF00E5FF).copy(alpha = 0.10f),
                                    Color.Transparent
                                )
                            ),
                            shape = CircleShape
                        )
                )

                Image(
                    painter = painterResource(id = R.drawable.ic_relay_logo),
                    contentDescription = "RELAY Shield Logo",
                    modifier = Modifier.size(112.dp)
                )
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Shimmering Gradient for "RELAY" Name
            val titleGradient = Brush.linearGradient(
                colors = listOf(
                    Color(0xFFFFFFFF), // Crisp pure white highlight
                    Color(0xFF38BDF8), // Electric Sky Blue
                    Color(0xFF00E5FF), // Radiant Neon Cyan
                    Color(0xFF2DD4BF), // Emerald Teal
                    Color(0xFFFFFFFF)  // Back to white
                ),
                start = Offset(shimmerOffset, 0f),
                end = Offset(shimmerOffset + 350f, 60f)
            )

            Text(
                text = "Relay",
                style = TextStyle(
                    brush = titleGradient,
                    fontSize = 48.sp,
                    fontWeight = FontWeight.Black,
                    letterSpacing = 4.sp,
                    shadow = Shadow(
                        color = Color(0xFF00E5FF).copy(alpha = 0.75f),
                        blurRadius = 24f,
                        offset = Offset(0f, 4f)
                    )
                ),
                modifier = Modifier
                    .alpha(textAlpha.value)
                    .offset(y = textOffsetY.value.dp)
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Subtitle Tactical Badge Pill
            Surface(
                color = Color(0xFF0B192C).copy(alpha = 0.95f),
                shape = RoundedCornerShape(20.dp),
                border = androidx.compose.foundation.BorderStroke(1.2.dp, Color(0xFF00E5FF).copy(alpha = 0.7f)),
                shadowElevation = 8.dp,
                modifier = Modifier.alpha(badgeAlpha.value)
            ) {
                Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 7.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    // Pulsing Green Beacon LED
                    Box(
                        modifier = Modifier
                            .size(9.dp)
                            .background(
                                brush = Brush.radialGradient(
                                    colors = listOf(Color(0xFF10B981), Color(0xFF059669))
                                ),
                                shape = CircleShape
                            )
                    )
                    Text(
                        text = "OFFLINE EMERGENCY MESH",
                        color = Color(0xFF00E5FF),
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Black,
                        letterSpacing = 1.4.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // Live Animated Radio Signal Equalizer Bars
            Row(
                horizontalArrangement = Arrangement.spacedBy(5.dp),
                verticalAlignment = Alignment.Bottom,
                modifier = Modifier
                    .height(26.dp)
                    .alpha(badgeAlpha.value)
            ) {
                listOf(bar1, bar2, bar3, bar4, bar5).forEachIndexed { i, barHeight ->
                    Box(
                        modifier = Modifier
                            .width(4.dp)
                            .height(barHeight.dp)
                            .background(
                                brush = Brush.verticalGradient(
                                    colors = listOf(
                                        Color(0xFF00E5FF),
                                        if (i % 2 == 0) Color(0xFF10B981) else Color(0xFFFF6B35)
                                    )
                                ),
                                shape = RoundedCornerShape(2.dp)
                            )
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Dynamic Cycling Status Text
            Text(
                text = statusText,
                color = Color(0xFF94A3B8),
                fontSize = 10.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 1.2.sp,
                modifier = Modifier.alpha(badgeAlpha.value)
            )

            Spacer(modifier = Modifier.height(6.dp))

            Text(
                text = "PEER-TO-PEER • ZERO INTERNET • HARDWARE ENCLAVE E2EE",
                color = Color(0xFF64748B),
                fontSize = 9.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = 0.8.sp,
                modifier = Modifier.alpha(badgeAlpha.value)
            )
        }
    }
}
package com.relay.emergency.mesh

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import androidx.compose.runtime.mutableStateOf

/**
 * Manages adaptive duty cycling for emergency low-power mesh operation.
 *
 * Operational Theory:
 * Continuous BLE advertising and Wi-Fi Direct discovery consume significant power.
 * During extended disaster blackouts, device battery preservation is life-critical.
 *
 * When the battery drops below [LOW_BATTERY_THRESHOLD_PERCENT] (15%) or when
 * explicitly toggled by the user:
 * - Switches radio duty cycling from 100% continuous to Burst Duty Cycling:
 *   20 seconds ACTIVE (transmitting & discovering) followed by 40 seconds SLEEP.
 * - This reduces radio energy drain by ~66%, extending operational field runtime by up to 3x!
 */
object PowerConservationManager {

    /** Battery percentage threshold below which low-power mesh mode automatically engages */
    const val LOW_BATTERY_THRESHOLD_PERCENT = 15

    /** Burst active duration: 20 seconds */
    const val ACTIVE_BURST_MS = 20_000L

    /** Burst sleep duration: 40 seconds */
    const val SLEEP_BURST_MS = 40_000L

    val isBatterySaverEnabledState = mutableStateOf(false)
    val batteryPercentState = mutableStateOf(100)
    val isChargingState = mutableStateOf(false)
    val dutyCyclePhaseState = mutableStateOf(DutyCyclePhase.ACTIVE)

    enum class DutyCyclePhase(val label: String) {
        ACTIVE("Transmitting Beacon"),
        SLEEP("Power-Saving Sleep")
    }

    private var batteryReceiver: BroadcastReceiver? = null
    private var isInitialized = false

    fun initialize(context: Context) {
        if (isInitialized) return
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        batteryReceiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                updateBatteryStateFromIntent(intent)
            }
        }
        try {
            val batteryStatus = context.registerReceiver(batteryReceiver, filter)
            batteryStatus?.let { updateBatteryStateFromIntent(it) }
            isInitialized = true
        } catch (_: Exception) {
            // Safe fallback for test environments without real battery service
        }
    }

    fun updateBatteryStateFromIntent(intent: Intent) {
        val level = intent.getIntExtra(BatteryManager.EXTRA_LEVEL, -1)
        val scale = intent.getIntExtra(BatteryManager.EXTRA_SCALE, -1)
        val status = intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)

        val pct = if (level >= 0 && scale > 0) (level * 100) / scale else 100
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
                       status == BatteryManager.BATTERY_STATUS_FULL

        batteryPercentState.value = pct
        isChargingState.value = charging

        // Automatically engage if below threshold and not on charger
        if (pct <= LOW_BATTERY_THRESHOLD_PERCENT && !charging) {
            isBatterySaverEnabledState.value = true
        }
    }

    fun setManualBatterySaver(enabled: Boolean) {
        isBatterySaverEnabledState.value = enabled
    }

    fun isLowPowerModeActive(): Boolean {
        return isBatterySaverEnabledState.value && !isChargingState.value
    }

    fun setMockBatteryLevelForTesting(pct: Int, isCharging: Boolean = false) {
        batteryPercentState.value = pct
        isChargingState.value = isCharging
        if (pct <= LOW_BATTERY_THRESHOLD_PERCENT && !isCharging) {
            isBatterySaverEnabledState.value = true
        } else if (isCharging) {
            isBatterySaverEnabledState.value = false
        }
    }

    fun resetForTesting() {
        isBatterySaverEnabledState.value = false
        batteryPercentState.value = 100
        isChargingState.value = false
        dutyCyclePhaseState.value = DutyCyclePhase.ACTIVE
    }
}


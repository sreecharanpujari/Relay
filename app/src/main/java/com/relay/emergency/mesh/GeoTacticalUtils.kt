package com.relay.emergency.mesh

import java.util.Locale

/**
 * Pure Kotlin mathematical utilities for offline GPS navigation, distance, and bearing.
 * Completely independent of Android framework Location class for 100% JVM testability.
 */
object GeoTacticalUtils {

    const val DEFAULT_BASE_LATITUDE = 13.0827
    const val DEFAULT_BASE_LONGITUDE = 80.2707

    /**
     * Calculates the great-circle distance in meters between two decimal coordinates
     * using the Haversine formula.
     */
    fun calculateDistanceMeters(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val earthRadiusMeters = 6371000.0
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                Math.cos(Math.toRadians(lat1)) * Math.cos(Math.toRadians(lat2)) *
                Math.sin(dLon / 2) * Math.sin(dLon / 2)
        val c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a))
        return earthRadiusMeters * c
    }

    /**
     * Calculates the initial compass bearing in degrees (0..360) from start point to destination.
     */
    fun calculateBearingDegrees(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Float {
        val phi1 = Math.toRadians(lat1)
        val phi2 = Math.toRadians(lat2)
        val deltaLambda = Math.toRadians(lon2 - lon1)

        val y = Math.sin(deltaLambda) * Math.cos(phi2)
        val x = Math.cos(phi1) * Math.sin(phi2) -
                Math.sin(phi1) * Math.cos(phi2) * Math.cos(deltaLambda)
        val theta = Math.atan2(y, x)
        val bearing = (Math.toDegrees(theta) + 360.0) % 360.0
        return bearing.toFloat()
    }

    /**
     * Returns the 8-wind compass direction name (N, NE, E, SE, S, SW, W, NW) and arrow.
     */
    fun getCompassDirectionName(degrees: Float): String {
        val directions = arrayOf("N ↑", "NE ↗", "E →", "SE ↘", "S ↓", "SW ↙", "W ←", "NW ↖", "N ↑")
        val index = Math.round((degrees % 360) / 45.0).toInt()
        return directions[index]
    }

    /**
     * Human-friendly distance formatting ("240 m", "1.8 km").
     */
    fun formatDistance(meters: Double): String {
        return if (meters < 1000) {
            "${meters.toInt()} m"
        } else {
            String.format(Locale.US, "%.1f km", meters / 1000.0)
        }
    }

    /**
     * Formats latitude and longitude to standard GPS coordinate notation.
     */
    fun formatCoordinates(lat: Double, lon: Double): String {
        val latDir = if (lat >= 0) "N" else "S"
        val lonDir = if (lon >= 0) "E" else "W"
        return String.format(Locale.US, "%.4f° %s, %.4f° %s", Math.abs(lat), latDir, Math.abs(lon), lonDir)
    }
}


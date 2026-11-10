package com.relay.emergency.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// ============================================================================
// 1. MATERIAL 3 COLOR SCHEMES (SEPARATE LIGHT & DARK)
// ============================================================================

val RelayDarkColorScheme = darkColorScheme(
    primary = RelayDarkPrimaryAccent,
    onPrimary = RelayDarkBg,
    primaryContainer = Color(0xFF164E63),
    onPrimaryContainer = Color(0xFFCCFBF1),
    secondary = RelayDarkEmergencyAction,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFF7C2D12),
    onSecondaryContainer = Color(0xFFFFEDD5),
    tertiary = RelayDarkSuccess,
    onTertiary = Color.White,
    error = RelayDarkCritical,
    onError = Color.White,
    errorContainer = Color(0xFF7F1D1D),
    onErrorContainer = Color(0xFFFEE2E2),
    background = RelayDarkBg,
    onBackground = RelayDarkTextPrimary,
    surface = RelayDarkCardBg,
    onSurface = RelayDarkTextPrimary,
    surfaceVariant = RelayDarkCardElevated,
    onSurfaceVariant = RelayDarkTextSecondary,
    outline = RelayDarkBorder
)

val RelayLightColorScheme = lightColorScheme(
    primary = RelayLightPrimaryAccent,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFCCFBF1),
    onPrimaryContainer = Color(0xFF134E4A),
    secondary = RelayLightEmergencyAction,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFFFEDD5),
    onSecondaryContainer = Color(0xFF7C2D12),
    tertiary = RelayLightSuccess,
    onTertiary = Color.White,
    error = RelayLightCritical,
    onError = Color.White,
    errorContainer = Color(0xFFFEE2E2),
    onErrorContainer = Color(0xFF7F1D1D),
    background = RelayLightBg,
    onBackground = RelayLightTextPrimary,
    surface = RelayLightCardBg,
    onSurface = RelayLightTextPrimary,
    surfaceVariant = RelayLightCardElevated,
    onSurfaceVariant = RelayLightTextSecondary,
    outline = RelayLightBorder
)

// ============================================================================
// 2. COMPOSITION LOCALS
// ============================================================================

val LocalIsDarkTheme = staticCompositionLocalOf { true }
val LocalThemeMode = staticCompositionLocalOf { ThemeMode.SYSTEM }

// ============================================================================
// 3. THEME-AWARE DYNAMIC COLOR ACCESSORS (FOR SEAMLESS COMPONENT INTEGRATION)
// ============================================================================

val RelayBg: Color
    @Composable
    get() = MaterialTheme.colorScheme.background

val RelayCardBg: Color
    @Composable
    get() = MaterialTheme.colorScheme.surface

val RelayCardElevated: Color
    @Composable
    get() = MaterialTheme.colorScheme.surfaceVariant

val RelayTextPrimary: Color
    @Composable
    get() = MaterialTheme.colorScheme.onBackground

val RelayTextSecondary: Color
    @Composable
    get() = MaterialTheme.colorScheme.onSurfaceVariant

val RelayTextMuted: Color
    @Composable
    get() = if (LocalIsDarkTheme.current) RelayDarkTextMuted else RelayLightTextMuted

val RelayBorder: Color
    @Composable
    get() = MaterialTheme.colorScheme.outline

val RelayPrimaryAccent: Color
    @Composable
    get() = MaterialTheme.colorScheme.primary

val RelayEmergencyAction: Color
    @Composable
    get() = MaterialTheme.colorScheme.secondary

val RelayCritical: Color
    @Composable
    get() = MaterialTheme.colorScheme.error

val RelaySuccess: Color
    @Composable
    get() = MaterialTheme.colorScheme.tertiary

val RelayWarning: Color
    @Composable
    get() = if (LocalIsDarkTheme.current) RelayDarkWarning else RelayLightWarning

// ============================================================================
// 4. MAIN RELAY THEME COMPOSABLE
// ============================================================================

@Composable
fun RELAYTheme(
    themeMode: ThemeMode = ThemeMode.SYSTEM,
    content: @Composable () -> Unit
) {
    val isSystemDark = isSystemInDarkTheme()
    val isDark = when (themeMode) {
        ThemeMode.SYSTEM -> isSystemDark
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }

    val colorScheme = if (isDark) RelayDarkColorScheme else RelayLightColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as? Activity)?.window
            if (window != null) {
                val insetsController = WindowCompat.getInsetsController(window, view)
                insetsController.isAppearanceLightStatusBars = !isDark
                insetsController.isAppearanceLightNavigationBars = !isDark
                window.statusBarColor = colorScheme.background.toArgb()
                window.navigationBarColor = colorScheme.surface.toArgb()
            }
        }
    }

    CompositionLocalProvider(
        LocalIsDarkTheme provides isDark,
        LocalThemeMode provides themeMode
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            content = content
        )
    }
}

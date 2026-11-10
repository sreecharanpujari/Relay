package com.relay.emergency.ui.theme

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

val Context.themeDataStore: DataStore<Preferences> by preferencesDataStore(name = "relay_theme_preferences")

enum class ThemeMode(val title: String, val description: String) {
    SYSTEM("System Default", "Follows device appearance settings"),
    LIGHT("Light Mode", "Clean, high-readability command canvas"),
    DARK("Dark Mode", "High-contrast tactical command center")
}

object ThemePreferences {
    private val THEME_MODE_KEY = stringPreferencesKey("theme_mode")
    private const val PREFS_CACHE_NAME = "relay_theme_fast_cache"
    private const val CACHE_KEY = "cached_theme_mode"

    fun getThemeModeFlow(context: Context): Flow<ThemeMode> {
        return context.themeDataStore.data.map { preferences ->
            val savedValue = preferences[THEME_MODE_KEY] ?: getCachedThemeMode(context).name
            parseThemeMode(savedValue)
        }
    }

    suspend fun setThemeMode(context: Context, mode: ThemeMode) {
        // 1. Synchronously update fast cache so restarts are instantaneous
        context.getSharedPreferences(PREFS_CACHE_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(CACHE_KEY, mode.name)
            .apply()

        // 2. Persist in DataStore Preferences
        context.themeDataStore.edit { preferences ->
            preferences[THEME_MODE_KEY] = mode.name
        }
    }

    fun getCachedThemeMode(context: Context): ThemeMode {
        val sp = context.getSharedPreferences(PREFS_CACHE_NAME, Context.MODE_PRIVATE)
        val value = sp.getString(CACHE_KEY, ThemeMode.SYSTEM.name) ?: ThemeMode.SYSTEM.name
        return parseThemeMode(value)
    }

    private fun parseThemeMode(value: String): ThemeMode {
        return try {
            ThemeMode.valueOf(value)
        } catch (e: Exception) {
            ThemeMode.SYSTEM
        }
    }
}


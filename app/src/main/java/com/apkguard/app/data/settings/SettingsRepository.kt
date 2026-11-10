package com.apkguard.app.data.settings

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "apk_guard_settings")

/** Stores the optional VirusTotal API key. Nothing else is ever persisted. */
class SettingsRepository(private val context: Context) {

    private val vtKey = stringPreferencesKey("virustotal_api_key")

    val virusTotalApiKey: Flow<String> = context.dataStore.data.map { prefs ->
        prefs[vtKey].orEmpty()
    }

    suspend fun setVirusTotalApiKey(value: String) {
        context.dataStore.edit { prefs ->
            val trimmed = value.trim()
            if (trimmed.isEmpty()) prefs.remove(vtKey) else prefs[vtKey] = trimmed
        }
    }
}

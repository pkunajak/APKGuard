package com.apkguard.app.ui.screens

import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.apkguard.app.R
import com.apkguard.app.ui.ScanViewModel

@Composable
fun SettingsScreen(
    vm: ScanViewModel,
    onBack: () -> Unit,
) {
    val savedKey by vm.vtApiKey.collectAsStateWithLifecycle()

    // null until the user edits; the field then shows the working copy.
    var editing by remember { mutableStateOf<String?>(null) }
    var showKey by rememberSaveable { mutableStateOf(false) }
    var saved by rememberSaveable { mutableStateOf(false) }
    val keyValue = editing ?: savedKey

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.cd_back),
                )
            }
            Text(
                stringResource(R.string.settings_title),
                style = MaterialTheme.typography.titleLarge,
            )
        }

        // --- VirusTotal (optional) -------------------------------------
        Text(
            stringResource(R.string.settings_vt_heading),
            style = MaterialTheme.typography.titleMedium,
        )
        OutlinedTextField(
            value = keyValue,
            onValueChange = {
                editing = it
                saved = false
            },
            label = { Text(stringResource(R.string.settings_vt_key_label)) },
            placeholder = { Text(stringResource(R.string.settings_vt_key_hint)) },
            singleLine = true,
            visualTransformation = if (showKey) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { showKey = !showKey }) {
                    Icon(
                        imageVector = if (showKey) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = stringResource(R.string.cd_show_password),
                    )
                }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Button(
                onClick = {
                    vm.saveVirusTotalApiKey(keyValue)
                    editing = keyValue.trim()
                    saved = true
                },
            ) { Text(stringResource(R.string.settings_vt_key_save)) }
            if (saved) {
                Text(
                    stringResource(R.string.settings_vt_key_saved),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
        Text(
            stringResource(R.string.settings_vt_howto),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        // --- Language --------------------------------------------------
        Text(
            stringResource(R.string.settings_language_heading),
            style = MaterialTheme.typography.titleMedium,
        )
        val appLocales = AppCompatDelegate.getApplicationLocales()
        val currentTag = appLocales.toLanguageTags()
        RadioRow(
            label = stringResource(R.string.lang_system),
            selected = appLocales.isEmpty,
        ) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
        }
        RadioRow(
            label = stringResource(R.string.lang_th),
            selected = currentTag.startsWith("th"),
        ) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("th"))
        }
        RadioRow(
            label = stringResource(R.string.lang_en),
            selected = currentTag.startsWith("en"),
        ) {
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("en"))
        }

        // --- Privacy ---------------------------------------------------
        Text(
            stringResource(R.string.settings_privacy_heading),
            style = MaterialTheme.typography.titleMedium,
        )
        Text(
            stringResource(R.string.settings_privacy_body),
            style = MaterialTheme.typography.bodySmall,
        )
        Spacer(Modifier.size(24.dp))
    }
}

@Composable
private fun RadioRow(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(label)
    }
}

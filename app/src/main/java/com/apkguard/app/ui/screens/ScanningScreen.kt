package com.apkguard.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.apkguard.app.R
import com.apkguard.app.domain.model.ScanStage
import com.apkguard.app.ui.ScanViewModel
import com.apkguard.app.ui.ScanViewModel.ScanState

@Composable
fun ScanningScreen(
    vm: ScanViewModel,
    onDone: () -> Unit,
    onAbort: () -> Unit,
) {
    val state by vm.scanState.collectAsStateWithLifecycle()

    when (val s = state) {
        ScanState.Idle -> LaunchedEffect(Unit) { onAbort() }

        is ScanState.Scanning -> Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(32.dp),
            verticalArrangement = Arrangement.Center,
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            CircularProgressIndicator(modifier = Modifier.size(64.dp))
            Spacer(Modifier.size(24.dp))
            Text(
                stringResource(R.string.scanning_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Spacer(Modifier.size(8.dp))
            Text(
                stringResource(stageRes(s.stage)),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        is ScanState.Done -> LaunchedEffect(Unit) { onDone() }

        is ScanState.Error -> AlertDialog(
            onDismissRequest = onAbort,
            title = { Text(stringResource(R.string.app_name)) },
            text = { Text(stringResource(messageRes(s.code))) },
            confirmButton = {
                TextButton(onClick = onAbort) {
                    Text(stringResource(android.R.string.ok))
                }
            },
        )
    }
}

private fun stageRes(stage: ScanStage): Int = when (stage) {
    ScanStage.PREPARING -> R.string.stage_preparing
    ScanStage.COPYING -> R.string.stage_copying
    ScanStage.PARSING -> R.string.stage_parsing
    ScanStage.PERMISSIONS -> R.string.stage_permissions
    ScanStage.SIGNATURE -> R.string.stage_signature
    ScanStage.STRINGS -> R.string.stage_strings
    ScanStage.FINALIZING -> R.string.stage_finalizing
}

private fun messageRes(code: ScanViewModel.MessageCode): Int = when (code) {
    ScanViewModel.MessageCode.NOT_APK -> R.string.error_not_apk
    ScanViewModel.MessageCode.CORRUPT -> R.string.error_corrupt
    ScanViewModel.MessageCode.NOT_FOUND -> R.string.error_not_found
    ScanViewModel.MessageCode.GENERIC -> R.string.error_generic
}

package com.apkguard.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.apkguard.app.R
import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.RiskLevel
import com.apkguard.app.domain.model.ScanReport
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.Verdict
import com.apkguard.app.domain.model.VtSummary
import com.apkguard.app.ui.ScanViewModel
import com.apkguard.app.ui.isThaiNow
import com.apkguard.app.ui.localized
import com.apkguard.app.ui.theme.color
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun ResultScreen(
    vm: ScanViewModel,
    onScanAgain: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val state by vm.scanState.collectAsStateWithLifecycle()
    val report = (state as? ScanViewModel.ScanState.Done)?.report
    if (report == null) {
        LaunchedEffectOnce { onScanAgain() }
        return
    }

    val isThai = isThaiNow()
    val vtState by vm.vtState.collectAsStateWithLifecycle()
    val vtKey by vm.vtApiKey.collectAsStateWithLifecycle()

    if (vtState is ScanViewModel.VtUiState.AwaitingUploadConsent) {
        AlertDialog(
            onDismissRequest = { vm.dismissVtUpload() },
            title = { Text(stringResource(R.string.vt_not_found_title)) },
            text = { Text(stringResource(R.string.vt_not_found_msg)) },
            confirmButton = {
                TextButton(onClick = { vm.confirmVtUpload() }) {
                    Text(stringResource(R.string.vt_upload_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { vm.dismissVtUpload() }) {
                    Text(stringResource(R.string.vt_cancel))
                }
            },
        )
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        VerdictHeader(report)
        SummarySection(report)
        VtSection(vm, report, vtState, hasKey = vtKey.isNotBlank(), onOpenSettings = onOpenSettings)
        PermissionsSection(report)
        SignatureSection(report)
        AppInfoSection(report)
        StringsSection(report)

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            OutlinedButton(
                onClick = { vm.shareText(isThai) },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.share_text)) }
            OutlinedButton(
                onClick = { vm.shareImage(isThai) },
                modifier = Modifier.weight(1f),
            ) { Text(stringResource(R.string.share_image)) }
        }
        Button(
            onClick = {
                vm.reset()
                onScanAgain()
            },
            modifier = Modifier.fillMaxWidth(),
        ) { Text(stringResource(R.string.scan_again)) }
        Spacer(Modifier.size(12.dp))
    }
}

/** Fires exactly once per composition lifetime; survives recomposition. */
@Composable
private fun LaunchedEffectOnce(action: suspend () -> Unit) {
    androidx.compose.runtime.LaunchedEffect(Unit) { action() }
}

// ---------------------------------------------------------------- header

@Composable
private fun VerdictHeader(report: ScanReport) {
    Card(
        colors = CardDefaults.cardColors(containerColor = report.verdict.color),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                text = report.identity.appName ?: report.identity.packageName ?: "?",
                style = MaterialTheme.typography.titleMedium,
                color = Color.White.copy(alpha = 0.92f),
            )
            Spacer(Modifier.size(8.dp))
            Text(
                text = stringResource(verdictRes(report.verdict)),
                fontSize = 44.sp,
                fontWeight = FontWeight.Black,
                color = Color.White,
            )
            Spacer(Modifier.size(4.dp))
            Text(
                text = "${report.score}/100 · " + stringResource(R.string.risk_score),
                style = MaterialTheme.typography.titleSmall,
                color = Color.White.copy(alpha = 0.85f),
            )
        }
    }
}

private fun verdictRes(verdict: Verdict): Int = when (verdict) {
    Verdict.SAFE -> R.string.verdict_safe
    Verdict.SUSPICIOUS -> R.string.verdict_suspicious
    Verdict.DANGEROUS -> R.string.verdict_dangerous
}

// ---------------------------------------------------------------- summary

@Composable
private fun SummarySection(report: ScanReport) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                stringResource(R.string.result_summary_title),
                style = MaterialTheme.typography.titleMedium,
            )
            val notable = report.findings.filter { it.severity != Severity.INFO }
            if (notable.isEmpty()) {
                Text(
                    stringResource(R.string.no_findings),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                )
            } else {
                notable.take(8).forEach { FindingRow(it) }
                val rest = notable.size - 8
                if (rest > 0) {
                    Text(
                        stringResource(R.string.more_findings, rest),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun FindingRow(finding: Finding) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            modifier = Modifier
                .padding(top = 6.dp)
                .size(10.dp)
                .clip(CircleShape)
                .background(severityColor(finding.severity)),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                finding.title.localized(),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                finding.detail.localized(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun severityColor(severity: Severity): Color = when (severity) {
    Severity.CRITICAL, Severity.HIGH -> Color(0xFFC62828)
    Severity.MEDIUM -> Color(0xFFEF6C00)
    Severity.LOW -> Color(0xFF1565C0)
    Severity.INFO -> Color(0xFF757575)
}

// ---------------------------------------------------------------- VirusTotal

@Composable
private fun VtSection(
    vm: ScanViewModel,
    report: ScanReport,
    vtState: ScanViewModel.VtUiState,
    hasKey: Boolean,
    onOpenSettings: () -> Unit,
) {
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(
                stringResource(R.string.vt_section_title),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                stringResource(R.string.vt_section_desc),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (vtState) {
                ScanViewModel.VtUiState.Running -> Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp,
                    )
                    Text(stringResource(R.string.vt_running))
                }

                is ScanViewModel.VtUiState.Error -> Column(
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        stringResource(vtErrorRes(vtState.code)),
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = { vm.startVtScan() }) {
                        Text(stringResource(R.string.vt_button_scan))
                    }
                }

                else -> {
                    val vt = report.vt
                    when {
                        vt != null -> VtResultContent(vt)
                        !hasKey -> {
                            Text(
                                stringResource(R.string.vt_need_key),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            TextButton(onClick = onOpenSettings) {
                                Text(stringResource(R.string.vt_go_settings))
                            }
                        }
                        else -> Button(
                            onClick = { vm.startVtScan() },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(stringResource(R.string.vt_button_scan)) }
                    }
                }
            }
        }
    }
}

@Composable
private fun VtResultContent(vt: VtSummary) {
    val flagged = vt.malicious + vt.suspicious
    Text(
        stringResource(R.string.vt_detections, vt.malicious, vt.totalEngines),
        fontWeight = FontWeight.Bold,
        color = if (flagged > 0) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
    )
    vt.threatLabel?.let { LabelValue(stringResource(R.string.vt_threat_label), it) }
    vt.reputation?.let { LabelValue(stringResource(R.string.vt_reputation), it.toString()) }
    if (vt.flaggedEngines.isNotEmpty()) {
        Text(
            stringResource(R.string.vt_engines_flagged),
            style = MaterialTheme.typography.titleSmall,
        )
        Text(
            vt.flaggedEngines.take(12).joinToString(", "),
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

private fun vtErrorRes(code: ScanViewModel.VtErrorCode): Int = when (code) {
    ScanViewModel.VtErrorCode.RATE_LIMIT -> R.string.vt_error_rate_limit
    ScanViewModel.VtErrorCode.INVALID_KEY -> R.string.vt_error_invalid_key
    ScanViewModel.VtErrorCode.NETWORK -> R.string.vt_error_network
    ScanViewModel.VtErrorCode.TOO_LARGE -> R.string.vt_error_too_large
    ScanViewModel.VtErrorCode.PROCESSING -> R.string.vt_processing
    ScanViewModel.VtErrorCode.CANNOT_UPLOAD -> R.string.vt_error_cannot_upload
}

// ---------------------------------------------------------------- sections

@Composable
private fun ExpandableSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    var expanded by rememberSaveable { mutableStateOf(false) }
    OutlinedCard(modifier = Modifier.fillMaxWidth()) {
        Column {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { expanded = !expanded }
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    title,
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                )
                Icon(
                    imageVector = if (expanded) Icons.Filled.KeyboardArrowUp else Icons.Filled.KeyboardArrowDown,
                    contentDescription = null,
                )
            }
            if (expanded) {
                Column(
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                    content = content,
                )
            }
        }
    }
}

@Composable
private fun PermissionsSection(report: ScanReport) {
    if (report.permissions.isEmpty()) return
    ExpandableSection(title = stringResource(R.string.section_permissions, report.permissions.size)) {
        listOf(
            Triple(RiskLevel.DANGEROUS, stringResource(R.string.perm_risk_dangerous), Color(0xFFC62828)),
            Triple(RiskLevel.NOTEWORTHY, stringResource(R.string.perm_risk_noteworthy), Color(0xFFEF6C00)),
            Triple(RiskLevel.SAFE, stringResource(R.string.perm_risk_safe), Color(0xFF2E7D32)),
        ).forEach { (level, label, color) ->
            val items = report.permissions.filter { it.risk == level }
            if (items.isNotEmpty()) {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        "$label (${items.size})",
                        style = MaterialTheme.typography.titleSmall,
                        color = color,
                    )
                    items.forEach { perm ->
                        Column {
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(
                                    perm.name.substringAfterLast('.'),
                                    style = MaterialTheme.typography.bodyMedium,
                                    fontWeight = FontWeight.SemiBold,
                                )
                                if (perm.granted == true) {
                                    Text(
                                        "· " + stringResource(R.string.perm_granted),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                }
                            }
                            Text(
                                perm.description.localized(),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun SignatureSection(report: ScanReport) {
    ExpandableSection(title = stringResource(R.string.section_signature)) {
        val sig = report.signature
        if (sig == null) {
            Text(stringResource(R.string.sig_missing))
            return@ExpandableSection
        }
        val schemes = listOf(
            "v1" to sig.hasV1,
            "v2" to sig.hasV2,
            "v3" to sig.hasV3,
        ).joinToString("   ") { "${it.first} ${if (it.second) "✓" else "✗"}" }
        Text(
            stringResource(R.string.sig_scheme_template, schemes),
            style = MaterialTheme.typography.bodyMedium,
        )
        if (sig.certificates.isEmpty() && !sig.hasV2 && !sig.hasV3) {
            Text(
                stringResource(R.string.sig_missing),
                color = MaterialTheme.colorScheme.error,
            )
        }
        val dateFormat = remember {
            SimpleDateFormat.getDateInstance(SimpleDateFormat.MEDIUM, Locale.getDefault())
        }
        sig.certificates.forEach { cert ->
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                LabelValue("Subject", cert.subject)
                LabelValue("Issuer", cert.issuer)
                cert.notAfterMs?.let { LabelValue("Valid until", dateFormat.format(Date(it))) }
                if (cert.isDebug) {
                    Text(
                        "⚠ debug certificate",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                cert.sha256?.let { LabelValue("SHA-256", it.take(32) + "…") }
            }
        }
    }
}

@Composable
private fun AppInfoSection(report: ScanReport) {
    ExpandableSection(title = stringResource(R.string.section_app_info)) {
        report.identity.versionName?.let { LabelValue(stringResource(R.string.app_info_version), it) }
        report.identity.packageName?.let { LabelValue(stringResource(R.string.app_info_package), it) }
        report.identity.targetSdk?.let { LabelValue(stringResource(R.string.app_info_target_sdk), it.toString()) }
        report.identity.minSdk?.let { LabelValue(stringResource(R.string.app_info_min_sdk), it.toString()) }
        if (report.identity.isInstalledApp) {
            LabelValue(
                stringResource(R.string.app_info_installer),
                installerText(report.identity.installerPackage),
            )
        }
        report.sha256?.let { LabelValue(stringResource(R.string.vt_hash), it) }
    }
}

@Composable
private fun installerText(installer: String?): String = when (installer) {
    "com.android.vending" -> stringResource(R.string.installer_play)
    null -> stringResource(R.string.installer_sideloaded)
    else -> "${stringResource(R.string.installer_unknown)} ($installer)"
}

@Composable
private fun StringsSection(report: ScanReport) {
    val s = report.stringsScan ?: return
    ExpandableSection(title = stringResource(R.string.section_strings)) {
        if (s.urls.isEmpty() && s.rawIps.isEmpty() && s.keywordHits.isEmpty()) {
            Text(stringResource(R.string.strings_none))
        } else {
            if (s.urls.isNotEmpty()) {
                Text(
                    stringResource(R.string.strings_urls_found, s.urls.size),
                    style = MaterialTheme.typography.titleSmall,
                )
                s.urls.take(10).forEach {
                    Text(it, style = MaterialTheme.typography.bodySmall)
                }
            }
            if (s.rawIps.isNotEmpty()) {
                Text(
                    stringResource(R.string.strings_ips_found, s.rawIps.size),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    s.rawIps.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (s.keywordHits.isNotEmpty()) {
                Text(
                    s.keywordHits.joinToString(", "),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun LabelValue(label: String, value: String) {
    Column {
        Text(
            label.uppercase(),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}

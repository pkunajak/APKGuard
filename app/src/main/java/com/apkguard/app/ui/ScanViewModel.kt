package com.apkguard.app.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.apkguard.app.data.apk.ApkFileParser
import com.apkguard.app.data.installed.InstalledAppProvider
import com.apkguard.app.data.settings.SettingsRepository
import com.apkguard.app.data.share.ReportShareManager
import com.apkguard.app.data.vt.VirusTotalRepository
import com.apkguard.app.data.vt.VtException
import com.apkguard.app.domain.model.AppIdentity
import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.PermissionInfo
import com.apkguard.app.domain.model.ScanReport
import com.apkguard.app.domain.model.ScanStage
import com.apkguard.app.domain.model.SignatureInfo
import com.apkguard.app.domain.model.StringsScanResult
import com.apkguard.app.domain.model.VtSummary
import com.apkguard.app.domain.scanner.ApkStaticAnalyzer
import com.apkguard.app.domain.scanner.PermissionRiskCatalog
import com.apkguard.app.domain.scanner.ScoringEngine
import com.apkguard.app.domain.scanner.VtSeverityMapper
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Orchestrates scans. Results live in memory only — nothing is persisted,
 * matching the privacy promise (no scan history).
 */
class ScanViewModel(app: Application) : AndroidViewModel(app) {

    sealed interface ScanState {
        data object Idle : ScanState
        data class Scanning(val stage: ScanStage) : ScanState
        data class Error(val code: MessageCode) : ScanState
        data class Done(val report: ScanReport) : ScanState
    }

    enum class MessageCode { NOT_APK, CORRUPT, NOT_FOUND, GENERIC }

    sealed interface VtUiState {
        data object Idle : VtUiState
        data object Running : VtUiState
        data object AwaitingUploadConsent : VtUiState
        data class Done(val summary: VtSummary) : VtUiState
        data class Error(val code: VtErrorCode) : VtUiState
    }

    enum class VtErrorCode { RATE_LIMIT, INVALID_KEY, NETWORK, TOO_LARGE, PROCESSING, CANNOT_UPLOAD }

    private val apkParser = ApkFileParser()
    private val installedProvider = InstalledAppProvider(app)
    private val vtRepository = VirusTotalRepository()
    private val shareManager = ReportShareManager(app)

    val settingsRepository = SettingsRepository(app)

    val vtApiKey: StateFlow<String> = settingsRepository.virusTotalApiKey
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "")

    private val _scanState = MutableStateFlow<ScanState>(ScanState.Idle)
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    private val _vtState = MutableStateFlow<VtUiState>(VtUiState.Idle)
    val vtState: StateFlow<VtUiState> = _vtState.asStateFlow()

    /**
     * The APK of the last scan, kept in cache so VirusTotal can upload it if —
     * and only if — the user consents. Overwritten by the next scan.
     */
    var lastScanFile: File? = null
        private set

    // ------------------------------------------------------------ scans

    fun scanApkFile(uri: Uri) {
        if (_scanState.value is ScanState.Scanning) return
        viewModelScope.launch {
            try {
                val displayName = queryDisplayName(uri)
                if (displayName != null && !displayName.endsWith(".apk", ignoreCase = true)) {
                    _scanState.value = ScanState.Error(MessageCode.NOT_APK)
                    return@launch
                }

                _scanState.value = ScanState.Scanning(ScanStage.COPYING)
                val tempFile = withContext(Dispatchers.IO) {
                    val target = File(getApplication<Application>().cacheDir, TEMP_SCAN_FILE)
                    getApplication<Application>().contentResolver.openInputStream(uri)?.use { ins ->
                        target.outputStream().use { out -> ins.copyTo(out) }
                    } ?: throw IllegalStateException("cannot open input stream")
                    target
                }
                runFileScan(tempFile)
            } catch (_: Exception) {
                _scanState.value = ScanState.Error(MessageCode.CORRUPT)
            }
        }
    }

    fun scanInstalledApp(packageName: String) {
        if (_scanState.value is ScanState.Scanning) return
        viewModelScope.launch {
            try {
                _scanState.value = ScanState.Scanning(ScanStage.PARSING)
                withContext(Dispatchers.IO) {
                    val deep = installedProvider.deepInfo(packageName) ?: throw NotFound()

                    _scanState.value = ScanState.Scanning(ScanStage.PERMISSIONS)
                    val grantedMap = deep.permissions.associateWith { it in deep.grantedPermissions }
                    val permissions = PermissionRiskCatalog.toPermissionInfos(deep.permissions, grantedMap)

                    // Deep static pass only when the APK file itself is readable;
                    // otherwise we gracefully fall back to metadata-only analysis.
                    var strings: StringsScanResult? = null
                    var dexCount: Int? = null
                    var sha256: String? = null
                    val apkFile = deep.apkFile
                    if (apkFile != null) {
                        _scanState.value = ScanState.Scanning(ScanStage.STRINGS)
                        strings = apkParser.scanStrings(apkFile)
                        dexCount = apkParser.countDexFiles(apkFile)
                        sha256 = apkParser.sha256(apkFile)
                    }

                    _scanState.value = ScanState.Scanning(ScanStage.FINALIZING)
                    val findings = ApkStaticAnalyzer.analyze(
                        ApkStaticAnalyzer.Input(
                            identity = deep.identity,
                            permissions = permissions,
                            signature = deep.signature,
                            strings = strings,
                            dexCount = dexCount,
                            appFlags = deep.flags,
                            declaresAccessibilityService = deep.declaresAccessibilityService,
                            declaresNotificationListenerService = deep.declaresNotificationListenerService,
                        ),
                    )
                    publishReport(deep.identity, sha256, permissions, deep.signature, strings, dexCount, findings)
                    lastScanFile = apkFile
                }
            } catch (e: NotFound) {
                _scanState.value = ScanState.Error(MessageCode.NOT_FOUND)
            } catch (_: Exception) {
                _scanState.value = ScanState.Error(MessageCode.GENERIC)
            }
        }
    }

    private suspend fun runFileScan(file: File) {
        try {
            withContext(Dispatchers.IO) {
                _scanState.value = ScanState.Scanning(ScanStage.PARSING)
                val manifest = apkParser.parseManifest(file)

                _scanState.value = ScanState.Scanning(ScanStage.PERMISSIONS)
                val permissions = PermissionRiskCatalog.toPermissionInfos(manifest.permissions)

                _scanState.value = ScanState.Scanning(ScanStage.SIGNATURE)
                val signature = apkParser.readSignature(file)

                _scanState.value = ScanState.Scanning(ScanStage.STRINGS)
                val strings = apkParser.scanStrings(file)
                val dexCount = apkParser.countDexFiles(file)
                val sha256 = apkParser.sha256(file)

                _scanState.value = ScanState.Scanning(ScanStage.FINALIZING)
                val identity = AppIdentity(
                    appName = manifest.label ?: manifest.packageName,
                    packageName = manifest.packageName,
                    versionName = manifest.versionName,
                    versionCode = manifest.versionCode,
                    minSdk = manifest.minSdk,
                    targetSdk = manifest.targetSdk,
                    installerPackage = null,
                    firstInstallTimeMs = null,
                    isInstalledApp = false,
                )
                val findings = ApkStaticAnalyzer.analyze(
                    ApkStaticAnalyzer.Input(
                        identity = identity,
                        permissions = permissions,
                        signature = signature,
                        strings = strings,
                        dexCount = dexCount,
                    ),
                )
                publishReport(identity, sha256, permissions, signature, strings, dexCount, findings)
                lastScanFile = file
            }
        } catch (_: ApkFileParser.ApkParseException) {
            _scanState.value = ScanState.Error(MessageCode.CORRUPT)
        } catch (_: Exception) {
            _scanState.value = ScanState.Error(MessageCode.GENERIC)
        }
    }

    private fun publishReport(
        identity: AppIdentity,
        sha256: String?,
        permissions: List<PermissionInfo>,
        signature: SignatureInfo?,
        strings: StringsScanResult?,
        dexCount: Int?,
        findings: List<Finding>,
    ) {
        val score = ScoringEngine.score(findings)
        _vtState.value = VtUiState.Idle
        _scanState.value = ScanState.Done(
            ScanReport(
                identity = identity,
                sha256 = sha256,
                permissions = permissions,
                signature = signature,
                stringsScan = strings,
                dexCount = dexCount,
                findings = findings,
                score = score,
                verdict = ScoringEngine.verdict(score),
                vt = null,
                scannedAtMs = System.currentTimeMillis(),
            ),
        )
    }

    private class NotFound : Exception()

    private fun queryDisplayName(uri: Uri): String? = try {
        getApplication<Application>().contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
    } catch (_: Exception) {
        null
    }

    // ------------------------------------------------------------ VirusTotal

    /** Hash-first lookup. Falls back to an upload-consent dialog when unknown. */
    fun startVtScan() {
        val report = (_scanState.value as? ScanState.Done)?.report ?: return
        val apiKey = vtApiKey.value
        if (apiKey.isBlank() || _vtState.value is VtUiState.Running) return

        viewModelScope.launch {
            _vtState.value = VtUiState.Running
            try {
                val summary = report.sha256?.let { sha ->
                    withContext(Dispatchers.IO) { vtRepository.lookupByHash(sha, apiKey) }
                }
                when {
                    summary != null -> applyVtResult(summary)
                    lastScanFile?.exists() == true -> _vtState.value = VtUiState.AwaitingUploadConsent
                    else -> _vtState.value = VtUiState.Error(VtErrorCode.CANNOT_UPLOAD)
                }
            } catch (e: VtException) {
                _vtState.value = VtUiState.Error(e.toErrorCode())
            } catch (_: Exception) {
                _vtState.value = VtUiState.Error(VtErrorCode.NETWORK)
            }
        }
    }

    fun confirmVtUpload() {
        val report = (_scanState.value as? ScanState.Done)?.report ?: return
        val apiKey = vtApiKey.value
        val file = lastScanFile?.takeIf { it.exists() }
        val sha256 = report.sha256
        if (apiKey.isBlank() || _vtState.value is VtUiState.Running) return
        if (file == null || sha256 == null) {
            _vtState.value = VtUiState.Error(VtErrorCode.CANNOT_UPLOAD)
            return
        }

        viewModelScope.launch {
            _vtState.value = VtUiState.Running
            try {
                val summary = withContext(Dispatchers.IO) {
                    vtRepository.uploadAndScan(file, sha256, apiKey)
                }
                if (summary != null) applyVtResult(summary)
                else _vtState.value = VtUiState.Error(VtErrorCode.PROCESSING)
            } catch (e: VtException) {
                _vtState.value = VtUiState.Error(e.toErrorCode())
            } catch (_: Exception) {
                _vtState.value = VtUiState.Error(VtErrorCode.NETWORK)
            }
        }
    }

    fun dismissVtUpload() {
        if (_vtState.value is VtUiState.AwaitingUploadConsent) _vtState.value = VtUiState.Idle
    }

    private fun applyVtResult(summary: VtSummary) {
        val done = _scanState.value as? ScanState.Done ?: return
        val vtFinding = VtSeverityMapper.findingFor(summary)
        val findings = done.report.findings.filterNot { it.id == vtFinding.id } + vtFinding
        val score = ScoringEngine.score(findings)
        _scanState.value = ScanState.Done(
            done.report.copy(
                findings = findings,
                score = score,
                verdict = ScoringEngine.verdict(score),
                vt = summary,
            ),
        )
        _vtState.value = VtUiState.Done(summary)
    }

    private fun VtException.toErrorCode(): VtErrorCode = when (this) {
        is VtException.RateLimited -> VtErrorCode.RATE_LIMIT
        is VtException.InvalidKey -> VtErrorCode.INVALID_KEY
        is VtException.TooLarge -> VtErrorCode.TOO_LARGE
        is VtException.Processing -> VtErrorCode.PROCESSING
        else -> VtErrorCode.NETWORK
    }

    // ------------------------------------------------------------ misc

    fun loadInstalledApps(includeSystem: Boolean) = flow {
        emit(withContext(Dispatchers.IO) { installedProvider.list(includeSystem) })
    }

    fun saveVirusTotalApiKey(value: String) {
        viewModelScope.launch { settingsRepository.setVirusTotalApiKey(value) }
    }

    fun shareText(isThai: Boolean) {
        val report = (_scanState.value as? ScanState.Done)?.report ?: return
        shareManager.shareText(report, isThai)
    }

    fun shareImage(isThai: Boolean) {
        val report = (_scanState.value as? ScanState.Done)?.report ?: return
        shareManager.shareImage(report, isThai)
    }

    fun reset() {
        _scanState.value = ScanState.Idle
        _vtState.value = VtUiState.Idle
    }

    private companion object {
        const val TEMP_SCAN_FILE = "scan_cache.apk"
    }
}

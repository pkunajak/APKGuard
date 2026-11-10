package com.apkguard.app.domain.model

/** Risk classification of a single Android permission. */
enum class RiskLevel { SAFE, NOTEWORTHY, DANGEROUS }

/** Severity of a finding; [weight] is what the scoring engine sums. */
enum class Severity(val weight: Int) {
    INFO(0),
    LOW(4),
    MEDIUM(10),
    HIGH(18),
    CRITICAL(30),
}

enum class FindingCategory { PERMISSION, SIGNATURE, MANIFEST, STRINGS, METADATA, VIRUSTOTAL }

enum class Verdict { SAFE, SUSPICIOUS, DANGEROUS }

/**
 * Text with both locales baked in. The domain layer has no access to Android string
 * resources, so catalog-provided copy lives here and the UI resolves it at render time.
 */
data class LocalizedText(val th: String, val en: String) {
    fun resolve(isThai: Boolean): String = if (isThai) th else en
}

data class Finding(
    val id: String,
    val category: FindingCategory,
    val severity: Severity,
    val title: LocalizedText,
    val detail: LocalizedText,
)

data class PermissionInfo(
    val name: String,
    val risk: RiskLevel,
    val severity: Severity,
    val description: LocalizedText,
    /** Only known when scanning installed apps; null for plain .apk files. */
    val granted: Boolean? = null,
)

data class CertificateInfo(
    val subject: String,
    val issuer: String,
    val notBeforeMs: Long?,
    val notAfterMs: Long?,
    val isDebug: Boolean,
    val sha256: String?,
)

data class SignatureInfo(
    val hasV1: Boolean,
    val hasV2: Boolean,
    val hasV3: Boolean,
    val certificates: List<CertificateInfo>,
)

data class StringsScanResult(
    val urls: List<String>,
    val rawIps: List<String>,
    val keywordHits: List<String>,
) {
    val rootToolHits: List<String>
        get() = keywordHits.filter {
            it.contains("su") || it.contains("magisk") || it.contains("chmod")
        }
    val hasDexClassLoader: Boolean get() = keywordHits.any { it.contains("DexClassLoader") }
}

data class AppIdentity(
    val appName: String?,
    val packageName: String?,
    val versionName: String?,
    val versionCode: Long?,
    val minSdk: Int?,
    val targetSdk: Int?,
    val installerPackage: String?,
    val firstInstallTimeMs: Long?,
    val isInstalledApp: Boolean,
)

/** Only available when scanning installed apps (from ApplicationInfo flags). */
data class AppFlags(
    val debuggable: Boolean?,
    val allowBackup: Boolean?,
)

data class VtSummary(
    val malicious: Int,
    val suspicious: Int,
    val undetected: Int,
    val harmless: Int,
    val timeout: Int,
    val totalEngines: Int,
    val reputation: Long?,
    val threatLabel: String?,
    val flaggedEngines: List<String>,
)

data class ScanReport(
    val identity: AppIdentity,
    val sha256: String?,
    val permissions: List<PermissionInfo>,
    val signature: SignatureInfo?,
    val stringsScan: StringsScanResult?,
    val dexCount: Int?,
    val findings: List<Finding>,
    val score: Int,
    val verdict: Verdict,
    val vt: VtSummary? = null,
    val scannedAtMs: Long,
)

/** Progress stages surfaced to the UI while a scan runs. */
enum class ScanStage { PREPARING, COPYING, PARSING, PERMISSIONS, SIGNATURE, STRINGS, FINALIZING }

package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.AppFlags
import com.apkguard.app.domain.model.AppIdentity
import com.apkguard.app.domain.model.CertificateInfo
import com.apkguard.app.domain.model.PermissionInfo
import com.apkguard.app.domain.model.RiskLevel
import com.apkguard.app.domain.model.SignatureInfo
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.StringsScanResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ApkStaticAnalyzerTest {

    private val dayMs = 24L * 60 * 60 * 1000

    private fun identity(
        targetSdk: Int? = null,
        isInstalledApp: Boolean = false,
        installer: String? = null,
    ) = AppIdentity(
        appName = "Test App",
        packageName = "com.example.test",
        versionName = "1.0",
        versionCode = 1L,
        minSdk = 26,
        targetSdk = targetSdk,
        installerPackage = installer,
        firstInstallTimeMs = null,
        isInstalledApp = isInstalledApp,
    )

    private fun perm(name: String, severity: Severity, risk: RiskLevel = RiskLevel.DANGEROUS) =
        PermissionInfo(
            name = name,
            risk = risk,
            severity = severity,
            description = com.apkguard.app.domain.model.LocalizedText("th", "en"),
        )

    private fun input(
        permissions: List<PermissionInfo> = emptyList(),
        signature: SignatureInfo? = null,
        identity: AppIdentity = identity(),
        strings: StringsScanResult? = null,
        dexCount: Int? = null,
        flags: AppFlags? = null,
        accessibility: Boolean = false,
        notificationListener: Boolean = false,
        nowMs: Long = System.currentTimeMillis(),
    ) = ApkStaticAnalyzer.Input(
        identity = identity,
        permissions = permissions,
        signature = signature,
        strings = strings,
        dexCount = dexCount,
        appFlags = flags,
        declaresAccessibilityService = accessibility,
        declaresNotificationListenerService = notificationListener,
        nowMs = nowMs,
    )

    private fun validCert(isDebug: Boolean = false, expired: Boolean = false, nowMs: Long) =
        CertificateInfo(
            subject = if (isDebug) "CN=Android Debug, O=Android, C=US" else "CN=Example Ltd",
            issuer = "CN=Example Ltd",
            notBeforeMs = nowMs - 10 * dayMs,
            notAfterMs = if (expired) nowMs - dayMs else nowMs + 365 * dayMs,
            isDebug = isDebug,
            sha256 = "ab",
        )

    @Test
    fun `clean app produces no findings`() {
        val findings = ApkStaticAnalyzer.analyze(input())
        assertTrue(findings.isEmpty())
        assertEquals(0, ScoringEngine.score(findings))
    }

    @Test
    fun `sms plus contacts plus location triggers spyware combo`() {
        val findings = ApkStaticAnalyzer.analyze(
            input(
                permissions = listOf(
                    perm("android.permission.RECEIVE_SMS", Severity.HIGH),
                    perm("android.permission.READ_CONTACTS", Severity.HIGH),
                    perm("android.permission.ACCESS_FINE_LOCATION", Severity.MEDIUM, RiskLevel.NOTEWORTHY),
                ),
            ),
        )
        val combo = findings.first { it.id == "combo:spyware" }
        assertEquals(Severity.CRITICAL, combo.severity)
    }

    @Test
    fun `install-packages plus overlay triggers dropper combo`() {
        val findings = ApkStaticAnalyzer.analyze(
            input(
                permissions = listOf(
                    perm("android.permission.REQUEST_INSTALL_PACKAGES", Severity.HIGH),
                    perm("android.permission.SYSTEM_ALERT_WINDOW", Severity.MEDIUM),
                ),
            ),
        )
        assertEquals(Severity.HIGH, findings.first { it.id == "combo:dropper" }.severity)
    }

    @Test
    fun `debug certificate is flagged HIGH`() {
        val now = System.currentTimeMillis()
        val findings = ApkStaticAnalyzer.analyze(
            input(
                signature = SignatureInfo(
                    hasV1 = true, hasV2 = true, hasV3 = true,
                    certificates = listOf(validCert(isDebug = true, nowMs = now)),
                ),
                nowMs = now,
            ),
        )
        assertEquals(Severity.HIGH, findings.first { it.id == "sig:debug" }.severity)
    }

    @Test
    fun `unsigned apk is CRITICAL`() {
        val findings = ApkStaticAnalyzer.analyze(
            input(signature = SignatureInfo(false, false, false, emptyList())),
        )
        assertEquals(Severity.CRITICAL, findings.first { it.id == "sig:missing" }.severity)
    }

    @Test
    fun `v1-only signing is MEDIUM`() {
        val now = System.currentTimeMillis()
        val findings = ApkStaticAnalyzer.analyze(
            input(
                signature = SignatureInfo(
                    hasV1 = true, hasV2 = false, hasV3 = false,
                    certificates = listOf(validCert(nowMs = now)),
                ),
                nowMs = now,
            ),
        )
        assertEquals(Severity.MEDIUM, findings.first { it.id == "sig:v1only" }.severity)
    }

    @Test
    fun `ancient targetSdk is flagged`() {
        assertEquals(
            Severity.MEDIUM,
            ApkStaticAnalyzer.analyze(input(identity = identity(targetSdk = 21)))
                .first { it.id == "manifest:target_sdk_ancient" }
                .severity,
        )
        assertEquals(
            Severity.LOW,
            ApkStaticAnalyzer.analyze(input(identity = identity(targetSdk = 24)))
                .first { it.id == "manifest:target_sdk_old" }
                .severity,
        )
        assertTrue(
            ApkStaticAnalyzer.analyze(input(identity = identity(targetSdk = 33)))
                .none { it.id.startsWith("manifest:target_sdk") },
        )
    }

    @Test
    fun `debuggable and allowBackup flags map to findings`() {
        val findings = ApkStaticAnalyzer.analyze(
            input(flags = AppFlags(debuggable = true, allowBackup = true)),
        )
        assertEquals(Severity.HIGH, findings.first { it.id == "manifest:debuggable" }.severity)
        assertEquals(Severity.LOW, findings.first { it.id == "manifest:allow_backup" }.severity)
    }

    @Test
    fun `accessibility service declaration is HIGH`() {
        val findings = ApkStaticAnalyzer.analyze(input(accessibility = true))
        assertEquals(Severity.HIGH, findings.first { it.id == "service:accessibility" }.severity)
    }

    @Test
    fun `notification listener declaration is MEDIUM`() {
        val findings = ApkStaticAnalyzer.analyze(input(notificationListener = true))
        assertEquals(Severity.MEDIUM, findings.first { it.id == "service:notification_listener" }.severity)
    }

    @Test
    fun `suspicious strings map to findings`() {
        val scan = StringsScanResult(
            urls = listOf("http://evil.example.com/a"),
            rawIps = listOf("45.77.212.36"),
            keywordHits = listOf("/system/xbin/su", "DexClassLoader"),
        )
        val findings = ApkStaticAnalyzer.analyze(input(strings = scan))
        assertEquals(Severity.MEDIUM, findings.first { it.id == "strings:root_tools" }.severity)
        assertEquals(Severity.MEDIUM, findings.first { it.id == "strings:dexclassloader" }.severity)
        assertEquals(Severity.LOW, findings.first { it.id == "strings:raw_ips" }.severity)
        assertEquals(Severity.INFO, findings.first { it.id == "strings:urls" }.severity)
    }

    @Test
    fun `sideloaded installed app gets an INFO note`() {
        val findings = ApkStaticAnalyzer.analyze(
            input(identity = identity(isInstalledApp = true, installer = null)),
        )
        assertEquals(Severity.INFO, findings.first { it.id == "meta:side_loaded" }.severity)
    }

    @Test
    fun `multiple dex files is INFO only`() {
        val findings = ApkStaticAnalyzer.analyze(input(dexCount = 4))
        assertEquals(Severity.INFO, findings.first { it.id == "manifest:multiple_dex" }.severity)
    }
}

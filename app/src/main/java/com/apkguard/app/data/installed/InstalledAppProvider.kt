package com.apkguard.app.data.installed

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.apkguard.app.domain.model.AppFlags
import com.apkguard.app.domain.model.AppIdentity
import com.apkguard.app.domain.model.CertificateInfo
import com.apkguard.app.domain.model.SignatureInfo
import java.io.ByteArrayInputStream
import java.io.File
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Lists installed apps and pulls their deep metadata via PackageManager.
 * When the app's APK file is readable we hand it back so the full static
 * engine can run on it; otherwise the caller falls back to metadata-only analysis.
 */
class InstalledAppProvider(private val context: Context) {

    private val pm: PackageManager get() = context.packageManager

    data class InstalledAppRow(
        val packageName: String,
        val label: String,
        val isSystem: Boolean,
        val installerPackage: String?,
        val versionName: String?,
    )

    data class DeepInfo(
        val identity: AppIdentity,
        val permissions: List<String>,
        val grantedPermissions: Set<String>,
        val signature: SignatureInfo?,
        val flags: AppFlags,
        val declaresAccessibilityService: Boolean,
        val declaresNotificationListenerService: Boolean,
        val apkFile: File?,
    )

    fun list(includeSystem: Boolean): List<InstalledAppRow> = try {
        pm.getInstalledPackages(0)
            .asSequence()
            .filter { includeSystem || !isSystemApp(it) }
            .map { it.toRow() }
            .sortedBy { it.label.lowercase() }
            .toList()
    } catch (_: Exception) {
        emptyList()
    }

    private fun isSystemApp(info: PackageInfo): Boolean =
        ((info.applicationInfo?.flags ?: 0) and ApplicationInfo.FLAG_SYSTEM) != 0

    private fun PackageInfo.toRow(): InstalledAppRow = InstalledAppRow(
        packageName = packageName,
        label = applicationInfo?.loadLabel(pm)?.toString() ?: packageName,
        isSystem = isSystemApp(this),
        installerPackage = safeInstaller(packageName),
        versionName = @Suppress("DEPRECATION") versionName,
    )

    fun safeInstaller(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) {
            val source = pm.getInstallSourceInfo(packageName)
            // All three getters exist since API 30; installingOriginatingPackageName
            // is API 33 and usually null for third-party apps, so it is not used.
            source.initiatingPackageName
                ?: source.installingPackageName
                ?: source.originatingPackageName
        } else {
            @Suppress("DEPRECATION")
            pm.getInstallerPackageName(packageName)
        }
    } catch (_: Exception) {
        null
    }

    fun deepInfo(packageName: String): DeepInfo? {
        val packageInfo: PackageInfo = try {
            if (Build.VERSION.SDK_INT >= 28) {
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES,
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    packageName,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNATURES,
                )
            }
        } catch (_: Exception) {
            return null
        }

        val appInfo = packageInfo.applicationInfo ?: return null
        val label = appInfo.loadLabel(pm).toString()
        val installer = safeInstaller(packageName)

        val requested = packageInfo.requestedPermissions?.toList().orEmpty()
        val granted = buildGrantedSet(packageInfo)

        val signature = readSignature(packageInfo)
        val apkFile = appInfo.sourceDir?.let(::File)?.takeIf { it.exists() && it.canRead() }

        return DeepInfo(
            identity = AppIdentity(
                appName = label,
                packageName = packageName,
                versionName = @Suppress("DEPRECATION") packageInfo.versionName,
                versionCode = if (Build.VERSION.SDK_INT >= 28) packageInfo.longVersionCode
                else @Suppress("DEPRECATION") packageInfo.versionCode.toLong(),
                minSdk = if (appInfo.minSdkVersion > 0) appInfo.minSdkVersion else null,
                targetSdk = appInfo.targetSdkVersion,
                installerPackage = installer,
                firstInstallTimeMs = packageInfo.firstInstallTime,
                isInstalledApp = true,
            ),
            permissions = requested,
            grantedPermissions = granted,
            signature = signature,
            flags = AppFlags(
                debuggable = (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                allowBackup = (appInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP) != 0,
            ),
            declaresAccessibilityService = declaresService(packageName, ACCESSIBILITY_ACTION),
            declaresNotificationListenerService = declaresService(packageName, NOTIFICATION_LISTENER_ACTION),
            apkFile = apkFile,
        )
    }

    private fun buildGrantedSet(packageInfo: PackageInfo): Set<String> {
        val names = packageInfo.requestedPermissions ?: return emptySet()
        val flagArray = packageInfo.requestedPermissionsFlags ?: return emptySet()
        val granted = mutableSetOf<String>()
        for (i in names.indices) {
            if (i >= flagArray.size) break
            if (flagArray[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0) {
                granted.add(names[i])
            }
        }
        return granted
    }

    private fun readSignature(packageInfo: PackageInfo): SignatureInfo? {
        val signatures: List<Signature> = try {
            if (Build.VERSION.SDK_INT >= 28) {
                val signingInfo = packageInfo.signingInfo ?: return null
                if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners.toList()
                else signingInfo.signingCertificateHistory.toList()
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures?.toList().orEmpty()
            }
        } catch (_: Exception) {
            emptyList()
        }

        val certs = signatures.mapNotNull(::parseCertificate)
        // v2/v3 detection needs the raw APK; degrade gracefully when it is unreadable.
        val apkFile = packageInfo.applicationInfo?.sourceDir?.let(::File)?.takeIf { it.exists() && it.canRead() }
        val schemes = apkFile?.let { com.apkguard.app.data.apk.ApkSigningBlockReader.read(it) }

        return SignatureInfo(
            hasV1 = certs.isNotEmpty(),
            hasV2 = schemes?.hasV2 ?: false,
            hasV3 = schemes?.hasV3 ?: false,
            certificates = certs,
        )
    }

    private fun parseCertificate(signature: Signature): CertificateInfo? = try {
        val factory = CertificateFactory.getInstance("X.509")
        val cert = factory.generateCertificate(ByteArrayInputStream(signature.toByteArray()))
                as? X509Certificate ?: return null
        val fingerprint = MessageDigest.getInstance("SHA-256")
            .digest(cert.encoded)
            .joinToString("") { "%02x".format(it) }
        CertificateInfo(
            subject = cert.subjectDN.toString(),
            issuer = cert.issuerDN.toString(),
            notBeforeMs = cert.notBefore?.time,
            notAfterMs = cert.notAfter?.time,
            isDebug = cert.subjectDN.toString().contains("CN=Android Debug", ignoreCase = true),
            sha256 = fingerprint,
        )
    } catch (_: Exception) {
        null
    }

    private fun declaresService(packageName: String, action: String): Boolean = try {
        pm.queryIntentServices(Intent(action), 0).any { it.serviceInfo?.packageName == packageName }
    } catch (_: Exception) {
        false
    }

    private companion object {
        const val ACCESSIBILITY_ACTION = "android.accessibilityservice.AccessibilityService"
        const val NOTIFICATION_LISTENER_ACTION = "android.service.notification.NotificationListenerService"
    }
}

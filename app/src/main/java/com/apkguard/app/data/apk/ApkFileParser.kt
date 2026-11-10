package com.apkguard.app.data.apk

import com.apkguard.app.domain.model.CertificateInfo
import com.apkguard.app.domain.model.SignatureInfo
import com.apkguard.app.domain.model.StringsScanResult
import com.apkguard.app.domain.scanner.StringsAnalyzer
import net.dongliu.apk.parser.ApkFile
import java.io.File
import java.io.InputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.zip.ZipFile

/**
 * Parses standalone .apk files: manifest metadata (via apk-parser), v1 certificates,
 * v2/v3 signing schemes, embedded strings and the file hash.
 */
class ApkFileParser {

    class ApkParseException(message: String, cause: Throwable? = null) : Exception(message, cause)

    data class ManifestInfo(
        val packageName: String?,
        val label: String?,
        val versionName: String?,
        val versionCode: Long?,
        val minSdk: Int?,
        val targetSdk: Int?,
        val permissions: List<String>,
    )

    fun parseManifest(file: File): ManifestInfo = try {
        ApkFile(file).use { apk ->
            val meta = apk.apkMeta
            ManifestInfo(
                packageName = meta.packageName,
                label = meta.label,
                versionName = meta.versionName,
                versionCode = meta.versionCode,
                // apk-parser returns the SDK fields as raw strings (e.g. "21")
                minSdk = meta.minSdkVersion?.toIntOrNull(),
                targetSdk = meta.targetSdkVersion?.toIntOrNull(),
                permissions = meta.usesPermissions.orEmpty().distinct(),
            )
        }
    } catch (e: Exception) {
        throw ApkParseException("Cannot parse APK manifest", e)
    }

    /** Streams the file so multi-hundred-MB APKs do not blow the heap. */
    fun sha256(file: File): String? = try {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { ins ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val read = ins.read(buf)
                if (read < 0) break
                digest.update(buf, 0, read)
            }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    } catch (_: Exception) {
        null
    }

    fun readSignature(file: File): SignatureInfo {
        val certs = readV1Certificates(file)
        val schemes = ApkSigningBlockReader.read(file)
        return SignatureInfo(
            hasV1 = certs.isNotEmpty(),
            hasV2 = schemes.hasV2,
            hasV3 = schemes.hasV3,
            certificates = certs,
        )
    }

    private fun readV1Certificates(file: File): List<CertificateInfo> = try {
        ZipFile(file).use { zip ->
            val factory = CertificateFactory.getInstance("X.509")
            zip.entries().asSequence()
                .filter { isSignatureBlock(it.name) }
                .flatMap { entry ->
                    zip.getInputStream(entry).use { ins ->
                        runCatching { factory.generateCertificates(ins) }
                            .getOrDefault(emptySet())
                            .asSequence()
                    }
                }
                .filterIsInstance<X509Certificate>()
                .map { it.toCertificateInfo() }
                .toList()
        }
    } catch (_: Exception) {
        emptyList()
    }

    private fun isSignatureBlock(name: String): Boolean {
        val upper = name.uppercase()
        return upper.startsWith("META-INF/") &&
            (upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC"))
    }

    /**
     * Scans DEX files and assets for URLs / raw IPs / suspicious keywords.
     * Bounded: at most [perEntryBudgetBytes] per zip entry and [totalBudgetBytes] overall,
     * so hostile APKs cannot stall the scan.
     */
    fun scanStrings(
        file: File,
        perEntryBudgetBytes: Long = 8L * 1024 * 1024,
        totalBudgetBytes: Long = 24L * 1024 * 1024,
    ): StringsScanResult = try {
        val builder = StringBuilder()
        ZipFile(file).use { zip ->
            var remaining = totalBudgetBytes
            val entries = zip.entries().asSequence()
                .filter { it.name.endsWith(".dex") || it.name.startsWith("assets/") }
                .toList()
            for (entry in entries) {
                if (remaining <= 0) break
                val readLen = minOf(entry.size, perEntryBudgetBytes, remaining)
                if (readLen <= 0) continue
                zip.getInputStream(entry).use { ins ->
                    copyBounded(ins, readLen) { chunk -> builder.append(chunk) }
                    // remaining decreases by bytes actually consumed below
                }
                remaining -= readLen
            }
        }
        StringsAnalyzer.analyze(builder.toString())
    } catch (_: Exception) {
        StringsScanResult(urls = emptyList(), rawIps = emptyList(), keywordHits = emptyList())
    }

    fun countDexFiles(file: File): Int? = try {
        ZipFile(file).use { zip ->
            zip.entries().asSequence().count { Regex("classes\\d*\\.dex").matches(it.name) }
        }
    } catch (_: Exception) {
        null
    }

    private inline fun copyBounded(ins: InputStream, limit: Long, consumer: (String) -> Unit) {
        val buf = ByteArray(64 * 1024)
        var read = 0L
        while (read < limit) {
            val r = ins.read(buf)
            if (r < 0) break
            val take = minOf(r.toLong(), limit - read).toInt()
            consumer(String(buf, 0, take, Charsets.ISO_8859_1))
            read += take
        }
    }
}

private fun X509Certificate.toCertificateInfo(): CertificateInfo = try {
    val fingerprint = MessageDigest.getInstance("SHA-256")
        .digest(encoded)
        .joinToString("") { "%02x".format(it) }
    CertificateInfo(
        subject = subjectDN.toString(),
        issuer = issuerDN.toString(),
        notBeforeMs = notBefore?.time,
        notAfterMs = notAfter?.time,
        isDebug = subjectDN.toString().contains("CN=Android Debug", ignoreCase = true),
        sha256 = fingerprint,
    )
} catch (_: Exception) {
    CertificateInfo(
        subject = subjectDN.toString(),
        issuer = issuerDN.toString(),
        notBeforeMs = null,
        notAfterMs = null,
        isDebug = false,
        sha256 = null,
    )
}

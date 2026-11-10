package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.StringsScanResult

/**
 * Regex-based scan over raw APK bytes (decoded as ISO-8859-1 so every byte survives).
 * Pure Kotlin — unit-testable without any Android machinery.
 */
object StringsAnalyzer {

    private val URL_REGEX =
        Regex("(?i)https?://[A-Za-z0-9\\-._~%:/?#\\[\\]@!$&'()*+,;=]{4,140}")

    private val IP_REGEX = Regex("\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b")

    /** High-signal strings; hits are surfaced as findings by ApkStaticAnalyzer. */
    val SUSPICIOUS_KEYWORDS: List<String> = listOf(
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "magisk",
        "supersu",
        "chmod 777",
        "DexClassLoader",
        "content://sms",
    )

    private val benignIps = setOf("127.0.0.1", "0.0.0.0", "255.255.255.255")

    fun analyze(
        text: String,
        maxUrls: Int = 20,
        maxIps: Int = 10,
    ): StringsScanResult {
        val urls = URL_REGEX.findAll(text)
            .map { it.value.trimEnd('.', ',') }
            .toSortedSet()
            .take(maxUrls)
            .toList()

        val lower = text.lowercase()
        val keywordHits = SUSPICIOUS_KEYWORDS.filter { lower.contains(it.lowercase()) }

        val ips = IP_REGEX.findAll(text)
            .map { it.value }
            .filter { it !in benignIps && !looksLikeVersionNumber(it) }
            .toSortedSet()
            .take(maxIps)
            .toList()

        return StringsScanResult(urls = urls, rawIps = ips, keywordHits = keywordHits)
    }

    /**
     * Filters strings like "1.2.3.4" / "2.5.0.1" that are almost always version
     * numbers baked into the code, not network endpoints.
     */
    internal fun looksLikeVersionNumber(ip: String): Boolean {
        if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
            return false // private ranges are still interesting
        }
        return ip.split(".").all { it.toInt() in 0..9 }
    }
}

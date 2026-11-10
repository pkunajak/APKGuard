package com.apkguard.app.domain.scanner

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class StringsAnalyzerTest {

    @Test
    fun `extracts and dedupes urls`() {
        val result = StringsAnalyzer.analyze(
            "visit https://api.example.com/v1 and again https://api.example.com/v1 plus http://ads.other.net/x.",
        )
        assertEquals(listOf("http://ads.other.net/x", "https://api.example.com/v1"), result.urls)
    }

    @Test
    fun `filters benign and version-like ips but keeps real ones`() {
        val result = StringsAnalyzer.analyze(
            "127.0.0.1 localhost; version 1.2.3.4 build; home 192.168.1.5; c2 45.77.212.36",
        )
        assertTrue(result.rawIps.contains("45.77.212.36"))
        assertTrue(result.rawIps.contains("192.168.1.5"))
        assertFalse(result.rawIps.contains("127.0.0.1"))
        assertFalse(result.rawIps.contains("1.2.3.4"))
    }

    @Test
    fun `looksLikeVersionNumber heuristic`() {
        assertTrue(StringsAnalyzer.looksLikeVersionNumber("1.2.3.4"))
        assertFalse(StringsAnalyzer.looksLikeVersionNumber("192.168.1.5"))
        assertFalse(StringsAnalyzer.looksLikeVersionNumber("45.77.212.36"))
    }

    @Test
    fun `detects root and dynamic-loading keywords case-insensitively`() {
        val result = StringsAnalyzer.analyze(
            "runtime.exec(\"/system/xbin/su\") with DexClassLoader after chmod 777",
        )
        assertTrue(result.keywordHits.contains("/system/xbin/su"))
        assertTrue(result.keywordHits.contains("DexClassLoader"))
        assertTrue(result.keywordHits.contains("chmod 777"))
        assertTrue(result.rootToolHits.isNotEmpty())
        assertTrue(result.hasDexClassLoader)
    }

    @Test
    fun `clean text yields nothing`() {
        val result = StringsAnalyzer.analyze("hello world nothing to see here")
        assertTrue(result.urls.isEmpty() && result.rawIps.isEmpty() && result.keywordHits.isEmpty())
    }

    @Test
    fun `private range ips are never treated as version numbers`() {
        assertFalse(StringsAnalyzer.looksLikeVersionNumber("10.0.0.2"))
        assertFalse(StringsAnalyzer.looksLikeVersionNumber("172.16.0.1"))
    }
}

package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.RiskLevel
import com.apkguard.app.domain.model.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PermissionRiskCatalogTest {

    @Test
    fun `SMS permissions are dangerous and heavily weighted`() {
        listOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
        ).forEach { name ->
            val entry = PermissionRiskCatalog.lookup(name)
            assertEquals("$name should be DANGEROUS", RiskLevel.DANGEROUS, entry.risk)
            assertEquals("$name should be HIGH+", Severity.HIGH, entry.severity)
        }
    }

    @Test
    fun `contacts and call log are dangerous`() {
        listOf(
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
        ).forEach { name ->
            assertEquals(RiskLevel.DANGEROUS, PermissionRiskCatalog.lookup(name).risk)
        }
    }

    @Test
    fun `install-packages permission is dangerous`() {
        val entry = PermissionRiskCatalog.lookup("android.permission.REQUEST_INSTALL_PACKAGES")
        assertEquals(RiskLevel.DANGEROUS, entry.risk)
        assertEquals(Severity.HIGH, entry.severity)
    }

    @Test
    fun `fine location is noteworthy but not dangerous`() {
        val entry = PermissionRiskCatalog.lookup("android.permission.ACCESS_FINE_LOCATION")
        assertEquals(RiskLevel.NOTEWORTHY, entry.risk)
        assertEquals(Severity.MEDIUM, entry.severity)
    }

    @Test
    fun `internet is standard`() {
        val entry = PermissionRiskCatalog.lookup("android.permission.INTERNET")
        assertEquals(RiskLevel.SAFE, entry.risk)
        assertEquals(Severity.INFO, entry.severity)
    }

    @Test
    fun `unknown custom permissions fall back to SAFE`() {
        val entry = PermissionRiskCatalog.lookup("com.vendor.app.SOME_CUSTOM_PERMISSION")
        assertEquals(RiskLevel.SAFE, entry.risk)
        assertEquals(Severity.INFO, entry.severity)
    }

    @Test
    fun `toPermissionInfos carries granted flags`() {
        val infos = PermissionRiskCatalog.toPermissionInfos(
            names = listOf("android.permission.READ_SMS", "android.permission.INTERNET"),
            grantedFlags = mapOf("android.permission.READ_SMS" to true),
        )
        assertEquals(2, infos.size)
        val sms = infos.first { it.name == "android.permission.READ_SMS" }
        val internet = infos.first { it.name == "android.permission.INTERNET" }
        assertEquals(true, sms.granted)
        assertEquals(null, internet.granted)
        assertTrue(sms.description.th.isNotBlank() && sms.description.en.isNotBlank())
    }
}

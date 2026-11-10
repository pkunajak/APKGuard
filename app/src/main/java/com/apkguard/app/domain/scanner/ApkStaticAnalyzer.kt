package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.AppFlags
import com.apkguard.app.domain.model.AppIdentity
import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.FindingCategory
import com.apkguard.app.domain.model.LocalizedText
import com.apkguard.app.domain.model.PermissionInfo
import com.apkguard.app.domain.model.RiskLevel
import com.apkguard.app.domain.model.SignatureInfo
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.StringsScanResult

/**
 * The on-device static analysis brain: turns parsed APK/app data into findings.
 * Pure Kotlin — no Android dependencies — so every rule is unit-testable.
 */
object ApkStaticAnalyzer {

    data class Input(
        val identity: AppIdentity,
        val permissions: List<PermissionInfo>,
        val signature: SignatureInfo? = null,
        val strings: StringsScanResult? = null,
        val dexCount: Int? = null,
        /** Only available for installed apps. */
        val appFlags: AppFlags? = null,
        /** Only detectable for installed apps (via service intent query). */
        val declaresAccessibilityService: Boolean = false,
        val declaresNotificationListenerService: Boolean = false,
        val nowMs: Long = System.currentTimeMillis(),
    )

    fun analyze(input: Input): List<Finding> = buildList {
        addAll(permissionFindings(input))
        addAll(comboFindings(input))
        addAll(signatureFindings(input))
        addAll(targetSdkFindings(input))
        addAll(appFlagFindings(input))
        addAll(serviceFindings(input))
        addAll(stringsFindings(input))
        addAll(metadataFindings(input))
        addAll(dexFindings(input))
    }

    private fun permissionFindings(input: Input): List<Finding> {
        val notable = input.permissions.filter { it.severity == Severity.MEDIUM || it.severity == Severity.HIGH || it.severity == Severity.CRITICAL }
        val individual = notable.map { p ->
            Finding(
                id = "perm:${p.name}",
                category = FindingCategory.PERMISSION,
                severity = p.severity,
                title = LocalizedText(
                    th = "ขอสิทธิ์: ${p.name.substringAfterLast('.')} (${riskLabelTh(p.risk)})",
                    en = "Requests permission: ${p.name.substringAfterLast('.')} (${riskLabelEn(p.risk)})",
                ),
                detail = p.description,
            )
        }
        val lows = input.permissions.filter { it.severity == Severity.LOW }
        val lowAggregated = if (lows.isEmpty()) null else Finding(
            id = "perm:low_aggregate",
            category = FindingCategory.PERMISSION,
            severity = Severity.LOW,
            title = LocalizedText(
                "ขอสิทธิ์ที่ควรระวังอีก ${lows.size} รายการ",
                "Requests ${lows.size} more permissions worth noting",
            ),
            detail = LocalizedText(
                th = lows.joinToString("\n") { "• ${it.name.substringAfterLast('.')}" },
                en = lows.joinToString("\n") { "• ${it.name.substringAfterLast('.')}" },
            ),
        )
        return individual + listOfNotNull(lowAggregated)
    }

    private fun comboFindings(input: Input): List<Finding> {
        val perms = input.permissions.map { it.name }.toSet()
        val hasSms = perms.any { it.endsWith("SMS") && it != "android.permission.SEND_SMS" } || perms.contains("android.permission.SEND_SMS")
        val hasContacts = perms.contains("android.permission.READ_CONTACTS") || perms.contains("android.permission.WRITE_CONTACTS")
        val hasCallLog = perms.contains("android.permission.READ_CALL_LOG")
        val hasLocation = perms.contains("android.permission.ACCESS_FINE_LOCATION") || perms.contains("android.permission.ACCESS_COARSE_LOCATION")

        val spywareCombo = hasSms && (hasContacts || hasCallLog) && hasLocation
        val dropperCombo = perms.contains("android.permission.REQUEST_INSTALL_PACKAGES") &&
            (perms.contains("android.permission.SYSTEM_ALERT_WINDOW") || input.declaresAccessibilityService)

        return buildList {
            if (spywareCombo) add(
                Finding(
                    id = "combo:spyware",
                    category = FindingCategory.PERMISSION,
                    severity = Severity.CRITICAL,
                    title = LocalizedText(
                        "ชุดสิทธิ์แบบแอปสอดแนม (spyware)",
                        "Permission combo typical of spyware",
                    ),
                    detail = LocalizedText(
                        "แอปนี้ขอข้อความ + รายชื่อ/ประวัติโทร + ตำแหน่งพร้อมกัน — รูปแบบเดียวกับมัลแวร์ขโมยข้อมูลส่วนตัว",
                        "Requests messaging + contacts/call log + location together — the classic stalkerware/malware pattern",
                    ),
                ),
            )
            if (dropperCombo) add(
                Finding(
                    id = "combo:dropper",
                    category = FindingCategory.PERMISSION,
                    severity = Severity.HIGH,
                    title = LocalizedText(
                        "สามารถโหลดแอปเพิ่มและหลอกผู้ใช้ได้",
                        "Can install more apps and deceive the user",
                    ),
                    detail = LocalizedText(
                        "การขอสิทธิ์ติดตั้งแอปเพิ่ม ร่วมกับการวาดทับหน้าจอหรือ Accessibility ทำให้สามารถลอบติดตั้งแอปอันตรายโดยคุณไม่ทันสังเกต",
                        "Requesting install rights combined with overlay or accessibility access allows silent installation of further malicious apps",
                    ),
                ),
            )
        }
    }

    private fun signatureFindings(input: Input): List<Finding> {
        val sig = input.signature ?: return emptyList()
        val out = mutableListOf<Finding>()
        val noCerts = sig.certificates.isEmpty()

        if (noCerts && !sig.hasV2 && !sig.hasV3) {
            out += Finding(
                id = "sig:missing",
                category = FindingCategory.SIGNATURE,
                severity = Severity.CRITICAL,
                title = LocalizedText("ไม่พบลายเซ็นดิจิทัล", "No digital signature found"),
                detail = LocalizedText(
                    "APK ปกติต้องมีลายเซ็นเสมอ ไม่พบลายเซ็นแสดงว่าไฟล์ถูกแก้ไขหรือสร้างอย่างไม่ถูกต้อง — ไม่ควรติดตั้ง",
                    "Every valid APK is signed; a missing signature means the file was tampered with or built incorrectly — do not install",
                ),
            )
            return out
        }
        if (sig.certificates.any { it.isDebug }) {
            out += Finding(
                id = "sig:debug",
                category = FindingCategory.SIGNATURE,
                severity = Severity.HIGH,
                title = LocalizedText("เซ็นด้วยใบรับรองชั่วคราว (debug)", "Signed with a debug certificate"),
                detail = LocalizedText(
                    "ใบรับรอง debug ใช้สำหรับทดสอบเท่านั้น แอปที่เผยแพร่จริงไม่ควรใช้ — อาจเป็นงานสะสมของนักพัฒนาหรือแอปปลอม",
                    "Debug certificates are for development only; released apps should never use one — possibly a leaked build or an impersonation",
                ),
            )
        }
        val expired = sig.certificates.filter { c -> (c.notAfterMs ?: Long.MAX_VALUE) < input.nowMs }
        if (expired.isNotEmpty()) {
            out += Finding(
                id = "sig:expired",
                category = FindingCategory.SIGNATURE,
                severity = Severity.MEDIUM,
                title = LocalizedText("ใบรับรองหมดอายุ", "Signing certificate has expired"),
                detail = LocalizedText(
                    "แอปเก่าที่เซ็นนานมาแล้ว ไม่ได้แปลว่าอันตราย แต่บอกว่าไม่มีการอัปเดตดูแลอีกแล้ว",
                    "Signed long ago and never renewed; not necessarily malicious, but the app is no longer maintained",
                ),
            )
        }
        if (!sig.hasV2 && !sig.hasV3) {
            out += Finding(
                id = "sig:v1only",
                category = FindingCategory.SIGNATURE,
                severity = Severity.MEDIUM,
                title = LocalizedText("เซ็นแบบเก่า (v1) เท่านั้น", "Signed with the legacy v1 scheme only"),
                detail = LocalizedText(
                    "รูปแบบ v1 เป็นมาตรฐานเก่ากว่าปี 2016 และอ่อนแอกว่า v2/v3 ที่ Android รุ่นใหม่ใช้",
                    "The v1 scheme predates 2016 and is weaker than the v2/v3 schemes used by modern Android",
                ),
            )
        }
        return out
    }

    private fun targetSdkFindings(input: Input): List<Finding> {
        val target = input.identity.targetSdk ?: return emptyList()
        return when {
            target < 23 -> listOf(
                Finding(
                    id = "manifest:target_sdk_ancient",
                    category = FindingCategory.MANIFEST,
                    severity = Severity.MEDIUM,
                    title = LocalizedText("สร้างสำหรับ Android รุ่นเก่ามาก", "Targets a very old Android version"),
                    detail = LocalizedText(
                        "กำหนด targetSdk ต่ำกว่า 23 ทำให้หลบเลี่ยงข้อจำกัดความปลอดภัยสมัยใหม่ เช่น การขอสิทธิ์ทีละอย่างตอนใช้งาน",
                        "targetSdk below 23 opts out of modern runtime permission restrictions",
                    ),
                ),
            )
            target < 26 -> listOf(
                Finding(
                    id = "manifest:target_sdk_old",
                    category = FindingCategory.MANIFEST,
                    severity = Severity.LOW,
                    title = LocalizedText("กำหนด target SDK ค่อนข้างเก่า", "Targets a fairly old SDK"),
                    detail = LocalizedText(
                        "แอปที่ไม่อัปเดตตาม Android รุ่นใหม่ อาจมีช่องโหว่ที่ถูกแก้ไปแล้วในเวอร์ชันใหม่",
                        "Apps not updated for newer Android may carry already-fixed vulnerabilities",
                    ),
                ),
            )
            else -> emptyList()
        }
    }

    private fun appFlagFindings(input: Input): List<Finding> {
        val flags = input.appFlags ?: return emptyList()
        val out = mutableListOf<Finding>()
        if (flags.debuggable == true) {
            out += Finding(
                id = "manifest:debuggable",
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = LocalizedText("เปิดโหมด debug ไว้", "Ships with debug mode enabled"),
                detail = LocalizedText(
                    "โหมด debug เปิดให้เข้าถึงข้อมูลภายในแอปได้ง่าย ไม่ควรปรากฏในแอปที่เผยแพร่จริง",
                    "Debug mode exposes the app internals and must never ship in production builds",
                ),
            )
        }
        if (flags.allowBackup == true) {
            out += Finding(
                id = "manifest:allow_backup",
                category = FindingCategory.MANIFEST,
                severity = Severity.LOW,
                title = LocalizedText("อนุญาตให้สำรองข้อมูลแอป", "Allows app data backup"),
                detail = LocalizedText(
                    "ข้อมูลในแอปสามารถดึงออกมาผ่าน adb backup ได้ — ควรปิดสำหรับแอปที่เก็บข้อมูลอ่อนไหว",
                    "App data can be extracted via adb backup — should be off for sensitive apps",
                ),
            )
        }
        return out
    }

    private fun serviceFindings(input: Input): List<Finding> {
        val out = mutableListOf<Finding>()
        if (input.declaresAccessibilityService) {
            out += Finding(
                id = "service:accessibility",
                category = FindingCategory.MANIFEST,
                severity = Severity.HIGH,
                title = LocalizedText("มีบริการ Accessibility (อ่านหน้าจอ)", "Declares an accessibility service (screen reader)"),
                detail = LocalizedText(
                    "บริการนี้อ่านได้ทุกอย่างที่แสดงบนหน้าจอและควบคุมการแตะได้ — ถ้าไม่ใช่แอปช่วยพิเศษจริง ๆ นี่คือสัญญาณอันตรายชัดเจน",
                    "Accessibility services read everything on screen and can inject touches — anything other than a genuine assistive app is a major red flag",
                ),
            )
        }
        if (input.declaresNotificationListenerService) {
            out += Finding(
                id = "service:notification_listener",
                category = FindingCategory.MANIFEST,
                severity = Severity.MEDIUM,
                title = LocalizedText("อ่านการแจ้งเตือนทั้งหมด", "Reads all notifications"),
                detail = LocalizedText(
                    "สามารถอ่าน OTP และข้อความสำคัญจากการแจ้งเตือนของทุกแอปได้",
                    "Can read OTP codes and messages from every app's notifications",
                ),
            )
        }
        return out
    }

    private fun stringsFindings(input: Input): List<Finding> {
        val s = input.strings ?: return emptyList()
        val out = mutableListOf<Finding>()
        if (s.rootToolHits.isNotEmpty()) {
            out += Finding(
                id = "strings:root_tools",
                category = FindingCategory.STRINGS,
                severity = Severity.MEDIUM,
                title = LocalizedText("พบสตริงเกี่ยวกับเครื่องมือ root", "Contains root-tool strings"),
                detail = LocalizedText(
                    "พบคำที่เกี่ยวข้องกับการรูทเครื่อง (su/Magisk) หรือการเปลี่ยนสิทธิ์ไฟล์ — บางแอปปกติก็มี แต่ควรตรวจสอบเพิ่ม",
                    "References to su/Magisk or permission changes found — some legitimate apps include these, but worth investigating",
                ),
            )
        }
        if (s.hasDexClassLoader) {
            out += Finding(
                id = "strings:dexclassloader",
                category = FindingCategory.STRINGS,
                severity = Severity.MEDIUM,
                title = LocalizedText("โหลดโค้ดเพิ่มขณะทำงาน", "Loads extra code at runtime"),
                detail = LocalizedText(
                    "ใช้ DexClassLoader ดึงโค้ดจากภายนอกมารันตอนที่แอปทำงาน — ทำให้ตรวจสอบล่วงหน้าไม่ได้ว่าโค้ดนั้นทำอะไร",
                    "Uses DexClassLoader to run downloaded code, which cannot be pre-audited",
                ),
            )
        }
        if (s.rawIps.isNotEmpty()) {
            out += Finding(
                id = "strings:raw_ips",
                category = FindingCategory.STRINGS,
                severity = Severity.LOW,
                title = LocalizedText("สื่อสารกับ IP ตรง ๆ", "Talks to raw IP addresses"),
                detail = LocalizedText(
                    "พบที่อยู่ IP ฝังอยู่ในไฟล์ — เซิร์ฟเวอร์ที่ไม่ใช้ชื่อโดเมนมักเป็นสัญญาณของคอมมานด์เซ็นเตอร์",
                    "Embedded IP addresses found; servers without domain names are a common command-and-control pattern",
                ),
            )
        }
        if (s.urls.isNotEmpty()) {
            out += Finding(
                id = "strings:urls",
                category = FindingCategory.STRINGS,
                severity = Severity.INFO,
                title = LocalizedText("พบ URL ฝังอยู่ ${s.urls.size} รายการ", "Contains ${s.urls.size} embedded URLs"),
                detail = LocalizedText(
                    th = s.urls.take(10).joinToString("\n"),
                    en = s.urls.take(10).joinToString("\n"),
                ),
            )
        }
        return out
    }

    private fun metadataFindings(input: Input): List<Finding> {
        if (!input.identity.isInstalledApp) return emptyList()
        val installer = input.identity.installerPackage ?: return listOf(
            Finding(
                id = "meta:side_loaded",
                category = FindingCategory.METADATA,
                severity = Severity.INFO,
                title = LocalizedText("ติดตั้งนอกร้านค้า", "Installed outside any store"),
                detail = LocalizedText(
                    "แอปนี้ถูกติดตั้งโดยตรงจากไฟล์ APK — ไม่ได้ผ่านการตรวจสอบของร้านค้าใด ๆ ไม่ใช่ความผิดปกติ แต่ควรรู้ไว้",
                    "Sideloaded from an APK file with no store review; not an anomaly by itself, but good to know",
                ),
            ),
        )
        return emptyList()
    }

    private fun dexFindings(input: Input): List<Finding> {
        val count = input.dexCount ?: return emptyList()
        return if (count > 1) listOf(
            Finding(
                id = "manifest:multiple_dex",
                category = FindingCategory.MANIFEST,
                severity = Severity.INFO,
                title = LocalizedText("มีไฟล์โค้ด (DEX) $count ไฟล์", "Bundles $count DEX code files"),
                detail = LocalizedText(
                    "แอปขนาดใหญ่หรือมีไลบรารีจำนวนมากจะมีหลายไฟล์ DEX — เป็นเรื่องปกติ",
                    "Large apps and apps with many libraries ship multiple DEX files — this is normal",
                ),
            ),
        ) else emptyList()
    }

    private fun riskLabelTh(risk: RiskLevel) = when (risk) {
        RiskLevel.SAFE -> "ทั่วไป"
        RiskLevel.NOTEWORTHY -> "ควรระวัง"
        RiskLevel.DANGEROUS -> "อันตราย"
    }

    private fun riskLabelEn(risk: RiskLevel) = when (risk) {
        RiskLevel.SAFE -> "standard"
        RiskLevel.NOTEWORTHY -> "use with care"
        RiskLevel.DANGEROUS -> "dangerous"
    }
}

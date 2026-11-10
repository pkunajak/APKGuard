package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.LocalizedText
import com.apkguard.app.domain.model.PermissionInfo
import com.apkguard.app.domain.model.RiskLevel
import com.apkguard.app.domain.model.Severity

/**
 * Catalog of Android permissions with plain-language risk explanations (Thai + English).
 * Pure Kotlin on purpose: this is the knowledge base the scoring engine relies on.
 */
object PermissionRiskCatalog {

    data class Entry(
        val risk: RiskLevel,
        val severity: Severity,
        val th: String,
        val en: String,
    )

    private val unknown = Entry(
        risk = RiskLevel.SAFE,
        severity = Severity.INFO,
        th = "สิทธิ์ทั่วไปที่ไม่อยู่ในรายการเฝ้าระวัง",
        en = "Standard permission not on the watch list",
    )

    // region SMS / messaging — classic OTP-interception territory
    private val sms = Entry(
        RiskLevel.DANGEROUS, Severity.HIGH,
        "อ่านหรือรับ-ส่งข้อความ SMS ได้ รวมถึงรหัสยืนยันตัวตน (OTP) — มักถูกแอปม้าโทรจันธนาคารใช้ขโมยเงิน",
        "Can read/send SMS, including one-time passwords (OTP) — a hallmark of banking trojans",
    )
    private val mms = Entry(
        RiskLevel.DANGEROUS, Severity.HIGH,
        "รับข้อความ MMS/WAP push ได้ ใช้ร่วมกับ SMS ในการดักข้อความ",
        "Can receive MMS/WAP push messages, often paired with SMS interception",
    )
    // endregion

    private val entries: Map<String, Entry> = mapOf(
        // SMS family
        "android.permission.READ_SMS" to sms,
        "android.permission.RECEIVE_SMS" to sms,
        "android.permission.SEND_SMS" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "ส่งข้อความ SMS ได้เองโดยผู้ใช้ไม่รู้ — อาจมีค่าบริการแอบแฝง",
            "Can silently send SMS, potentially subscribing you to paid services",
        ),
        "android.permission.RECEIVE_MMS" to mms,
        "android.permission.RECEIVE_WAP_PUSH" to mms,

        // Contacts & call log
        "android.permission.READ_CONTACTS" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "อ่านรายชื่อผู้ติดต่อทั้งหมดในเครื่อง — ข้อมูลส่วนตัวของคุณและคนรู้จักอาจถูกส่งออก",
            "Reads your entire contact list — your and your contacts' data can be exfiltrated",
        ),
        "android.permission.WRITE_CONTACTS" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "แก้ไขหรือลบรายชื่อผู้ติดต่อได้",
            "Can modify or delete your contacts",
        ),
        "android.permission.READ_CALL_LOG" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "อ่านประวัติการโทรทั้งหมด — รู้ว่าคุณโทรหาใครเมื่อไหร่",
            "Reads your full call history",
        ),
        "android.permission.WRITE_CALL_LOG" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "แก้ไขประวัติการโทรได้ ใช้ปิดบังกิจกรรมการโทรของมัลแวร์ได้",
            "Can modify call logs, e.g. to hide fraudulent calls",
        ),
        "android.permission.PROCESS_OUTGOING_CALLS" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "ตรวจจับ/ขัดจังหวะสายที่กำลังโทรออก",
            "Can observe or redirect outgoing calls",
        ),

        // Device control / installation
        "android.permission.REQUEST_INSTALL_PACKAGES" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "ติดตั้งแอปเพิ่มได้เอง — มัลแวร์ใช้โหลดตัวร้ายตัวที่สองหลังจากติดตั้งแล้ว",
            "Can install additional apps — commonly used to drop a second-stage payload",
        ),
        "android.permission.REQUEST_DELETE_PACKAGES" to Entry(
            RiskLevel.DANGEROUS, Severity.MEDIUM,
            "ถือแอปอื่นออกได้ อาจใช้แทนที่แอปธนาคารด้วยตัวปลอม",
            "Can uninstall other apps, e.g. to replace a banking app with a fake one",
        ),
        "android.permission.BIND_DEVICE_ADMIN" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "สมัครเป็นผู้ดูแลอุปกรณ์ — ล็อกหน้าจอ/ล้างข้อมูล หรือกันผู้ใช้ถอนการติดตั้งได้",
            "Becomes device administrator — can lock or wipe the device and resist removal",
        ),
        "android.permission.BIND_ACCESSIBILITY_SERVICE" to Entry(
            RiskLevel.DANGEROUS, Severity.CRITICAL,
            "ให้บริการ Accessibility (อ่านทุกอย่างบนหน้าจอและควบคุมเครื่องได้) — สิทธิ์ที่มัลแวร์อยากได้ที่สุด",
            "Provides an accessibility service (reads the screen, controls the device) — the most abused permission",
        ),
        "android.permission.SYSTEM_ALERT_WINDOW" to Entry(
            RiskLevel.DANGEROUS, Severity.MEDIUM,
            "วางหน้าต่างทับบนแอปอื่นได้ — ใช้ทำหน้าล็อกอินปลอมหรือกดยืนยันหลอกได้",
            "Can draw over other apps — used for fake login screens and deceptive dialogs",
        ),
        "android.permission.WRITE_SETTINGS" to Entry(
            RiskLevel.DANGEROUS, Severity.MEDIUM,
            "แก้ไขการตั้งค่าระบบได้",
            "Can modify system settings",
        ),
        "android.permission.MANAGE_EXTERNAL_STORAGE" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "เข้าถึงไฟล์ทั้งเครื่อง รวมถึงรูป เอกสาร และไฟล์ของแอปอื่น",
            "Full access to all files on the device, including photos and documents",
        ),

        // Privacy sensors
        "android.permission.RECORD_AUDIO" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "ใช้ไมโครโฟนอัดเสียงได้",
            "Can record audio with the microphone",
        ),
        "android.permission.CAMERA" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "ใช้กล้องได้ — ปกติสำหรับแอปกล้อง/สแกน แต่ควรระวังถ้าแอปไม่เกี่ยวกับกล้อง",
            "Can use the camera — normal for camera apps, odd otherwise",
        ),
        "android.permission.ACCESS_FINE_LOCATION" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "รู้ตำแหน่งที่แม่นยำของคุณ",
            "Knows your precise location",
        ),
        "android.permission.ACCESS_COARSE_LOCATION" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "รู้ตำแหน่งโดยประมาณของคุณ",
            "Knows your approximate location",
        ),
        "android.permission.ACCESS_BACKGROUND_LOCATION" to Entry(
            RiskLevel.DANGEROUS, Severity.HIGH,
            "ติดตามตำแหน่งแม้ตอนที่ไม่ได้ใช้แอป",
            "Tracks your location even when the app is not in use",
        ),
        "android.permission.READ_PHONE_STATE" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "อ่านข้อมูลอุปกรณ์/เบอร์โทร — ส่วนใหญ่ใช้ทำแอปไอดี แต่เป็นข้อมูลระบุตัวตน",
            "Reads device identifiers — commonly used for ad identification",
        ),
        "android.permission.READ_PHONE_NUMBERS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "อ่านเบอร์โทรศัพท์ของเครื่อง",
            "Reads this device's phone number",
        ),
        "android.permission.CALL_PHONE" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "โทรออกได้เอง — อาจมีค่าใช้จ่ายแอบแฝง",
            "Can place calls on its own — possible hidden charges",
        ),
        "android.permission.ANSWER_PHONE_CALLS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "รับสายโทรเข้าแทนคุณได้",
            "Can answer incoming calls",
        ),
        "android.permission.GET_ACCOUNTS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "ดูบัญชีที่ล็อกอินไว้ในเครื่อง",
            "Sees accounts signed in on the device",
        ),
        "android.permission.READ_HISTORY_BOOKMARKS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "อ่านประวัติการเข้าเว็บ (สิทธิ์รุ่นเก่า)",
            "Reads browsing history (legacy permission)",
        ),
        "android.permission.BODY_SENSORS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "อ่านค่าเซ็นเซอร์ร่างกาย เช่น ชีพจร",
            "Reads body sensors such as heart rate",
        ),
        "android.permission.ACTIVITY_RECOGNITION" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "จับการเคลื่อนไหว/กิจกรรมของคุณ",
            "Recognizes your physical activity",
        ),

        // Storage
        "android.permission.READ_EXTERNAL_STORAGE" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "อ่านไฟล์ในเครื่อง (สิทธิ์รุ่นเก่า)",
            "Reads files on the device (legacy permission)",
        ),
        "android.permission.WRITE_EXTERNAL_STORAGE" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "เขียน/แก้ไขไฟล์ในเครื่อง (สิทธิ์รุ่นเก่า)",
            "Writes files on the device (legacy permission)",
        ),

        // Common benign
        "android.permission.INTERNET" to Entry(
            RiskLevel.SAFE, Severity.INFO,
            "เชื่อมต่ออินเทอร์เน็ต — สิทธิ์พื้นฐานของแอปส่วนใหญ่",
            "Internet access — required by most apps",
        ),
        "android.permission.ACCESS_NETWORK_STATE" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ตรวจสถานะเครือข่าย", "Checks network state",
        ),
        "android.permission.ACCESS_WIFI_STATE" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ตรวจสถานะ Wi-Fi", "Checks Wi-Fi state",
        ),
        "android.permission.VIBRATE" to Entry(
            RiskLevel.SAFE, Severity.INFO, "สั่นเตือน", "Vibration",
        ),
        "android.permission.WAKE_LOCK" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ป้องกันหน้าจอดับขณะทำงาน", "Keeps the device awake",
        ),
        "android.permission.POST_NOTIFICATIONS" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ส่งการแจ้งเตือน", "Shows notifications",
        ),
        "android.permission.FOREGROUND_SERVICE" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ทำงานเบื้องหลังแบบมีการแจ้งเตือน", "Runs a user-visible background service",
        ),
        "android.permission.RECEIVE_BOOT_COMPLETED" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "เริ่มทำงานทุกครั้งที่เปิดเครื่อง",
            "Starts itself every time the device boots",
        ),
        "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "ขอยกเว้นการประหยัดแบตเตอรี่เพื่อทำงานตลอดเวลา",
            "Asks to skip battery optimization so it can run non-stop",
        ),
        "android.permission.PACKAGE_USAGE_STATS" to Entry(
            RiskLevel.NOTEWORTHY, Severity.MEDIUM,
            "ดูสถิติการใช้แอปว่าคุณใช้อะไรบ่อยแค่ไหน",
            "Sees which apps you use and how often",
        ),
        "android.permission.QUERY_ALL_PACKAGES" to Entry(
            RiskLevel.NOTEWORTHY, Severity.LOW,
            "ดูรายชื่อแอปทั้งหมดในเครื่อง",
            "Sees all apps installed on the device",
        ),
        "android.permission.BLUETOOTH_CONNECT" to Entry(
            RiskLevel.SAFE, Severity.INFO, "เชื่อมต่ออุปกรณ์บลูทูธ", "Connects to Bluetooth devices",
        ),
        "android.permission.USE_BIOMETRIC" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ใช้ไบโอเมตริก (ลายนิ้วมือ)", "Uses biometric authentication",
        ),
        "android.permission.USE_FINGERPRINT" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ใช้ลายนิ้วมือ (สิทธิ์รุ่นเก่า)", "Fingerprint auth (legacy)",
        ),
        "com.android.vending.BILLING" to Entry(
            RiskLevel.SAFE, Severity.INFO, "การชำระเงินในแอปผ่าน Play", "In-app billing via Play",
        ),
        "com.android.vending.CHECK_LICENSE" to Entry(
            RiskLevel.SAFE, Severity.INFO, "ตรวจสอบใบอนุญาต Play", "Play license check",
        ),
    )

    fun lookup(permissionName: String): Entry = entries[permissionName] ?: unknown

    fun toPermissionInfo(name: String, granted: Boolean? = null): PermissionInfo {
        val e = lookup(name)
        return PermissionInfo(
            name = name,
            risk = e.risk,
            severity = e.severity,
            description = LocalizedText(e.th, e.en),
            granted = granted,
        )
    }

    fun toPermissionInfos(names: Collection<String>, grantedFlags: Map<String, Boolean>? = null): List<PermissionInfo> =
        names.map { toPermissionInfo(it, grantedFlags?.get(it)) }
}

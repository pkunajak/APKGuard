package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.FindingCategory
import com.apkguard.app.domain.model.LocalizedText
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.VtSummary

/**
 * Maps a VirusTotal summary onto the local severity scale so VT results feed the
 * same scoring engine as the on-device findings.
 */
object VtSeverityMapper {

    fun severityFor(vt: VtSummary): Severity = when {
        vt.malicious >= 5 -> Severity.CRITICAL
        vt.malicious >= 2 -> Severity.HIGH
        vt.malicious == 1 -> Severity.MEDIUM
        vt.suspicious >= 3 -> Severity.MEDIUM
        vt.suspicious >= 1 -> Severity.LOW
        else -> Severity.INFO
    }

    fun findingFor(vt: VtSummary): Finding {
        val severity = severityFor(vt)
        val engines = vt.flaggedEngines.take(8).joinToString(", ")
        val label = vt.threatLabel?.let { " ($it)" }.orEmpty()
        return Finding(
            id = "vt:engines",
            category = FindingCategory.VIRUSTOTAL,
            severity = severity,
            title = LocalizedText(
                th = "VirusTotal: ${vt.malicious}/${vt.totalEngines} เอนจินตรวจพบ",
                en = "VirusTotal: flagged by ${vt.malicious}/${vt.totalEngines} engines",
            ),
            detail = LocalizedText(
                th = when {
                    vt.malicious > 0 -> "เอนจินที่แจ้งเตือน: $engines$label — แนะนำอย่างแรงให้หลีกเลี่ยงไฟล์นี้"
                    vt.suspicious > 0 -> "มีเอนจินระบุว่าน่าสงสัย ($engines) — พิจารณาอย่างรอบคอบก่อนใช้"
                    else -> "ไม่มีเอนจินรายงานว่าเป็นอันตราย อย่างไรก็ตาม ไฟล์ใหม่ที่ยังไม่มีใครเคยสแกนอาจยังตรวจไม่พบ"
                },
                en = when {
                    vt.malicious > 0 -> "Flagging engines: $engines$label — strongly recommended to avoid this file"
                    vt.suspicious > 0 -> "Some engines consider it suspicious ($engines) — proceed with caution"
                    else -> "No engine flagged it as malicious; note that brand-new files can still go undetected"
                },
            ),
        )
    }
}

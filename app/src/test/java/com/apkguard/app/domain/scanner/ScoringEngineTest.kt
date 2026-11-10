package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.FindingCategory
import com.apkguard.app.domain.model.LocalizedText
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class ScoringEngineTest {

    private fun finding(id: String, severity: Severity) = Finding(
        id = id,
        category = FindingCategory.PERMISSION,
        severity = severity,
        title = LocalizedText("th-$id", "en-$id"),
        detail = LocalizedText("th", "en"),
    )

    @Test
    fun `no findings yields zero score and SAFE verdict`() {
        assertEquals(0, ScoringEngine.score(emptyList()))
        assertEquals(Verdict.SAFE, ScoringEngine.verdict(0))
    }

    @Test
    fun `severity weights are summed`() {
        val findings = listOf(
            finding("a", Severity.MEDIUM), // 10
            finding("b", Severity.LOW),    // 4
            finding("c", Severity.INFO),   // 0
        )
        assertEquals(14, ScoringEngine.score(findings))
        assertEquals(Verdict.SAFE, ScoringEngine.verdict(14))
    }

    @Test
    fun `two high findings land in SUSPICIOUS`() {
        val findings = listOf(finding("a", Severity.HIGH), finding("b", Severity.HIGH)) // 36
        assertEquals(36, ScoringEngine.score(findings))
        assertEquals(Verdict.SUSPICIOUS, ScoringEngine.verdict(36))
    }

    @Test
    fun `critical plus high plus medium stays SUSPICIOUS at 58`() {
        val findings = listOf(
            finding("a", Severity.CRITICAL), // 30
            finding("b", Severity.HIGH),     // 18
            finding("c", Severity.MEDIUM),   // 10
        )
        assertEquals(58, ScoringEngine.score(findings))
        assertEquals(Verdict.SUSPICIOUS, ScoringEngine.verdict(58))
    }

    @Test
    fun `score is capped at 100`() {
        val findings = List(5) { finding("f$it", Severity.CRITICAL) } // raw 150
        assertEquals(100, ScoringEngine.score(findings))
        assertEquals(Verdict.DANGEROUS, ScoringEngine.verdict(100))
    }

    @Test
    fun `verdict thresholds are inclusive`() {
        assertEquals(Verdict.SAFE, ScoringEngine.verdict(29))
        assertEquals(Verdict.SUSPICIOUS, ScoringEngine.verdict(30))
        assertEquals(Verdict.SUSPICIOUS, ScoringEngine.verdict(69))
        assertEquals(Verdict.DANGEROUS, ScoringEngine.verdict(70))
    }

    @Test
    fun `topFindings sorts by severity and hides INFO`() {
        val findings = listOf(
            finding("info", Severity.INFO),
            finding("low", Severity.LOW),
            finding("critical", Severity.CRITICAL),
            finding("high", Severity.HIGH),
        )
        val top = ScoringEngine.topFindings(findings, count = 3)
        assertEquals(listOf("critical", "high", "low"), top.map { it.id })
    }
}

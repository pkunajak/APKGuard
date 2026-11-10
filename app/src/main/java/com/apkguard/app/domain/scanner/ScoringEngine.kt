package com.apkguard.app.domain.scanner

import com.apkguard.app.domain.model.Finding
import com.apkguard.app.domain.model.Severity
import com.apkguard.app.domain.model.Verdict

/**
 * Turns a list of findings into a 0–100 risk score and a final verdict.
 * Pure and deterministic so it is fully unit-testable.
 *
 * Rules: sum of severity weights, capped at 100.
 * Verdict thresholds: 0–29 SAFE, 30–69 SUSPICIOUS, 70+ DANGEROUS.
 */
object ScoringEngine {

    const val SUSPICIOUS_THRESHOLD: Int = 30
    const val DANGEROUS_THRESHOLD: Int = 70

    fun score(findings: List<Finding>): Int =
        findings.sumOf { it.severity.weight }.coerceIn(0, 100)

    fun verdict(score: Int): Verdict = when {
        score >= DANGEROUS_THRESHOLD -> Verdict.DANGEROUS
        score >= SUSPICIOUS_THRESHOLD -> Verdict.SUSPICIOUS
        else -> Verdict.SAFE
    }

    /** Most important findings first, ignoring purely informational ones. */
    fun topFindings(findings: List<Finding>, count: Int = 3): List<Finding> =
        findings
            .filter { it.severity != Severity.INFO }
            .sortedWith(compareByDescending<Finding> { it.severity.weight }.thenBy { it.id })
            .take(count)
}

package com.apkguard.app.data.vt

import kotlinx.serialization.Serializable

// VirusTotal API v3 response models. Every field except ids is optional so the
// parser survives schema additions and partial reports.

@Serializable
data class VtFileResponse(val data: VtFileData? = null)

@Serializable
data class VtFileData(
    val id: String? = null,
    val attributes: VtFileAttributes? = null,
)

@Serializable
data class VtFileAttributes(
    val last_analysis_stats: VtStats? = null,
    val reputation: Long? = null,
    val meaningful_name: String? = null,
    val popular_threat_classification: VtThreatClassification? = null,
    val last_analysis_results: Map<String, VtEngineResult>? = null,
)

@Serializable
data class VtStats(
    val malicious: Int = 0,
    val suspicious: Int = 0,
    val undetected: Int = 0,
    val harmless: Int = 0,
    val timeout: Int = 0,
)

@Serializable
data class VtThreatClassification(val suggested_threat_label: String? = null)

@Serializable
data class VtEngineResult(
    val engine_name: String? = null,
    val category: String? = null,
    val result: String? = null,
)

@Serializable
data class VtUploadResponse(val data: VtUploadData? = null)

@Serializable
data class VtUploadData(val id: String? = null)

@Serializable
data class VtAnalysisResponse(val data: VtAnalysisData? = null)

@Serializable
data class VtAnalysisData(
    val id: String? = null,
    val attributes: VtAnalysisAttributes? = null,
)

@Serializable
data class VtAnalysisAttributes(
    val status: String? = null,
    val stats: VtStats? = null,
)

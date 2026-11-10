package com.apkguard.app.data.vt

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class VirusTotalModelsTest {

    private val json = Json { ignoreUnknownKeys = true }

    @Test
    fun `parses a full file report and maps to summary`() {
        val payload = """
            {
              "data": {
                "id": "abc123",
                "type": "file",
                "attributes": {
                  "size": 123456,
                  "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 1,
                    "undetected": 55,
                    "harmless": 0,
                    "timeout": 2
                  },
                  "reputation": -35,
                  "meaningful_name": "bad.apk",
                  "popular_threat_classification": { "suggested_threat_label": "trojan/banker" },
                  "last_analysis_results": {
                    "Engine1": { "engine_name": "Engine1", "category": "malicious", "result": "Trojan.Banker" },
                    "Engine2": { "engine_name": "Engine2", "category": "malicious", "result": "Android.Trojan" },
                    "Engine3": { "engine_name": "Engine3", "category": "undetected" },
                    "Engine4": { "engine_name": "Engine4", "category": "suspicious", "result": "heur" }
                  }
                }
              }
            }
        """.trimIndent()

        val response = json.decodeFromString<VtFileResponse>(payload)
        val attributes = response.data?.attributes
        assertNotNull(attributes)
        val summary = attributes!!.toVtSummary()
        assertEquals(12, summary.malicious)
        assertEquals(1, summary.suspicious)
        assertEquals(55, summary.undetected)
        assertEquals(70, summary.totalEngines) // 12+1+55+0+2
        assertEquals(-35L, summary.reputation)
        assertEquals("trojan/banker", summary.threatLabel)
        assertEquals(listOf("Engine1", "Engine2", "Engine4"), summary.flaggedEngines)
    }

    @Test
    fun `ignores unknown fields and missing sections`() {
        val payload = """{ "data": { "id": "x", "attributes": { "some_future_field": true } } }"""
        val response = json.decodeFromString<VtFileResponse>(payload)
        val summary = response.data?.attributes?.toVtSummary()
        assertNotNull(summary)
        assertEquals(0, summary!!.malicious)
        assertEquals(0, summary.totalEngines)
        assertNull(summary.threatLabel)
    }

    @Test
    fun `empty payload decodes without crashing`() {
        val response = json.decodeFromString<VtFileResponse>("{}")
        assertNull(response.data)
    }

    @Test
    fun `parses an upload acknowledgement and analysis status`() {
        val upload = json.decodeFromString<VtUploadResponse>(
            """{ "data": { "id": "upload-123", "type": "analysis" } }""",
        )
        assertEquals("upload-123", upload.data?.id)

        val analysis = json.decodeFromString<VtAnalysisResponse>(
            """{ "data": { "id": "upload-123", "attributes": { "status": "completed",
                "stats": { "malicious": 3, "suspicious": 0, "undetected": 60, "harmless": 0, "timeout": 0 } } } }""",
        )
        assertEquals("completed", analysis.data?.attributes?.status)
        assertEquals(3, analysis.data?.attributes?.stats?.malicious)
    }
}

package com.apkguard.app.data.vt

import com.apkguard.app.domain.model.VtSummary
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.asRequestBody
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.kotlinx.serialization.asConverterFactory
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path
import java.io.File
import java.util.concurrent.TimeUnit

interface VirusTotalApi {
    @GET("api/v3/files/{hash}")
    suspend fun fileReport(
        @Path("hash") hash: String,
        @Header("x-apikey") apiKey: String,
    ): Response<VtFileResponse>

    @Multipart
    @POST("api/v3/files")
    suspend fun uploadFile(
        @Header("x-apikey") apiKey: String,
        @Part file: MultipartBody.Part,
    ): Response<VtUploadResponse>

    @GET("api/v3/analyses/{id}")
    suspend fun analysis(
        @Path("id") analysisId: String,
        @Header("x-apikey") apiKey: String,
    ): Response<VtAnalysisResponse>
}

sealed class VtException(message: String) : Exception(message) {
    class RateLimited : VtException("rate_limited")
    class InvalidKey : VtException("invalid_key")
    class NotFound : VtException("not_found")
    class TooLarge : VtException("too_large")
    class Processing : VtException("processing")
    class Network(cause: Throwable) : VtException(cause.message ?: "network")
}

/**
 * VirusTotal client. Hash lookups come first; uploads only ever happen when the
 * UI has collected the user's explicit consent. Every request is throttled to
 * respect the free-tier quota of 4 requests/minute.
 */
class VirusTotalRepository {

    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }

    private val okHttp = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(60, TimeUnit.SECONDS)
        .build()

    private val api: VirusTotalApi = Retrofit.Builder()
        .baseUrl("https://www.virustotal.com/")
        .client(okHttp)
        .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
        .build()
        .create(VirusTotalApi::class.java)

    companion object {
        const val FREE_TIER_MAX_UPLOAD_BYTES: Long = 32L * 1024 * 1024
        private const val MIN_REQUEST_INTERVAL_MS = 16_000L // < 4 requests/minute
        private const val MAX_ANALYSIS_POLLS = 4
        private const val POLL_INTERVAL_MS = 15_000L
    }

    private var lastRequestAtMs = 0L

    private suspend fun <T> throttled(block: suspend () -> T): T {
        val waitMs = lastRequestAtMs + MIN_REQUEST_INTERVAL_MS - System.currentTimeMillis()
        if (waitMs > 0) delay(waitMs)
        return block().also { lastRequestAtMs = System.currentTimeMillis() }
    }

    /** @return null when VirusTotal has never seen this hash (404). */
    suspend fun lookupByHash(sha256: String, apiKey: String): VtSummary? {
        val response = try {
            throttled { api.fileReport(sha256, apiKey) }
        } catch (e: Exception) {
            throw VtException.Network(e)
        }
        return when {
            response.code() == 404 -> null
            response.code() == 401 || response.code() == 403 -> throw VtException.InvalidKey()
            response.code() == 429 -> throw VtException.RateLimited()
            response.isSuccessful -> response.body()?.data?.attributes?.toVtSummary()
            else -> throw VtException.Network(IllegalStateException("HTTP ${response.code()}"))
        }
    }

    /**
     * Uploads the file and polls the analysis until it completes (or attempts run out,
     * in which case [VtException.Processing] tells the UI to retry later via the hash).
     */
    suspend fun uploadAndScan(file: File, sha256: String, apiKey: String): VtSummary? {
        if (file.length() > FREE_TIER_MAX_UPLOAD_BYTES) throw VtException.TooLarge()

        val upload = try {
            throttled {
                val body = MultipartBody.Part.createFormData(
                    "file",
                    file.name,
                    file.asRequestBody("application/octet-stream".toMediaType()),
                )
                api.uploadFile(apiKey, body)
            }
        } catch (e: VtException) {
            throw e
        } catch (e: Exception) {
            throw VtException.Network(e)
        }

        val analysisId = when {
            upload.code() == 401 || upload.code() == 403 -> throw VtException.InvalidKey()
            upload.code() == 429 -> throw VtException.RateLimited()
            upload.isSuccessful -> upload.body()?.data?.id
                ?: throw VtException.Network(IllegalStateException("no analysis id"))
            else -> throw VtException.Network(IllegalStateException("HTTP ${upload.code()}"))
        }

        repeat(MAX_ANALYSIS_POLLS) {
            delay(POLL_INTERVAL_MS)
            val analysis = try {
                throttled { api.analysis(analysisId, apiKey) }
            } catch (e: VtException) {
                throw e
            } catch (e: Exception) {
                throw VtException.Network(e)
            }
            if (analysis.code() == 429) throw VtException.RateLimited()
            if (analysis.isSuccessful && analysis.body()?.data?.attributes?.status == "completed") {
                return lookupByHash(sha256, apiKey)
            }
        }
        throw VtException.Processing()
    }
}

internal fun VtFileAttributes.toVtSummary(): VtSummary {
    val stats = last_analysis_stats ?: VtStats()
    val results = last_analysis_results ?: emptyMap()
    val flagged = results.values
        .filter { it.category == "malicious" || it.category == "suspicious" }
        .mapNotNull { it.engine_name }
        .sorted()
    val total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless + stats.timeout
    return VtSummary(
        malicious = stats.malicious,
        suspicious = stats.suspicious,
        undetected = stats.undetected,
        harmless = stats.harmless,
        timeout = stats.timeout,
        totalEngines = total,
        reputation = reputation,
        threatLabel = popular_threat_classification?.suggested_threat_label,
        flaggedEngines = flagged,
    )
}

package com.homenode.storage.cloud

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

enum class CloudProvider { GOOGLE_DRIVE, ONEDRIVE, DROPBOX }

/**
 * Where an upload lands. [existingId] != null means "replace this object";
 * the old object must stay intact until the provider commits the new one.
 * [remotePath] is required by path-addressed providers (Dropbox).
 */
data class UploadTarget(
  val parentId: String?,
  val name: String,
  val existingId: String? = null,
  val remotePath: String? = null,
  val allowReplace: Boolean = existingId != null,
)

data class RemoteObject(val id: String, val name: String, val size: Long)

sealed class UploadException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class QuotaExceeded(val provider: CloudProvider, detail: String) :
        UploadException("$provider quota/size limit exceeded: $detail")
    class SizeMismatch(val expected: Long, val actual: Long) :
        UploadException("expectedSize=$expected but stream carried ${if (actual < 0) "more" else actual.toString()} bytes")
    class SizeRequired(val provider: CloudProvider) :
        UploadException("$provider requires expectedSize up front")
    class ProviderError(val provider: CloudProvider, val status: Int, detail: String) :
        UploadException("$provider HTTP $status: $detail")
    class ProviderUnavailable(val provider: CloudProvider) :
        UploadException("No upload-session adapter configured for $provider (failing closed)")
}

/** One resumable upload. Offsets are bytes already accepted by the provider. */
interface UploadSession {
    /** Non-final chunk. Only ever called with len a multiple of the adapter's granularity. */
    suspend fun append(buf: ByteArray, len: Int, offset: Long)

    /** Final chunk (len may be 0 only when totalSize == 0). The object becomes visible here, not before. */
    suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject

    /** Best-effort cleanup of an uncommitted session. Must be safe to call more than once. */
    suspend fun abort()
}

interface CloudUploadAdapter {
    val provider: CloudProvider
    val maxObjectBytes: Long
    val chunkGranularityBytes: Int
    /** Bytes buffered/sent per request. Must be a multiple of [chunkGranularityBytes]. */
    val chunkSizeBytes: Int
    val requiresKnownSize: Boolean
    suspend fun open(target: UploadTarget, expectedSize: Long?): UploadSession
}

// ---- minimal HTTP seam so adapters are testable without a network ----

class HttpRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String> = emptyMap(),
    val body: ByteArray = EMPTY,
    val bodyLength: Int = body.size,
) { companion object { val EMPTY = ByteArray(0) } }

class HttpResponse(val status: Int, val headers: Map<String, String> = emptyMap(), val body: ByteArray = ByteArray(0)) {
    /** Header names are expected lower-cased by the transport. */
    fun header(name: String): String? = headers[name.lowercase()]
    fun text(): String = body.toString(Charsets.UTF_8)
}

interface HttpTransport { suspend fun execute(request: HttpRequest): HttpResponse }
fun interface TokenProvider { suspend fun accessToken(): String }

internal fun HttpResponse.toUploadException(provider: CloudProvider): UploadException {
    val t = text()
    val quota = status == 507 ||
        ((status == 403 || status == 429 || status == 409) &&
            listOf("quota", "insufficient_space", "storagequota").any { t.contains(it, ignoreCase = true) })
    return if (quota) UploadException.QuotaExceeded(provider, t.take(200))
    else UploadException.ProviderError(provider, status, t.take(200))
}

/**
 * Streams a Flow<ByteArray> into a provider session using one buffer of at most
 * [CloudUploadAdapter.chunkSizeBytes]. A full buffer is only flushed as "non-final"
 * once more data arrives, so the last buffer is always the (possibly aligned) final
 * chunk and expectedSize is verified BEFORE the commit request is sent.
 */
class StreamingUploader(private val adapter: CloudUploadAdapter) {

    suspend fun upload(target: UploadTarget, expectedSize: Long?, body: Flow<ByteArray>): RemoteObject {
        require(adapter.chunkGranularityBytes > 0 && adapter.chunkSizeBytes > 0 &&
            adapter.chunkSizeBytes % adapter.chunkGranularityBytes == 0) {
            "chunkSizeBytes must be a multiple of ${adapter.chunkGranularityBytes}"
        }
        if (expectedSize != null) {
            require(expectedSize >= 0) { "expectedSize < 0" }
            if (expectedSize > adapter.maxObjectBytes)
                throw UploadException.QuotaExceeded(adapter.provider, "$expectedSize > ${adapter.maxObjectBytes}")
        } else if (adapter.requiresKnownSize) {
            throw UploadException.SizeRequired(adapter.provider)
        }

        val session = adapter.open(target, expectedSize)
        try {
            val cap = if (expectedSize == null) adapter.chunkSizeBytes
            else minOf(adapter.chunkSizeBytes.toLong(), maxOf(expectedSize, 1L)).toInt()
            val buf = ByteArray(cap)
            var filled = 0
            var sent = 0L
            var total = 0L

            body.collect { chunk ->
                val chunkBytes = chunk.size.toLong()
                if (expectedSize != null && chunkBytes > expectedSize - total) {
                    throw UploadException.SizeMismatch(expectedSize, -1)
                }
                if (chunkBytes > adapter.maxObjectBytes - total)
                    throw UploadException.QuotaExceeded(adapter.provider, "stream exceeded ${adapter.maxObjectBytes}")
                total += chunkBytes
                var pos = 0
                while (pos < chunk.size) {
                    if (filled == buf.size) {
                        check(filled % adapter.chunkGranularityBytes == 0)
                        session.append(buf, filled, sent)
                        sent += filled
                        filled = 0
                    }
                    val n = minOf(chunk.size - pos, buf.size - filled)
                    System.arraycopy(chunk, pos, buf, filled, n)
                    filled += n
                    pos += n
                }
            }
            if (expectedSize != null && total != expectedSize) throw UploadException.SizeMismatch(expectedSize, total)
            return session.finish(buf, filled, sent, total)
        } catch (t: Throwable) {
            // Also runs on cancellation: abort must complete even though this coroutine is cancelled.
            withContext(NonCancellable) { runCatching { session.abort() } }
            throw t
        }
    }
}

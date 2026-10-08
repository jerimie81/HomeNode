package com.homenode.storage.cloud

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.advanceUntilIdle
import kotlin.test.*

/** TEST-ONLY adapter. Lives in src/test so production cannot reference it. */
class InMemoryUploadAdapter(
    override val provider: CloudProvider = CloudProvider.DROPBOX,
    override val maxObjectBytes: Long = 1_000_000,
    override val chunkGranularityBytes: Int = 4,
    override val chunkSizeBytes: Int = 8,
    override val requiresKnownSize: Boolean = false,
    val failAppendAt: Int? = null,
) : CloudUploadAdapter {
    val remote = mutableMapOf<String, ByteArray>()
    val appendSizes = mutableListOf<Int>()
    var opened = 0; var aborted = 0; var committed = 0
    var gate: CompletableDeferred<Unit>? = null

    override suspend fun open(target: UploadTarget, expectedSize: Long?): UploadSession {
        opened++
        val staged = java.io.ByteArrayOutputStream()
        return object : UploadSession {
            override suspend fun append(buf: ByteArray, len: Int, offset: Long) {
                assertEquals(offset, staged.size().toLong())
                assertEquals(0, len % chunkGranularityBytes)
                assertTrue(len <= chunkSizeBytes)
                if (failAppendAt == appendSizes.size) throw UploadException.ProviderError(provider, 500, "boom")
                appendSizes += len; staged.write(buf, 0, len)
                gate?.await()
            }
            override suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject {
                staged.write(buf, 0, len)
                remote[target.name] = staged.toByteArray()      // visible only at commit
                committed++
                return RemoteObject("id-${target.name}", target.name, totalSize)
            }
            override suspend fun abort() { aborted++ }
        }
    }
}

private fun bytes(n: Int) = ByteArray(n) { (it % 251).toByte() }
private fun pieces(data: ByteArray, size: Int): Flow<ByteArray> =
    data.toList().chunked(size).map { it.toByteArray() }.asFlow()

@OptIn(ExperimentalCoroutinesApi::class)
class StreamingUploaderTest {
    private val target = UploadTarget("p", "f.bin", remotePath = "/f.bin")

    @Test fun multiChunkUploadIsBoundedAndExact() = runTest {
        val a = InMemoryUploadAdapter()
        val data = bytes(20)                                   // 8 + 8 + final 4
        val r = StreamingUploader(a).upload(target, 20, pieces(data, 3))
        assertEquals(listOf(8, 8), a.appendSizes)
        assertContentEquals(data, a.remote["f.bin"]); assertEquals(20, r.size); assertEquals(0, a.aborted)
    }

    @Test fun exactMultipleSendsLastBufferAsFinal() = runTest {
        val a = InMemoryUploadAdapter()
        StreamingUploader(a).upload(target, 16, pieces(bytes(16), 5))
        assertEquals(listOf(8), a.appendSizes)                 // second 8 bytes went with finish()
        assertEquals(16, a.remote["f.bin"]!!.size)
    }

    @Test fun emptyFileCommits() = runTest {
        val a = InMemoryUploadAdapter()
        StreamingUploader(a).upload(target, 0, flow { })
        assertEquals(0, a.remote["f.bin"]!!.size)
    }

    @Test fun quotaRejectedBeforeSessionOpens() = runTest {
        val a = InMemoryUploadAdapter(maxObjectBytes = 10)
        assertFailsWith<UploadException.QuotaExceeded> { StreamingUploader(a).upload(target, 11, pieces(bytes(11), 4)) }
        assertEquals(0, a.opened)
    }

    @Test fun quotaEnforcedWhileStreamingWhenSizeUnknown() = runTest {
        val a = InMemoryUploadAdapter(maxObjectBytes = 10)
        assertFailsWith<UploadException.QuotaExceeded> { StreamingUploader(a).upload(target, null, pieces(bytes(30), 4)) }
        assertEquals(1, a.aborted); assertTrue(a.remote.isEmpty())
    }

    @Test fun shortStreamIsSizeMismatchAndNothingCommits() = runTest {
        val a = InMemoryUploadAdapter()
        assertFailsWith<UploadException.SizeMismatch> { StreamingUploader(a).upload(target, 20, pieces(bytes(15), 4)) }
        assertEquals(1, a.aborted); assertEquals(0, a.committed)
    }

    @Test fun longStreamIsSizeMismatchAndAbortsEarly() = runTest {
        val a = InMemoryUploadAdapter()
        assertFailsWith<UploadException.SizeMismatch> { StreamingUploader(a).upload(target, 10, pieces(bytes(40), 4)) }
        assertEquals(1, a.aborted); assertEquals(0, a.committed)
    }

    @Test fun cancellationAbortsSession() = runTest {
        val a = InMemoryUploadAdapter().apply { gate = CompletableDeferred() }
        val job = async { StreamingUploader(a).upload(target, 100, pieces(bytes(100), 8)) }
        advanceUntilIdle()                                     // parked inside the first append
        job.cancel(); advanceUntilIdle()
        assertTrue(job.isCancelled); assertEquals(1, a.aborted); assertTrue(a.remote.isEmpty())
    }

    @Test fun providerErrorAbortsAndPreservesExistingRemote() = runTest {
        val a = InMemoryUploadAdapter(failAppendAt = 1)
        val old = bytes(3); a.remote["f.bin"] = old
        assertFailsWith<UploadException.ProviderError> {
            StreamingUploader(a).upload(target.copy(existingId = "id-f.bin"), 40, pieces(bytes(40), 8))
        }
        assertEquals(1, a.aborted); assertContentEquals(old, a.remote["f.bin"])
    }

    @Test fun replacementHappensOnlyAtCommit() = runTest {
        val a = InMemoryUploadAdapter(); a.remote["f.bin"] = bytes(3)
        val fresh = bytes(21)
        StreamingUploader(a).upload(target.copy(existingId = "id-f.bin"), 21, pieces(fresh, 7))
        assertContentEquals(fresh, a.remote["f.bin"])
    }

    @Test fun providerWithoutAdapterFailsClosed() {
        val reg = CloudUploadRegistry.production(http = NoHttp, tokens = { null })
        for (p in CloudProvider.values()) assertFailsWith<UploadException.ProviderUnavailable> { reg.uploaderFor(p) }
    }
}

private object NoHttp : HttpTransport { override suspend fun execute(request: HttpRequest) = error("no network in tests") }

/** Records requests and replays canned responses so we can assert the wire protocol. */
class FakeHttp(private val respond: (HttpRequest) -> HttpResponse) : HttpTransport {
    class Seen(val method: String, val url: String, val headers: Map<String, String>, val len: Int)
    val seen = mutableListOf<Seen>()
    override suspend fun execute(request: HttpRequest): HttpResponse {
        seen += Seen(request.method, request.url, request.headers, request.bodyLength); return respond(request)
    }
}

class OneDriveAdapterTest {
    private val unit = 320 * 1024
    private val tokens = TokenProvider { "tok" }

    private fun fake() = FakeHttp { r ->
        when {
            r.url.endsWith("createUploadSession") ->
                HttpResponse(200, body = """{"uploadUrl":"https://upload.example/s1"}""".toByteArray())
            r.method == "DELETE" -> HttpResponse(204)
            r.headers["Content-Range"]!!.let { cr ->
                val (range, total) = cr.removePrefix("bytes ").split('/')
                range.substringAfter('-').toLong() + 1 == total.toLong()
            } -> HttpResponse(201, body = """{"id":"i1","name":"f","size":1}""".toByteArray())
            else -> HttpResponse(202)
        }
    }

    @Test fun nonFinalChunksAreMultiplesOf320KiBAndFinalIsUnaligned() = runTest {
        val http = fake()
        val size = unit * 32 * 2 + 12345L                       // two full 10 MiB requests + odd tail
        val chunk = ByteArray(1 * 1024 * 1024)
        val body = flow { var left = size; while (left > 0) { val n = minOf(left, chunk.size.toLong()).toInt(); emit(chunk.copyOf(n)); left -= n } }
        StreamingUploader(OneDriveUploadAdapter(http, tokens)).upload(UploadTarget("root", "f.bin"), size, body)

        val puts = http.seen.filter { it.method == "PUT" }
        assertEquals(3, puts.size)
        puts.dropLast(1).forEach { assertEquals(0, it.len % unit) }
        assertEquals(12345, puts.last().len)
        assertEquals("bytes 0-${unit * 32 - 1}/$size", puts[0].headers["Content-Range"])
        assertEquals("bytes ${unit * 64}-${size - 1}/$size", puts[2].headers["Content-Range"])
        assertTrue(puts.none { it.headers.containsKey("Authorization") })   // pre-auth upload URL
    }

    @Test fun createSessionRequestsReplaceAndFailureDeletesSession() = runTest {
        val size = unit * 32 * 2L
        val body = flow { repeat(2) { emit(ByteArray(unit * 32)) } }
        // the first non-final PUT fails with a quota error
        val failing = FakeHttp { r ->
            when {
                r.url.endsWith("createUploadSession") -> HttpResponse(200, body = """{"uploadUrl":"https://u/s"}""".toByteArray())
                r.method == "DELETE" -> HttpResponse(204)
                else -> HttpResponse(507, body = "quotaLimitReached".toByteArray())
            }
        }
        assertFailsWith<UploadException.QuotaExceeded> {
            StreamingUploader(OneDriveUploadAdapter(failing, tokens)).upload(UploadTarget("root", "f.bin"), size, body)
        }
        assertEquals(1, failing.seen.count { it.method == "DELETE" })
        assertEquals("Bearer tok", failing.seen.first().headers["Authorization"])
    }

    @Test fun unknownSizeIsRejected() = runTest {
        assertFailsWith<UploadException.SizeRequired> {
            StreamingUploader(OneDriveUploadAdapter(fake(), tokens)).upload(UploadTarget("root", "f"), null, flow { })
        }
    }
}

class GoogleDriveAdapterTest {
    @Test fun appendFailureAbortsResumableSessionAndDoesNotCommit() = runTest {
        val http = FakeHttp { request ->
            when {
                request.method == "GET" -> HttpResponse(200, body = """{"files":[]}""".toByteArray())
                request.method == "POST" -> HttpResponse(200, mapOf("location" to "https://upload.example/g-fail"))
                request.method == "DELETE" -> HttpResponse(204)
                else -> HttpResponse(500, body = "server error".toByteArray())
            }
        }
        assertFailsWith<UploadException.ProviderError> {
            StreamingUploader(GoogleDriveUploadAdapter(http, TokenProvider { "tok" })).upload(
                UploadTarget("root", "fail.bin"),
                8L * 1024 * 1024 + 1,
                flow { emit(ByteArray(8 * 1024 * 1024 + 1)) },
            )
        }
        assertEquals(listOf("GET", "POST", "PUT", "DELETE"), http.seen.map { it.method })
    }

    @Test fun resumableChunksUseAlignedRangesAndCommitOnlyAtFinish() = runTest {
        val http = FakeHttp { request ->
            when {
                request.method == "GET" -> HttpResponse(200, body = """{"files":[]}""".toByteArray())
                request.method == "POST" -> HttpResponse(200, mapOf("location" to "https://upload.example/g1"))
                request.method == "DELETE" -> HttpResponse(204)
                request.headers["Content-Range"]?.endsWith("/*") == true -> {
                    val end = request.headers.getValue("Content-Range").substringAfter('-').substringBefore('/').toLong()
                    HttpResponse(308, mapOf("range" to "bytes=0-$end"))
                }
                else -> HttpResponse(201, body = """{"id":"g1","name":"f"}""".toByteArray())
            }
        }
        val size = 8L * 1024 * 1024 + 7
        val body = flow { emit(ByteArray(size.toInt())) }
        val remote = StreamingUploader(GoogleDriveUploadAdapter(http, TokenProvider { "tok" }))
            .upload(UploadTarget("root", "f.bin"), size, body)
        assertEquals("g1", remote.id)
        val puts = http.seen.filter { it.method == "PUT" }
        assertEquals(2, puts.size)
        assertEquals(0, puts.first().len % (256 * 1024))
        assertEquals("bytes 0-${8L * 1024 * 1024 - 1}/*", puts.first().headers["Content-Range"])
        assertEquals("bytes ${8L * 1024 * 1024}-${size - 1}/$size", puts.last().headers["Content-Range"])
    }

    @Test fun createNewRejectsAnExistingNameBeforeOpeningUploadSession() = runTest {
        val http = FakeHttp { request ->
            if (request.method == "GET") {
                HttpResponse(200, body = """{"files":[{"id":"old"}]}""".toByteArray())
            } else error("upload session must not open for a duplicate")
        }
        val failure = assertFailsWith<UploadException.ProviderError> {
            StreamingUploader(GoogleDriveUploadAdapter(http, TokenProvider { "tok" }))
                .upload(UploadTarget("root", "existing.txt"), 1L, flow { emit(byteArrayOf(1)) })
        }
        assertEquals(409, failure.status)
        assertEquals(listOf("GET"), http.seen.map { it.method })
    }
}

class DropboxAdapterTest {
    @Test fun appendFailureDropsSessionWithoutCallingFinish() = runTest {
        val http = FakeHttp { request ->
            when {
                request.url.endsWith("upload_session/start") -> HttpResponse(200, body = """{"session_id":"s-fail"}""".toByteArray())
                request.url.endsWith("upload_session/append_v2") -> HttpResponse(503, body = "temporarily unavailable".toByteArray())
                else -> error("finish must not be called after append failure")
            }
        }
        assertFailsWith<UploadException.ProviderError> {
            StreamingUploader(DropboxUploadAdapter(http, TokenProvider { "tok" })).upload(
                UploadTarget("root", "fail.bin", remotePath = "/fail.bin"),
                null,
                flow { emit(ByteArray(16 * 1024 * 1024)) },
            )
        }
        assertEquals(listOf("upload_session/start", "upload_session/append_v2"), http.seen.map { it.url.substringAfterLast("/files/") })
    }

    @Test fun uploadSessionUsesRemotePathAndOverwriteAtCommit() = runTest {
        val http = FakeHttp { request ->
            when {
                request.url.endsWith("upload_session/start") -> HttpResponse(200, body = """{"session_id":"s1"}""".toByteArray())
                request.url.endsWith("upload_session/append_v2") -> HttpResponse(200)
                else -> HttpResponse(200, body = """{"id":"d1","name":"f.bin","size":9}""".toByteArray())
            }
        }
        val target = UploadTarget("root", "f.bin", existingId = "d1", remotePath = "/f.bin", allowReplace = true)
        val result = StreamingUploader(DropboxUploadAdapter(http, TokenProvider { "tok" }))
            .upload(target, 9L, flow { emit(ByteArray(9)) })
        assertEquals("d1", result.id)
        val finish = http.seen.single { it.url.endsWith("upload_session/finish") }
        assertTrue(finish.headers["Dropbox-API-Arg"].orEmpty().contains("overwrite"))
        assertTrue(finish.headers["Dropbox-API-Arg"].orEmpty().contains("/f.bin"))
    }
}

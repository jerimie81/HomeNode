package com.homenode.storage.cloud

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okio.BufferedSink
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Response

/** Executes upload-session requests while retaining only the request chunk and a bounded response. */
class OkHttpUploadTransport(
  private val client: OkHttpClient = OkHttpClient(),
  private val maxResponseBytes: Long = 1024L * 1024L,
) : HttpTransport {
  override suspend fun execute(request: HttpRequest): HttpResponse {
    require(request.bodyLength in 0..request.body.size) { "Invalid HTTP request body length" }
    val uri = URI(request.url)
    require(uri.scheme == "https" && !uri.host.isNullOrBlank()) { "Cloud upload requests require HTTPS" }
    val builder = Request.Builder().url(request.url)
    request.headers.forEach { (name, value) -> builder.header(name, value) }
    val body = object : RequestBody() {
      override fun contentType() = (request.headers.entries.firstOrNull {
        it.key.equals("Content-Type", ignoreCase = true)
      }?.value ?: "application/octet-stream").toMediaType()

      override fun contentLength(): Long = request.bodyLength.toLong()

      override fun writeTo(sink: BufferedSink) {
        if (request.bodyLength > 0) sink.write(request.body, 0, request.bodyLength)
      }
    }
    val verb = request.method.uppercase()
    if (verb in setOf("POST", "PUT", "PATCH", "DELETE")) {
      builder.method(verb, if (verb == "DELETE" && request.bodyLength == 0) null else body)
    } else {
      builder.method(verb, null)
    }
    val call = client.newCall(builder.build())
    return suspendCancellableCoroutine { continuation ->
      continuation.invokeOnCancellation { call.cancel() }
      call.enqueue(object : Callback {
        override fun onFailure(call: Call, e: IOException) {
          if (continuation.isActive) continuation.resumeWith(Result.failure(e))
        }

        override fun onResponse(call: Call, response: Response) {
          val result = try {
            response.use { responseValue ->
              val responseBody = responseValue.body
              val bytes = if (responseBody == null) ByteArray(0) else {
                val output = ByteArrayOutputStream()
                responseBody.byteStream().use { input ->
                  val buffer = ByteArray(8192)
                  var total = 0L
                  while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > maxResponseBytes) throw IOException("Provider response exceeds configured limit")
                    output.write(buffer, 0, count)
                  }
                }
                output.toByteArray()
              }
              val headers = mutableMapOf<String, String>()
              for (i in 0 until responseValue.headers.size) {
                headers[responseValue.headers.name(i).lowercase()] = responseValue.headers.value(i)
              }
              HttpResponse(responseValue.code, headers, bytes)
            }
          } catch (t: Throwable) {
            if (continuation.isActive) continuation.resumeWith(Result.failure(t))
            return
          }
          if (continuation.isActive) continuation.resumeWith(Result.success(result))
        }
      })
    }
  }
}

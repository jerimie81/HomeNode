package com.homenode.storage.cloud

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import java.net.URLEncoder

private const val KiB = 1024
private const val MiB = 1024 * KiB
private const val GiB = 1024L * MiB

private fun enc(s: String) = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
private fun parse(r: HttpResponse): JsonObject = Json.parseToJsonElement(r.text()).jsonObject
private fun JsonObject.str(k: String) = this[k]?.jsonPrimitive?.content ?: error("missing $k in provider response")

/** Dropbox-API-Arg must be ASCII; escape everything above 0x7E. */
private fun String.asciiSafe(): String = buildString {
    for (c in this@asciiSafe) if (c.code in 0x20..0x7E) append(c) else append("\\u%04x".format(c.code))
}

// ───────────────────────────── OneDrive ─────────────────────────────

class OneDriveUploadAdapter(
    private val http: HttpTransport,
    private val tokens: TokenProvider,
    private val graph: String = "https://graph.microsoft.com/v1.0",
) : CloudUploadAdapter {
    override val provider = CloudProvider.ONEDRIVE
    override val maxObjectBytes = 250 * GiB
    override val chunkGranularityBytes = 320 * KiB        // 327,680: required multiple for non-final chunks
    override val chunkSizeBytes = 32 * chunkGranularityBytes // 10 MiB per request
    override val requiresKnownSize = true                  // Content-Range needs the total

    override suspend fun open(target: UploadTarget, expectedSize: Long?): UploadSession {
        val total = requireNotNull(expectedSize)
        val base = if (target.existingId != null) "$graph/me/drive/items/${enc(target.existingId)}"
                   else "$graph/me/drive/items/${enc(target.parentId ?: "root")}:/${enc(target.name)}:"
        val auth = mapOf("Authorization" to "Bearer ${tokens.accessToken()}")
        if (total == 0L) {
            val emptyHeaders = if (target.allowReplace) auth else auth + ("If-None-Match" to "*")
            return EmptySession(http, "$base/content", emptyHeaders)
        }
        val body = buildJsonObject {
            put("item", buildJsonObject {
                put("@microsoft.graph.conflictBehavior", if (target.allowReplace) "replace" else "fail")
            })
        }.toString().toByteArray()
        val r = http.execute(HttpRequest("POST", "$base/createUploadSession",
            auth + ("Content-Type" to "application/json"), body))
        if (r.status != 200) throw r.toUploadException(provider)
        return Session(parse(r).str("uploadUrl"), total)
    }

    private inner class Session(val uploadUrl: String, val total: Long) : UploadSession {
        // Upload URLs are pre-authenticated: never send the bearer token to them.
        private fun put(buf: ByteArray, len: Int, offset: Long) = HttpRequest("PUT", uploadUrl,
            mapOf("Content-Range" to "bytes $offset-${offset + len - 1}/$total"), buf, len)

        override suspend fun append(buf: ByteArray, len: Int, offset: Long) {
            require(len % chunkGranularityBytes == 0) { "non-final OneDrive chunk must be a multiple of 320 KiB" }
            val r = http.execute(put(buf, len, offset))
            if (r.status != 202) throw r.toUploadException(provider)
        }

        override suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject {
            require(totalSize == total) { "total changed mid-session" }
            val r = http.execute(put(buf, len, offset))   // final chunk: any size
            if (r.status != 200 && r.status != 201) throw r.toUploadException(provider)
            val j = parse(r)
            return RemoteObject(j.str("id"), j.str("name"), j["size"]?.jsonPrimitive?.long ?: total)
        }

        override suspend fun abort() {
            val r = http.execute(HttpRequest("DELETE", uploadUrl))
            if (r.status !in setOf(204, 404)) throw r.toUploadException(provider)
        }
    }

    /** Zero-byte files cannot use an upload session; a single PUT is atomic anyway. */
    private inner class EmptySession(val http: HttpTransport, val url: String, val auth: Map<String, String>) : UploadSession {
        override suspend fun append(buf: ByteArray, len: Int, offset: Long) = error("unreachable for empty upload")
        override suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject {
            val r = http.execute(HttpRequest("PUT", url, auth))
            if (r.status != 200 && r.status != 201) throw r.toUploadException(provider)
            val j = parse(r); return RemoteObject(j.str("id"), j.str("name"), 0)
        }
        override suspend fun abort() {}
    }
}

// ───────────────────────────── Google Drive ─────────────────────────────

class GoogleDriveUploadAdapter(
    private val http: HttpTransport,
    private val tokens: TokenProvider,
    private val upload: String = "https://www.googleapis.com/upload/drive/v3/files",
) : CloudUploadAdapter {
    override val provider = CloudProvider.GOOGLE_DRIVE
    override val maxObjectBytes = 5L * 1024 * GiB          // 5 TiB per file
    override val chunkGranularityBytes = 256 * KiB         // non-final chunks: multiples of 256 KiB
    override val chunkSizeBytes = 32 * chunkGranularityBytes // 8 MiB
    override val requiresKnownSize = false

    override suspend fun open(target: UploadTarget, expectedSize: Long?): UploadSession {
        val uploadTarget = resolveTarget(target)
        val headers = mutableMapOf(
            "Authorization" to "Bearer ${tokens.accessToken()}",
            "Content-Type" to "application/json; charset=UTF-8",
            "X-Upload-Content-Type" to "application/octet-stream",
        )
        expectedSize?.let { headers["X-Upload-Content-Length"] = it.toString() }
        val req = if (uploadTarget.existingId != null) // PATCH keeps old content until the upload commits
            HttpRequest("PATCH", "$upload/${enc(uploadTarget.existingId)}?uploadType=resumable", headers, "{}".toByteArray())
        else {
            val meta = buildJsonObject {
                put("name", uploadTarget.name)
                uploadTarget.parentId?.let {
                    put("parents", kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive(it))))
                }
            }.toString().toByteArray()
            HttpRequest("POST", "$upload?uploadType=resumable", headers, meta)
        }
        val r = http.execute(req)
        if (r.status != 200) throw r.toUploadException(provider)
        return Session(r.header("location") ?: throw UploadException.ProviderError(provider, 200, "no session URI"))
    }

    private suspend fun resolveTarget(target: UploadTarget): UploadTarget {
        if (target.existingId != null) return target
        val escapedName = target.name.replace("\\", "\\\\").replace("'", "\\'")
        val query = buildString {
            append("name = '").append(escapedName).append("' and trashed = false")
            target.parentId?.let { append(" and '").append(it.replace("'", "\\'")).append("' in parents") }
        }
        val url = "https://www.googleapis.com/drive/v3/files?q=${enc(query)}&pageSize=2&fields=files(id,name)"
        val headers = mapOf("Authorization" to "Bearer ${tokens.accessToken()}")
        val response = http.execute(HttpRequest("GET", url, headers))
        if (response.status != 200) throw response.toUploadException(provider)
        val files = parse(response)["files"]?.jsonArray.orEmpty()
        if (files.size > 1) throw UploadException.ProviderError(provider, 409, "Multiple items have this name in the target folder")
        val existingId = files.singleOrNull()?.jsonObject?.str("id")
        if (existingId != null && !target.allowReplace) {
            throw UploadException.ProviderError(provider, 409, "Target already exists")
        }
        return if (existingId == null) target else target.copy(existingId = existingId)
    }

    private inner class Session(val sessionUri: String) : UploadSession {
        override suspend fun append(buf: ByteArray, len: Int, offset: Long) {
            require(len % chunkGranularityBytes == 0)
            val last = offset + len - 1
            val r = http.execute(HttpRequest("PUT", sessionUri, mapOf("Content-Range" to "bytes $offset-$last/*"), buf, len))
            if (r.status != 308) throw r.toUploadException(provider)
            val persisted = r.header("range")?.substringAfter("-")?.toLongOrNull()
            if (persisted != last) throw UploadException.ProviderError(provider, 308, "provider persisted up to $persisted, expected $last")
        }

        override suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject {
            val range = if (len == 0) "bytes */0" else "bytes $offset-${offset + len - 1}/$totalSize"
            val r = http.execute(HttpRequest("PUT", sessionUri, mapOf("Content-Range" to range), buf, len))
            if (r.status != 200 && r.status != 201) throw r.toUploadException(provider)
            val j = parse(r)
            return RemoteObject(j.str("id"), j["name"]?.jsonPrimitive?.content ?: "", totalSize)
        }

        override suspend fun abort() {
            val r = http.execute(HttpRequest("DELETE", sessionUri))
            if (r.status !in setOf(204, 404, 499)) throw r.toUploadException(provider) // 499 = cancelled
        }
    }
}

// ───────────────────────────── Dropbox ─────────────────────────────

class DropboxUploadAdapter(
    private val http: HttpTransport,
    private val tokens: TokenProvider,
    private val api: String = "https://content.dropboxapi.com/2/files",
) : CloudUploadAdapter {
    override val provider = CloudProvider.DROPBOX
    override val maxObjectBytes = 350 * GiB                // upload-session total limit
    override val chunkGranularityBytes = 4 * MiB           // Dropbox recommends 4 MiB multiples
    override val chunkSizeBytes = 2 * chunkGranularityBytes // 8 MiB (hard cap is 150 MiB/request)
    override val requiresKnownSize = false

    private suspend fun call(endpoint: String, arg: JsonObject, buf: ByteArray, len: Int): HttpResponse =
        http.execute(HttpRequest("POST", "$api/$endpoint", mapOf(
            "Authorization" to "Bearer ${tokens.accessToken()}",
            "Content-Type" to "application/octet-stream",
            "Dropbox-API-Arg" to arg.toString().asciiSafe(),
        ), buf, len))

    override suspend fun open(target: UploadTarget, expectedSize: Long?): UploadSession {
        val path = target.remotePath
            ?: throw IllegalArgumentException("Dropbox uploads need UploadTarget.remotePath")
        val r = call("upload_session/start", buildJsonObject { put("close", false) }, HttpRequest.EMPTY, 0)
        if (r.status != 200) throw r.toUploadException(provider)
        return Session(parse(r).str("session_id"), path, replace = target.allowReplace)
    }

    private inner class Session(val id: String, val path: String, val replace: Boolean) : UploadSession {
        private fun cursor(offset: Long) = buildJsonObject { put("session_id", id); put("offset", offset) }

        override suspend fun append(buf: ByteArray, len: Int, offset: Long) {
            require(len % chunkGranularityBytes == 0)
            val arg = buildJsonObject { put("cursor", cursor(offset)); put("close", false) }
            val r = call("upload_session/append_v2", arg, buf, len)
            if (r.status != 200) throw r.toUploadException(provider)
        }

        override suspend fun finish(buf: ByteArray, len: Int, offset: Long, totalSize: Long): RemoteObject {
            val commit = buildJsonObject {
                put("path", path)
                put("mode", if (replace) "overwrite" else "add")
                put("autorename", false)
                put("mute", true)
            }
            val arg = buildJsonObject { put("cursor", cursor(offset)); put("commit", commit) }
            val r = call("upload_session/finish", arg, buf, len)
            if (r.status != 200) throw r.toUploadException(provider)
            val j = parse(r)
            return RemoteObject(j.str("id"), j.str("name"), j["size"]?.jsonPrimitive?.long ?: totalSize)
        }

        // Dropbox has no cancel endpoint: an unfinished session never creates or touches a file
        // and expires server-side, so dropping it is the abort.
        override suspend fun abort() {}
    }
}

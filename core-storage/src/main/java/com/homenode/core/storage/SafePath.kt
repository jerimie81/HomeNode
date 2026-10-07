package com.homenode.core.storage

import java.text.Normalizer

/**
 * Validated, normalized relative path inside a single mount.
 * Cannot be constructed directly; always obtain via [PathValidator.parseRelative] or [PathValidator.parseVirtualPath].
 */
@JvmInline
value class SafePath private constructor(val value: String) {
  val segments: List<String>
    get() = if (value.isEmpty()) emptyList() else value.split('/')

  val name: String
    get() = segments.lastOrNull().orEmpty()

  val parent: SafePath?
    get() {
      val segs = segments
      if (segs.isEmpty()) return null
      return SafePath(segs.dropLast(1).joinToString("/"))
    }

  val isRoot: Boolean
    get() = value.isEmpty()

  fun child(segment: String): StorageResult<SafePath> {
    val combined = if (isRoot) segment else "$value/$segment"
    return PathValidator.parseRelative(combined)
  }

  override fun toString(): String = "/$value"

  companion object {
    val ROOT = SafePath("")

    internal fun createTrusted(normalized: String): SafePath = SafePath(normalized)
  }
}

/**
 * Parsed virtual path from the unified namespace `/<mountId>/<relativePath>`.
 * If the request targets `/` (root mount listing), [mountId] is null and [relativePath] is [SafePath.ROOT].
 */
data class VirtualPath(
  val mountId: MountId?,
  val relativePath: SafePath,
)

/**
 * Enforces Knowledge Base §8.4 PathValidator rules before any backend sees a path.
 */
object PathValidator {
  const val MAX_TOTAL_LENGTH = 1024
  const val MAX_SEGMENT_LENGTH = 255
  const val MAX_DEPTH = 32

  private val DRIVE_PREFIX_REGEX = Regex("^[a-zA-Z]:.*")
  private val PERCENT_ENCODED_REGEX = Regex("%[0-9a-fA-F]{2}")

  fun parseVirtualPath(rawInput: String): StorageResult<VirtualPath> {
    if (rawInput.isEmpty()) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Path must not be empty")
    }
    if (rawInput.length > MAX_TOTAL_LENGTH) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Path exceeds max length $MAX_TOTAL_LENGTH")
    }
    val nfc = Normalizer.normalize(rawInput, Normalizer.Form.NFC)
    if (nfc.length > MAX_TOTAL_LENGTH) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Normalized path exceeds max length $MAX_TOTAL_LENGTH")
    }
    if (nfc == "/") {
      return StorageResult.Success(VirtualPath(mountId = null, relativePath = SafePath.ROOT))
    }
    if (!nfc.startsWith("/")) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Virtual path must start with '/'")
    }
    val withoutLeadingSlash = nfc.substring(1)
    if (withoutLeadingSlash.endsWith("/") || withoutLeadingSlash.contains("//")) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Empty path segments are forbidden")
    }
    val firstSlash = withoutLeadingSlash.indexOf('/')
    val rawMountId = if (firstSlash == -1) withoutLeadingSlash else withoutLeadingSlash.substring(0, firstSlash)
    val mountId = MountId.parse(rawMountId).getOrElse {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Invalid mount ID segment")
    }
    val rawRelative = if (firstSlash == -1) "" else withoutLeadingSlash.substring(firstSlash + 1)
    val safeRelative = parseRelative(rawRelative).getOrElse { err ->
      return StorageResult.Failure(err.error, err.message)
    }
    return StorageResult.Success(VirtualPath(mountId = mountId, relativePath = safeRelative))
  }

  fun parseRelative(rawInput: String): StorageResult<SafePath> {
    if (rawInput.length > MAX_TOTAL_LENGTH) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Path exceeds max length $MAX_TOTAL_LENGTH")
    }
    val nfc = Normalizer.normalize(rawInput, Normalizer.Form.NFC)
    if (nfc.isEmpty()) {
      return StorageResult.Success(SafePath.ROOT)
    }

    // Reject control chars, NUL, backslashes, leading/trailing slash, ~, percent-encoded sequences
    for (ch in nfc) {
      if (ch == '\u0000' || ch.code < 0x20 || ch.code == 0x7F) {
        return StorageResult.Failure(StorageError.PATH_INVALID, "Control characters and NUL are forbidden")
      }
      if (ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') {
        return StorageResult.Failure(StorageError.PATH_INVALID, "Forbidden path character: $ch")
      }
    }
    if (nfc.startsWith("/") || nfc.endsWith("/") || nfc.contains("//") || nfc.contains("..")) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Relative path cannot have leading, trailing, double slashes, or '..'")
    }
    if (PERCENT_ENCODED_REGEX.containsMatchIn(nfc)) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Percent-encoded sequences are forbidden in paths")
    }
    if (DRIVE_PREFIX_REGEX.matches(nfc)) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Drive prefixes are forbidden")
    }

    val segments = nfc.split('/')
    if (segments.size > MAX_DEPTH) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Path exceeds max depth $MAX_DEPTH")
    }

    for (seg in segments) {
      if (seg.isEmpty() || seg.length > MAX_SEGMENT_LENGTH) {
        return StorageResult.Failure(StorageError.PATH_INVALID, "Invalid segment length")
      }
      if (seg == "." || seg == ".." || seg == "~" || seg.startsWith("~")) {
        return StorageResult.Failure(StorageError.PATH_INVALID, "Traversal or home segment forbidden")
      }
      if (seg.endsWith(".") || seg.endsWith(" ")) {
        return StorageResult.Failure(StorageError.PATH_INVALID, "Segments ending with dot or space are forbidden")
      }
    }

    return StorageResult.Success(SafePath.createTrusted(nfc))
  }
}

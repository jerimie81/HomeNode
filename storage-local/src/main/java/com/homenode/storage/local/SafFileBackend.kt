package com.homenode.storage.local

import com.homenode.core.storage.FileBackend
import com.homenode.core.storage.FileEntry
import com.homenode.core.storage.FileStat
import com.homenode.core.storage.ListPage
import com.homenode.core.storage.SafePath
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageException
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.WriteMode
import java.io.ByteArrayOutputStream
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.min
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext

data class SafDocumentMetadata(
  val documentId: String,
  val displayName: String,
  val isDirectory: Boolean,
  val sizeBytes: Long,
  val lastModifiedEpochMillis: Long,
)

/**
 * Narrow interface isolating Android Storage Access Framework (`DocumentsContract`) queries (§8.5, Slice S7).
 * Never concatenates path segments into document URIs; all lookups proceed hop-by-hop from [rootDocumentId].
 */
interface SafTreeAdapter {
  val rootDocumentId: String
  val isSimulated: Boolean
  fun isMediaMounted(): Boolean
  fun verifyPermissionGranted(requireWrite: Boolean = false): Boolean
  fun isChildDocument(parentDocumentId: String, candidateDocumentId: String): Boolean
  fun queryChildren(parentDocumentId: String): List<SafDocumentMetadata>
  fun statDocument(documentId: String): SafDocumentMetadata?
  fun readBytes(documentId: String, offset: Long, length: Int): ByteArray
  fun createOrReplaceFile(parentDocumentId: String, displayName: String, mode: WriteMode, bytes: ByteArray): SafDocumentMetadata
  fun createDirectory(parentDocumentId: String, displayName: String): SafDocumentMetadata
  fun deleteDocument(parentDocumentId: String, documentId: String, recursive: Boolean)
  fun moveDocument(
    sourceParentDocId: String,
    targetParentDocId: String,
    documentId: String,
    newDisplayName: String,
  ): SafDocumentMetadata
}

/**
 * Local Storage (SAF) [FileBackend] in `:storage-local` (§8.5, Slice S7).
 * Supports internal storage folders and removable microSD cards on Galaxy S8+ (API 28).
 * Enforces:
 * - Segment-wise display-name resolution from `rootDocumentId`
 * - Strict containment verification (`isChildDocument`) at every hop and before final I/O
 * - Read-only mounts require persisted `READ` URI permission; read/write mounts require `READ + WRITE`
 * - Duplicate display name detection (`StorageError.DUPLICATE_NAME`)
 * - `SecurityException` -> `StorageError.PERMISSION_LOST`
 * - Removable media removal -> `StorageError.UNAVAILABLE`
 * - Bounded parallelism (`Dispatchers.IO.limitedParallelism(4)`) and short listing cache
 */
class SafFileBackend(
  val adapter: SafTreeAdapter,
  override val isReadOnly: Boolean = false,
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(4),
  private val listingCacheTtlMs: Long = LISTING_CACHE_TTL_MS,
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) : FileBackend {

  val isSimulatedAdapter: Boolean
    get() = adapter.isSimulated

  private data class CachedListing(
    val entries: List<SafDocumentMetadata>,
    val timestampMillis: Long,
  )

  private val listingCache = ConcurrentHashMap<String, CachedListing>()

  /**
   * Verifies removable media mount state and persisted SAF URI permissions:
   * - Read-only mounts (`isReadOnly == true`) require persisted `READ` permission.
   * - Read/write mounts (`isReadOnly == false`) require persisted `READ + WRITE` permissions (fail-closed).
   */
  fun checkMediaAndPermissions(requireWrite: Boolean = !isReadOnly): StorageResult<Unit> {
    if (!adapter.isMediaMounted()) {
      return StorageResult.Failure(StorageError.UNAVAILABLE, "Removable microSD or storage volume is unmounted")
    }
    if (!adapter.verifyPermissionGranted(requireWrite = requireWrite)) {
      val msg = if (requireWrite) {
        "SAF persisted URI permission lacks required READ+WRITE access"
      } else {
        "SAF persisted URI permission was revoked"
      }
      return StorageResult.Failure(StorageError.PERMISSION_LOST, msg)
    }
    return StorageResult.Success(Unit)
  }

  /**
   * Evaluates current mount health for [com.homenode.service.node.MountManager] so insufficient
   * persisted permissions or ejected media immediately reflect in [com.homenode.core.storage.MountState].
   */
  fun evaluateMountState(): com.homenode.core.storage.MountState {
    return when (val check = checkMediaAndPermissions(requireWrite = !isReadOnly)) {
      is StorageResult.Success -> com.homenode.core.storage.MountState.Ready
      is StorageResult.Failure -> when (check.error) {
        StorageError.PERMISSION_LOST -> com.homenode.core.storage.MountState.NeedsReauth
        StorageError.UNAVAILABLE -> com.homenode.core.storage.MountState.Unavailable
        else -> com.homenode.core.storage.MountState.Degraded(check.message)
      }
    }
  }

  private fun queryChildrenCached(parentDocId: String): List<SafDocumentMetadata> {
    if (listingCacheTtlMs <= 0L) {
      return adapter.queryChildren(parentDocId)
    }
    val now = clockEpochMillis()
    val cached = listingCache[parentDocId]
    if (cached != null && now - cached.timestampMillis <= listingCacheTtlMs) {
      return cached.entries
    }
    val fresh = adapter.queryChildren(parentDocId)
    listingCache[parentDocId] = CachedListing(fresh, now)
    return fresh
  }

  private fun invalidateCache() {
    listingCache.clear()
  }

  private fun resolveHopByHop(path: SafePath): StorageResult<Pair<String?, SafDocumentMetadata>> {
    val precheck = checkMediaAndPermissions()
    if (precheck is StorageResult.Failure) return precheck

    return try {
      val rootMeta = adapter.statDocument(adapter.rootDocumentId)
        ?: return StorageResult.Failure(StorageError.UNAVAILABLE, "SAF root document unavailable")
      if (path.isRoot) {
        return StorageResult.Success(null to rootMeta)
      }

      var currentParentDocId = adapter.rootDocumentId
      var currentMeta = rootMeta

      for ((index, seg) in path.segments.withIndex()) {
        if (!currentMeta.isDirectory) {
          return StorageResult.Failure(StorageError.NOT_FOUND, "Intermediate segment is not a directory")
        }
        val children = queryChildrenCached(currentParentDocId)
        val matches = children.filter { it.displayName == seg }
        if (matches.size > 1) {
          return StorageResult.Failure(
            StorageError.DUPLICATE_NAME,
            "Ambiguous duplicate SAF display name '$seg'"
          )
        }
        val match = matches.firstOrNull()
          ?: return StorageResult.Failure(StorageError.NOT_FOUND, "SAF document not found: $seg")

        // Verify containment at EVERY hop AND against tree root (§8.5)
        if (!adapter.isChildDocument(currentParentDocId, match.documentId) ||
          !adapter.isChildDocument(adapter.rootDocumentId, match.documentId)
        ) {
          return StorageResult.Failure(
            StorageError.DENIED,
            "SAF containment violation detected for document '${match.documentId}'"
          )
        }

        if (index < path.segments.lastIndex) {
          currentParentDocId = match.documentId
        }
        currentMeta = match
      }
      StorageResult.Success(currentParentDocId to currentMeta)
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF SecurityException: permission lost")
    } catch (e: Exception) {
      StorageResult.Failure(StorageError.INTERNAL, "SAF resolution error: ${e.message}")
    }
  }

  override suspend fun list(
    path: SafePath,
    pageSize: Int,
    pageToken: String?,
  ): StorageResult<ListPage> = withContext(ioDispatcher) {
    currentCoroutineContext().ensureActive()
    if (pageSize <= 0 || pageSize > FileBackend.MAX_PAGE_SIZE) {
      return@withContext StorageResult.Failure(StorageError.PATH_INVALID, "Invalid pageSize")
    }
    val resolved = resolveHopByHop(path)
    if (resolved is StorageResult.Failure) return@withContext resolved
    val (_, targetMeta) = (resolved as StorageResult.Success).value
    if (!targetMeta.isDirectory) {
      return@withContext StorageResult.Failure(StorageError.PATH_INVALID, "Target is not a directory")
    }
    try {
      val children = queryChildrenCached(targetMeta.documentId)
      val names = children.map { it.displayName }
      if (names.size != names.distinct().size) {
        return@withContext StorageResult.Failure(
          StorageError.DUPLICATE_NAME,
          "SAF directory contains duplicate display names"
        )
      }
      val entries = children.sortedBy { it.displayName }.map {
        FileEntry(
          name = it.displayName,
          isDirectory = it.isDirectory,
          sizeBytes = it.sizeBytes,
          lastModifiedEpochMillis = it.lastModifiedEpochMillis,
        )
      }
      val start = pageToken?.toIntOrNull() ?: 0
      val slice = entries.drop(start).take(pageSize)
      val next = if (start + slice.size < entries.size) (start + slice.size).toString() else null
      StorageResult.Success(ListPage(slice, next))
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF permission lost during list")
    }
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> = withContext(ioDispatcher) {
    currentCoroutineContext().ensureActive()
    val resolved = resolveHopByHop(path)
    if (resolved is StorageResult.Failure) return@withContext resolved
    val (_, meta) = (resolved as StorageResult.Success).value
    StorageResult.Success(
      FileStat(
        name = if (path.isRoot) "/" else meta.displayName,
        isDirectory = meta.isDirectory,
        sizeBytes = meta.sizeBytes,
        lastModifiedEpochMillis = meta.lastModifiedEpochMillis,
      )
    )
  }

  override fun open(
    path: SafePath,
    offset: Long,
    length: Long,
  ): Flow<ByteArray> = flow {
    if (offset < 0L || length < 0L) {
      throw StorageException(StorageError.PATH_INVALID, "Negative offset or length")
    }
    val resolved = resolveHopByHop(path)
    if (resolved is StorageResult.Failure) {
      throw StorageException(resolved.error, resolved.message)
    }
    val (_, meta) = (resolved as StorageResult.Success).value
    if (meta.isDirectory) {
      throw StorageException(StorageError.PATH_INVALID, "Cannot open directory as file")
    }
    var cursor = offset
    val endExclusive = min(
      meta.sizeBytes,
      if (Long.MAX_VALUE - offset < length) meta.sizeBytes else offset + length
    )
    while (cursor < endExclusive) {
      currentCoroutineContext().ensureActive()
      val toRead = min((endExclusive - cursor).toInt(), FileBackend.CHUNK_SIZE_BYTES)
      val chunk = try {
        adapter.readBytes(meta.documentId, cursor, toRead)
      } catch (se: SecurityException) {
        throw StorageException(StorageError.PERMISSION_LOST, "SAF permission lost during read", se)
      }
      if (chunk.isEmpty()) break
      emit(chunk)
      cursor += chunk.size
    }
  }.flowOn(ioDispatcher)

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> = withContext(ioDispatcher) {
    if (isReadOnly) return@withContext StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    if (path.isRoot) return@withContext StorageResult.Failure(StorageError.PATH_INVALID, "Cannot write root")
    val precheck = checkMediaAndPermissions()
    if (precheck is StorageResult.Failure) return@withContext precheck

    val parentPath = path.parent ?: SafePath.ROOT
    val parentResolved = resolveHopByHop(parentPath)
    if (parentResolved is StorageResult.Failure) return@withContext parentResolved
    val (_, parentMeta) = (parentResolved as StorageResult.Success).value
    if (!parentMeta.isDirectory) {
      return@withContext StorageResult.Failure(StorageError.NOT_FOUND, "Parent is not a directory")
    }

    val out = ByteArrayOutputStream()
    var total = 0L
    data.collect { chunk ->
      currentCoroutineContext().ensureActive()
      total += chunk.size
      if (total > FileBackend.MAX_WRITE_SIZE_BYTES) {
        throw StorageException(StorageError.QUOTA, "Write exceeds max size")
      }
      out.write(chunk)
    }
    val bytes = out.toByteArray()
    if (expectedSize != null && expectedSize != bytes.size.toLong()) {
      return@withContext StorageResult.Failure(StorageError.PATH_INVALID, "Size mismatch")
    }

    try {
      val existingMatches = adapter.queryChildren(parentMeta.documentId).filter { it.displayName == path.name }
      if (existingMatches.size > 1) {
        return@withContext StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate target '${path.name}'")
      }
      val writtenMeta = adapter.createOrReplaceFile(parentMeta.documentId, path.name, mode, bytes)
      invalidateCache()
      StorageResult.Success(
        FileStat(
          name = writtenMeta.displayName,
          isDirectory = false,
          sizeBytes = writtenMeta.sizeBytes,
          lastModifiedEpochMillis = writtenMeta.lastModifiedEpochMillis,
        )
      )
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF permission lost during write")
    } catch (se: StorageException) {
      StorageResult.Failure(se.error, se.message)
    }
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> = withContext(ioDispatcher) {
    if (isReadOnly) return@withContext StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    if (path.isRoot) return@withContext StorageResult.Failure(StorageError.EXISTS, "Root exists")
    val parentResolved = resolveHopByHop(path.parent ?: SafePath.ROOT)
    if (parentResolved is StorageResult.Failure) return@withContext parentResolved
    val (_, parentMeta) = (parentResolved as StorageResult.Success).value
    try {
      val existing = adapter.queryChildren(parentMeta.documentId).filter { it.displayName == path.name }
      if (existing.isNotEmpty()) {
        return@withContext StorageResult.Failure(StorageError.EXISTS, "Directory already exists")
      }
      val created = adapter.createDirectory(parentMeta.documentId, path.name)
      invalidateCache()
      StorageResult.Success(
        FileStat(
          name = created.displayName,
          isDirectory = true,
          sizeBytes = 0L,
          lastModifiedEpochMillis = created.lastModifiedEpochMillis,
        )
      )
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF permission lost during mkdir")
    }
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> = withContext(ioDispatcher) {
    if (isReadOnly) return@withContext StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    if (path.isRoot) return@withContext StorageResult.Failure(StorageError.DENIED, "Cannot delete root")
    val resolved = resolveHopByHop(path)
    if (resolved is StorageResult.Failure) return@withContext resolved
    val (parentDocId, targetMeta) = (resolved as StorageResult.Success).value
    try {
      adapter.deleteDocument(parentDocId ?: adapter.rootDocumentId, targetMeta.documentId, recursive)
      invalidateCache()
      StorageResult.Success(Unit)
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF permission lost during delete")
    } catch (se: StorageException) {
      StorageResult.Failure(se.error, se.message)
    }
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> = withContext(ioDispatcher) {
    if (isReadOnly) return@withContext StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    if (src.isRoot || dst.isRoot) return@withContext StorageResult.Failure(StorageError.PATH_INVALID, "Cannot move root")
    val srcResolved = resolveHopByHop(src)
    if (srcResolved is StorageResult.Failure) return@withContext srcResolved
    val (srcParentDocId, srcMeta) = (srcResolved as StorageResult.Success).value

    val dstParentResolved = resolveHopByHop(dst.parent ?: SafePath.ROOT)
    if (dstParentResolved is StorageResult.Failure) return@withContext dstParentResolved
    val (_, dstParentMeta) = (dstParentResolved as StorageResult.Success).value

    try {
      val moved = adapter.moveDocument(
        sourceParentDocId = srcParentDocId ?: adapter.rootDocumentId,
        targetParentDocId = dstParentMeta.documentId,
        documentId = srcMeta.documentId,
        newDisplayName = dst.name,
      )
      invalidateCache()
      StorageResult.Success(
        FileStat(
          name = moved.displayName,
          isDirectory = moved.isDirectory,
          sizeBytes = moved.sizeBytes,
          lastModifiedEpochMillis = moved.lastModifiedEpochMillis,
        )
      )
    } catch (se: SecurityException) {
      StorageResult.Failure(StorageError.PERMISSION_LOST, "SAF permission lost during move")
    } catch (se: StorageException) {
      StorageResult.Failure(se.error, se.message)
    }
  }

  companion object {
    const val LISTING_CACHE_TTL_MS = 1_500L
  }
}

/**
 * Testable in-memory [SafTreeAdapter] simulating Android SAF `DocumentsProvider`, including:
 * - Removable microSD eject/mount toggles
 * - Persisted URI permission revocation
 * - Hostile non-descendant document injection for containment verification tests
 * Explicitly sets `isSimulated = true` so the UI displays a SIMULATION warning banner if active.
 */
class FakeSafTreeAdapter(
  override val rootDocumentId: String = "tree:primary:HomeNodeRoot",
) : SafTreeAdapter {
  override val isSimulated: Boolean = true
  var mounted: Boolean = true
  var readPermissionGranted: Boolean = true
  var writePermissionGranted: Boolean = true

  var permissionGranted: Boolean
    get() = readPermissionGranted && writePermissionGranted
    set(value) {
      readPermissionGranted = value
      writePermissionGranted = value
    }

  private data class FakeDoc(
    val docId: String,
    var parentDocId: String?,
    var displayName: String,
    val isDirectory: Boolean,
    var bytes: ByteArray = ByteArray(0),
    var lastModified: Long = 1_700_000_000_000L,
    var forceContainmentEscape: Boolean = false,
  )

  private val docs = mutableMapOf(
    rootDocumentId to FakeDoc(
      docId = rootDocumentId,
      parentDocId = null,
      displayName = "Root",
      isDirectory = true,
    )
  )
  private var nextId = 1

  fun injectHostileEscapedChild(parentDocId: String, displayName: String) {
    val id = "escaped:doc:${nextId++}"
    docs[id] = FakeDoc(
      docId = id,
      parentDocId = parentDocId,
      displayName = displayName,
      isDirectory = false,
      forceContainmentEscape = true,
    )
  }

  fun injectDuplicateDisplayName(parentDocId: String, displayName: String) {
    val id = "$rootDocumentId/dup_${nextId++}"
    docs[id] = FakeDoc(
      docId = id,
      parentDocId = parentDocId,
      displayName = displayName,
      isDirectory = false,
      bytes = byteArrayOf(9, 9),
    )
  }

  override fun isMediaMounted(): Boolean = mounted
  override fun verifyPermissionGranted(requireWrite: Boolean): Boolean =
    readPermissionGranted && (!requireWrite || writePermissionGranted)

  override fun isChildDocument(parentDocumentId: String, candidateDocumentId: String): Boolean {
    val doc = docs[candidateDocumentId] ?: return false
    if (doc.forceContainmentEscape) return false
    var cur: FakeDoc? = doc
    while (cur != null) {
      if (cur.docId == parentDocumentId) return true
      cur = cur.parentDocId?.let { docs[it] }
    }
    return false
  }

  override fun queryChildren(parentDocumentId: String): List<SafDocumentMetadata> {
    if (!readPermissionGranted) throw SecurityException("Read permission revoked")
    return docs.values.filter { it.parentDocId == parentDocumentId }.map { it.toMeta() }
  }

  override fun statDocument(documentId: String): SafDocumentMetadata? {
    if (!readPermissionGranted) throw SecurityException("Read permission revoked")
    return docs[documentId]?.toMeta()
  }

  override fun readBytes(documentId: String, offset: Long, length: Int): ByteArray {
    if (!readPermissionGranted) throw SecurityException("Read permission revoked")
    if (offset < 0L || length <= 0) return ByteArray(0)
    val doc = docs[documentId] ?: throw StorageException(StorageError.NOT_FOUND, "Missing doc")
    if (offset >= doc.bytes.size.toLong()) return ByteArray(0)
    val start = offset.toInt()
    val end = min(doc.bytes.size.toLong(), offset + length.toLong()).toInt()
    return doc.bytes.copyOfRange(start, end)
  }

  override fun createOrReplaceFile(
    parentDocumentId: String,
    displayName: String,
    mode: WriteMode,
    bytes: ByteArray,
  ): SafDocumentMetadata {
    if (!readPermissionGranted || !writePermissionGranted) {
      throw SecurityException("Write permission not granted")
    }
    val existing = docs.values.firstOrNull { it.parentDocId == parentDocumentId && it.displayName == displayName }
    if (existing != null) {
      if (mode == WriteMode.CREATE_NEW) {
        throw StorageException(StorageError.EXISTS, "File already exists")
      }
      existing.bytes = bytes.copyOf()
      return existing.toMeta()
    }
    val id = "$rootDocumentId/doc_${nextId++}"
    val created = FakeDoc(id, parentDocumentId, displayName, isDirectory = false, bytes = bytes.copyOf())
    docs[id] = created
    return created.toMeta()
  }

  override fun createDirectory(parentDocumentId: String, displayName: String): SafDocumentMetadata {
    if (!readPermissionGranted || !writePermissionGranted) {
      throw SecurityException("Write permission not granted")
    }
    val id = "$rootDocumentId/dir_${nextId++}"
    val created = FakeDoc(id, parentDocumentId, displayName, isDirectory = true)
    docs[id] = created
    return created.toMeta()
  }

  override fun deleteDocument(parentDocumentId: String, documentId: String, recursive: Boolean) {
    if (!readPermissionGranted || !writePermissionGranted) {
      throw SecurityException("Write permission not granted")
    }
    val children = docs.values.filter { it.parentDocId == documentId }
    if (children.isNotEmpty() && !recursive) {
      throw StorageException(StorageError.DENIED, "Directory not empty")
    }
    children.forEach { deleteDocument(documentId, it.docId, recursive = true) }
    docs.remove(documentId)
  }

  override fun moveDocument(
    sourceParentDocId: String,
    targetParentDocId: String,
    documentId: String,
    newDisplayName: String,
  ): SafDocumentMetadata {
    if (!readPermissionGranted || !writePermissionGranted) {
      throw SecurityException("Write permission not granted")
    }
    val doc = docs[documentId] ?: throw StorageException(StorageError.NOT_FOUND, "Missing source")
    if (docs.values.any { it.parentDocId == targetParentDocId && it.displayName == newDisplayName }) {
      throw StorageException(StorageError.EXISTS, "Destination exists")
    }
    doc.parentDocId = targetParentDocId
    doc.displayName = newDisplayName
    return doc.toMeta()
  }

  private fun FakeDoc.toMeta() = SafDocumentMetadata(
    documentId = docId,
    displayName = displayName,
    isDirectory = isDirectory,
    sizeBytes = bytes.size.toLong(),
    lastModifiedEpochMillis = lastModified,
  )
}

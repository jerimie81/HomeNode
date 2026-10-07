package com.homenode.core.storage

import java.io.ByteArrayOutputStream
import kotlin.math.min
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Reference in-memory [FileBackend] implementation (§8.3) supporting:
 * - 64 KiB chunked streaming with cancellation checks
 * - Read-only mount enforcement
 * - Duplicate child name detection (`StorageError.DUPLICATE_NAME`)
 * - Quota simulation
 * - Atomic writes
 */
class InMemoryFileBackend(
  override val isReadOnly: Boolean = false,
  private val quotaTotalBytes: Long = 64L * 1024L * 1024L,
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) : FileBackend {

  private sealed interface Node {
    val name: String
    var lastModified: Long

    class Dir(
      override val name: String,
      override var lastModified: Long,
      val children: MutableList<Node> = mutableListOf(),
    ) : Node

    class FileNode(
      override val name: String,
      override var lastModified: Long,
      var bytes: ByteArray,
    ) : Node
  }

  private val mutex = Mutex()
  private val root = Node.Dir(name = "", lastModified = clockEpochMillis())

  /**
   * Test helper to inject duplicate display names inside a directory (simulating SAF / Google Drive duplicate names).
   */
  suspend fun injectDuplicateChildForTesting(parentPath: SafePath, duplicateName: String, content: ByteArray) {
    mutex.withLock {
      val dir = resolveNodeLocked(parentPath) as? Node.Dir
        ?: throw StorageException(StorageError.NOT_FOUND, "Parent not found")
      dir.children.add(Node.FileNode(duplicateName, clockEpochMillis(), content.copyOf()))
    }
  }

  private fun totalUsedBytesLocked(node: Node = root): Long = when (node) {
    is Node.FileNode -> node.bytes.size.toLong()
    is Node.Dir -> node.children.sumOf { totalUsedBytesLocked(it) }
  }

  private fun resolveNodeLocked(path: SafePath): Node {
    var current: Node = root
    for (seg in path.segments) {
      val dir = current as? Node.Dir
        ?: throw StorageException(StorageError.NOT_FOUND, "Segment '$seg' parent is not a directory")
      val matches = dir.children.filter { it.name == seg }
      if (matches.size > 1) {
        throw StorageException(StorageError.DUPLICATE_NAME, "Duplicate entries named '$seg'")
      }
      current = matches.firstOrNull()
        ?: throw StorageException(StorageError.NOT_FOUND, "Path not found: $path")
    }
    return current
  }

  override suspend fun list(
    path: SafePath,
    pageSize: Int,
    pageToken: String?,
  ): StorageResult<ListPage> = mutex.withLock {
    currentCoroutineContext().ensureActive()
    if (pageSize <= 0 || pageSize > FileBackend.MAX_PAGE_SIZE) {
      return@withLock StorageResult.Failure(StorageError.PATH_INVALID, "Invalid pageSize $pageSize")
    }
    try {
      val node = resolveNodeLocked(path)
      val dir = node as? Node.Dir
        ?: return@withLock StorageResult.Failure(StorageError.PATH_INVALID, "Not a directory: $path")
      val names = dir.children.map { it.name }
      if (names.size != names.distinct().size) {
        return@withLock StorageResult.Failure(StorageError.DUPLICATE_NAME, "Directory contains duplicate names")
      }
      val sorted = dir.children.sortedBy { it.name }.map { child ->
        FileEntry(
          name = child.name,
          isDirectory = child is Node.Dir,
          sizeBytes = (child as? Node.FileNode)?.bytes?.size?.toLong() ?: 0L,
          lastModifiedEpochMillis = child.lastModified,
        )
      }
      val startIndex = pageToken?.toIntOrNull() ?: 0
      if (startIndex < 0 || startIndex > sorted.size) {
        return@withLock StorageResult.Failure(StorageError.PATH_INVALID, "Invalid pageToken")
      }
      val slice = sorted.drop(startIndex).take(pageSize)
      val nextIndex = startIndex + slice.size
      val nextToken = if (nextIndex < sorted.size) nextIndex.toString() else null
      StorageResult.Success(ListPage(entries = slice, nextPageToken = nextToken))
    } catch (e: StorageException) {
      StorageResult.Failure(e.error, e.message)
    }
  }

  override suspend fun stat(path: SafePath): StorageResult<FileStat> = mutex.withLock {
    currentCoroutineContext().ensureActive()
    try {
      val node = resolveNodeLocked(path)
      val used = totalUsedBytesLocked()
      StorageResult.Success(
        FileStat(
          name = if (path.isRoot) "/" else node.name,
          isDirectory = node is Node.Dir,
          sizeBytes = (node as? Node.FileNode)?.bytes?.size?.toLong() ?: 0L,
          lastModifiedEpochMillis = node.lastModified,
          quotaTotalBytes = quotaTotalBytes,
          quotaAvailableBytes = (quotaTotalBytes - used).coerceAtLeast(0L),
        )
      )
    } catch (e: StorageException) {
      StorageResult.Failure(e.error, e.message)
    }
  }

  override fun open(
    path: SafePath,
    offset: Long,
    length: Long,
  ): Flow<ByteArray> = flow {
    if (offset < 0L || length < 0L) {
      throw StorageException(StorageError.PATH_INVALID, "Negative offset or length")
    }
    val snapshotBytes = mutex.withLock {
      val node = resolveNodeLocked(path)
      val file = node as? Node.FileNode
        ?: throw StorageException(StorageError.PATH_INVALID, "Cannot open directory as file: $path")
      file.bytes.copyOf()
    }
    if (offset >= snapshotBytes.size) {
      return@flow
    }
    val endExclusive = min(
      snapshotBytes.size.toLong(),
      if (Long.MAX_VALUE - offset < length) snapshotBytes.size.toLong() else offset + length
    ).toInt()
    var cursor = offset.toInt()
    while (cursor < endExclusive) {
      currentCoroutineContext().ensureActive()
      val nextEnd = min(endExclusive, cursor + FileBackend.CHUNK_SIZE_BYTES)
      emit(snapshotBytes.copyOfRange(cursor, nextEnd))
      cursor = nextEnd
    }
  }

  override suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long?,
  ): StorageResult<FileStat> {
    if (isReadOnly) {
      return StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    }
    if (path.isRoot) {
      return StorageResult.Failure(StorageError.PATH_INVALID, "Cannot write to mount root")
    }
    val buffer = ByteArrayOutputStream()
    var totalRead = 0L
    try {
      data.collect { chunk ->
        currentCoroutineContext().ensureActive()
        totalRead += chunk.size
        if (totalRead > FileBackend.MAX_WRITE_SIZE_BYTES) {
          throw StorageException(StorageError.QUOTA, "Write exceeds max stream size")
        }
        buffer.write(chunk)
      }
    } catch (e: StorageException) {
      return StorageResult.Failure(e.error, e.message)
    }
    val stagedBytes = buffer.toByteArray()
    if (expectedSize != null && expectedSize != stagedBytes.size.toLong()) {
      return StorageResult.Failure(
        StorageError.PATH_INVALID,
        "Expected $expectedSize bytes but received ${stagedBytes.size}"
      )
    }

    return mutex.withLock {
      try {
        val parentPath = path.parent ?: SafePath.ROOT
        val parentDir = resolveNodeLocked(parentPath) as? Node.Dir
          ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Parent is not a directory")
        val matches = parentDir.children.filter { it.name == path.name }
        if (matches.size > 1) {
          return@withLock StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate target '${path.name}'")
        }
        val existing = matches.firstOrNull()
        if (existing is Node.Dir) {
          return@withLock StorageResult.Failure(StorageError.EXISTS, "Target is an existing directory")
        }
        if (existing != null && mode == WriteMode.CREATE_NEW) {
          return@withLock StorageResult.Failure(StorageError.EXISTS, "File already exists: $path")
        }
        val existingSize = (existing as? Node.FileNode)?.bytes?.size?.toLong() ?: 0L
        val currentUsed = totalUsedBytesLocked()
        if (currentUsed - existingSize + stagedBytes.size > quotaTotalBytes) {
          return@withLock StorageResult.Failure(StorageError.QUOTA, "Mount quota exceeded")
        }

        val now = clockEpochMillis()
        if (existing is Node.FileNode) {
          existing.bytes = stagedBytes
          existing.lastModified = now
        } else {
          parentDir.children.add(Node.FileNode(path.name, now, stagedBytes))
        }
        parentDir.lastModified = now
        StorageResult.Success(
          FileStat(
            name = path.name,
            isDirectory = false,
            sizeBytes = stagedBytes.size.toLong(),
            lastModifiedEpochMillis = now,
            quotaTotalBytes = quotaTotalBytes,
            quotaAvailableBytes = quotaTotalBytes - (currentUsed - existingSize + stagedBytes.size),
          )
        )
      } catch (e: StorageException) {
        StorageResult.Failure(e.error, e.message)
      }
    }
  }

  override suspend fun mkdir(path: SafePath): StorageResult<FileStat> = mutex.withLock {
    currentCoroutineContext().ensureActive()
    if (isReadOnly) {
      return@withLock StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    }
    if (path.isRoot) {
      return@withLock StorageResult.Failure(StorageError.EXISTS, "Root already exists")
    }
    try {
      val parentDir = resolveNodeLocked(path.parent ?: SafePath.ROOT) as? Node.Dir
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Parent is not a directory")
      val matches = parentDir.children.filter { it.name == path.name }
      if (matches.size > 1) {
        return@withLock StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate name '${path.name}'")
      }
      if (matches.isNotEmpty()) {
        return@withLock StorageResult.Failure(StorageError.EXISTS, "Entry already exists: $path")
      }
      val now = clockEpochMillis()
      val created = Node.Dir(path.name, now)
      parentDir.children.add(created)
      parentDir.lastModified = now
      StorageResult.Success(
        FileStat(
          name = created.name,
          isDirectory = true,
          sizeBytes = 0L,
          lastModifiedEpochMillis = now,
        )
      )
    } catch (e: StorageException) {
      StorageResult.Failure(e.error, e.message)
    }
  }

  override suspend fun delete(path: SafePath, recursive: Boolean): StorageResult<Unit> = mutex.withLock {
    currentCoroutineContext().ensureActive()
    if (isReadOnly) {
      return@withLock StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    }
    if (path.isRoot) {
      return@withLock StorageResult.Failure(StorageError.DENIED, "Cannot delete mount root")
    }
    try {
      val parentDir = resolveNodeLocked(path.parent ?: SafePath.ROOT) as? Node.Dir
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Parent not found")
      val matches = parentDir.children.filter { it.name == path.name }
      if (matches.size > 1) {
        return@withLock StorageResult.Failure(StorageError.DUPLICATE_NAME, "Refusing to delete ambiguous duplicate '${path.name}'")
      }
      val target = matches.firstOrNull()
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Target not found: $path")
      if (target is Node.Dir && target.children.isNotEmpty() && !recursive) {
        return@withLock StorageResult.Failure(StorageError.DENIED, "Directory not empty: $path")
      }
      parentDir.children.remove(target)
      parentDir.lastModified = clockEpochMillis()
      StorageResult.Success(Unit)
    } catch (e: StorageException) {
      StorageResult.Failure(e.error, e.message)
    }
  }

  override suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat> = mutex.withLock {
    currentCoroutineContext().ensureActive()
    if (isReadOnly) {
      return@withLock StorageResult.Failure(StorageError.DENIED, "Mount is read-only")
    }
    if (src.isRoot || dst.isRoot) {
      return@withLock StorageResult.Failure(StorageError.PATH_INVALID, "Cannot move mount root")
    }
    if (dst.value.startsWith("${src.value}/")) {
      return@withLock StorageResult.Failure(StorageError.PATH_INVALID, "Cannot move directory into its own subtree")
    }
    try {
      val srcParent = resolveNodeLocked(src.parent ?: SafePath.ROOT) as? Node.Dir
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Source parent not found")
      val dstParent = resolveNodeLocked(dst.parent ?: SafePath.ROOT) as? Node.Dir
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Destination parent not found")
      val srcMatches = srcParent.children.filter { it.name == src.name }
      if (srcMatches.size > 1) {
        return@withLock StorageResult.Failure(StorageError.DUPLICATE_NAME, "Duplicate source '${src.name}'")
      }
      val target = srcMatches.firstOrNull()
        ?: return@withLock StorageResult.Failure(StorageError.NOT_FOUND, "Source not found: $src")
      if (dstParent.children.any { it.name == dst.name }) {
        return@withLock StorageResult.Failure(StorageError.EXISTS, "Destination already exists: $dst")
      }
      srcParent.children.remove(target)
      val now = clockEpochMillis()
      val moved: Node = when (target) {
        is Node.FileNode -> Node.FileNode(dst.name, now, target.bytes)
        is Node.Dir -> Node.Dir(dst.name, now, target.children)
      }
      dstParent.children.add(moved)
      srcParent.lastModified = now
      dstParent.lastModified = now
      StorageResult.Success(
        FileStat(
          name = moved.name,
          isDirectory = moved is Node.Dir,
          sizeBytes = (moved as? Node.FileNode)?.bytes?.size?.toLong() ?: 0L,
          lastModifiedEpochMillis = now,
        )
      )
    } catch (e: StorageException) {
      StorageResult.Failure(e.error, e.message)
    }
  }
}

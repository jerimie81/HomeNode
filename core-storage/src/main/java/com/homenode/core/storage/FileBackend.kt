package com.homenode.core.storage

import kotlinx.coroutines.flow.Flow

/**
 * Unified storage backend contract (§8.3).
 * Implementations accept only validated [SafePath] instances and stream file data in bounded chunks.
 */
interface FileBackend {
  val isReadOnly: Boolean

  suspend fun list(
    path: SafePath,
    pageSize: Int = DEFAULT_PAGE_SIZE,
    pageToken: String? = null,
  ): StorageResult<ListPage>

  suspend fun stat(path: SafePath): StorageResult<FileStat>

  fun open(
    path: SafePath,
    offset: Long = 0L,
    length: Long = Long.MAX_VALUE,
  ): Flow<ByteArray>

  suspend fun write(
    path: SafePath,
    mode: WriteMode,
    data: Flow<ByteArray>,
    expectedSize: Long? = null,
  ): StorageResult<FileStat>

  suspend fun mkdir(path: SafePath): StorageResult<FileStat>

  suspend fun delete(path: SafePath, recursive: Boolean = false): StorageResult<Unit>

  suspend fun move(src: SafePath, dst: SafePath): StorageResult<FileStat>

  companion object {
    const val CHUNK_SIZE_BYTES: Int = 64 * 1024 // 64 KiB streaming chunk bound (§2, §8.3)
    const val DEFAULT_PAGE_SIZE: Int = 100
    const val MAX_PAGE_SIZE: Int = 500
    const val MAX_WRITE_SIZE_BYTES: Long = 2L * 1024L * 1024L * 1024L // 2 GiB cap per stream
  }
}

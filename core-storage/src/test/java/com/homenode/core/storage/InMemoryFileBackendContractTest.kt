package com.homenode.core.storage

import java.io.ByteArrayOutputStream
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryFileBackendContractTest {

  @Test
  fun fullLifecycle_mkdirWriteStatOpenListMoveDelete() = runTest {
    val backend = InMemoryFileBackend(isReadOnly = false, quotaTotalBytes = 1024 * 1024)
    val dirPath = PathValidator.parseRelative("projects/homenode").getOrThrow()
    assertEquals(StorageError.NOT_FOUND, (backend.mkdir(dirPath) as StorageResult.Failure).error)

    val parentPath = PathValidator.parseRelative("projects").getOrThrow()
    assertTrue(backend.mkdir(parentPath).isSuccess)
    assertTrue(backend.mkdir(dirPath).isSuccess)

    // Write 150 KiB across multiple chunks and verify 64 KiB chunked read back
    val payload = ByteArray(150 * 1024) { (it % 251).toByte() }
    val filePath = PathValidator.parseRelative("projects/homenode/archive.bin").getOrThrow()
    val writeStat = backend.write(
      path = filePath,
      mode = WriteMode.CREATE_NEW,
      data = flowOf(payload.copyOfRange(0, 70_000), payload.copyOfRange(70_000, payload.size)),
      expectedSize = payload.size.toLong(),
    ).getOrThrow()
    assertEquals(payload.size.toLong(), writeStat.sizeBytes)

    val out = ByteArrayOutputStream()
    var chunkCount = 0
    backend.open(filePath).collect { chunk ->
      assertTrue("Chunk must be bounded by 64 KiB", chunk.size <= FileBackend.CHUNK_SIZE_BYTES)
      chunkCount++
      out.write(chunk)
    }
    assertEquals(3, chunkCount)
    assertArrayEquals(payload, out.toByteArray())

    // Move and delete
    val movedPath = PathValidator.parseRelative("projects/homenode/renamed.bin").getOrThrow()
    assertTrue(backend.move(filePath, movedPath).isSuccess)
    assertEquals(StorageError.NOT_FOUND, (backend.stat(filePath) as StorageResult.Failure).error)
    assertTrue(backend.stat(movedPath).isSuccess)

    // Non-recursive delete on non-empty dir fails
    assertEquals(StorageError.DENIED, (backend.delete(dirPath, recursive = false) as StorageResult.Failure).error)
    assertTrue(backend.delete(dirPath, recursive = true).isSuccess)
  }

  @Test
  fun readOnlyBackend_rejectsAllWriteOperations() = runTest {
    val backend = InMemoryFileBackend(isReadOnly = true)
    val path = PathValidator.parseRelative("test.txt").getOrThrow()
    assertEquals(
      StorageError.DENIED,
      (backend.write(path, WriteMode.OVERWRITE, flowOf(byteArrayOf(1)), 1L) as StorageResult.Failure).error
    )
    assertEquals(StorageError.DENIED, (backend.mkdir(path) as StorageResult.Failure).error)
    assertEquals(StorageError.DENIED, (backend.delete(path, false) as StorageResult.Failure).error)
  }

  @Test
  fun duplicateChildNames_failClosedWithDuplicateNameError() = runTest {
    val backend = InMemoryFileBackend()
    val path = PathValidator.parseRelative("dup.txt").getOrThrow()
    assertTrue(backend.write(path, WriteMode.CREATE_NEW, flowOf(byteArrayOf(1)), 1L).isSuccess)
    backend.injectDuplicateChildForTesting(SafePath.ROOT, "dup.txt", byteArrayOf(2))

    assertEquals(
      StorageError.DUPLICATE_NAME,
      (backend.stat(path) as StorageResult.Failure).error
    )
    assertEquals(
      StorageError.DUPLICATE_NAME,
      (backend.list(SafePath.ROOT) as StorageResult.Failure).error
    )
  }

  @Test
  fun secretBytes_redactsToStringAndZerosOnClose() {
    val raw = byteArrayOf(10, 20, 30, 40)
    val secret = SecretBytes(raw)
    assertEquals("SecretBytes[REDACTED]", secret.toString())
    secret.useBytes { bytes ->
      assertEquals(10.toByte(), bytes[0])
    }
    assertTrue(raw.all { it == 0.toByte() })
  }
}

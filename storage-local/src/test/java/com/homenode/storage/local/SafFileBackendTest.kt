package com.homenode.storage.local

import com.homenode.core.storage.PathValidator
import com.homenode.core.storage.SafePath
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.WriteMode
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SafFileBackendTest {

  @Test
  fun safBackend_enforcesContainmentDuplicateRejectionPermissionLossAndMicroSdEject() = runTest {
    val adapter = FakeSafTreeAdapter("tree:microsd:DCIM")
    val backend = SafFileBackend(adapter, isReadOnly = false, listingCacheTtlMs = 0L)

    val folder = PathValidator.parseRelative("Camera").getOrThrow()
    assertTrue(backend.mkdir(folder).isSuccess)

    val photo = PathValidator.parseRelative("Camera/IMG_001.jpg").getOrThrow()
    val bytes = ByteArray(1024) { 0x42 }
    assertTrue(backend.write(photo, WriteMode.CREATE_NEW, flowOf(bytes), 1024L).isSuccess)
    assertEquals(1024L, backend.stat(photo).getOrThrow().sizeBytes)

    // 1. Hostile escaped document outside granted tree must be rejected with DENIED
    adapter.injectHostileEscapedChild(adapter.rootDocumentId, "symlink_escape.txt")
    val escapePath = PathValidator.parseRelative("symlink_escape.txt").getOrThrow()
    val escapeRes = backend.stat(escapePath)
    assertEquals(StorageError.DENIED, (escapeRes as StorageResult.Failure).error)

    // 2. Duplicate display name inside directory must fail closed with DUPLICATE_NAME
    adapter.injectDuplicateDisplayName(adapter.rootDocumentId, "dup_file.txt")
    adapter.injectDuplicateDisplayName(adapter.rootDocumentId, "dup_file.txt")
    val dupPath = PathValidator.parseRelative("dup_file.txt").getOrThrow()
    assertEquals(StorageError.DUPLICATE_NAME, (backend.stat(dupPath) as StorageResult.Failure).error)

    // 3. Revoked SAF permission maps to PERMISSION_LOST
    adapter.permissionGranted = false
    assertEquals(StorageError.PERMISSION_LOST, (backend.stat(SafePath.ROOT) as StorageResult.Failure).error)
    adapter.permissionGranted = true

    // 4. Removable microSD card eject maps to UNAVAILABLE and recovers when re-mounted
    adapter.mounted = false
    assertEquals(StorageError.UNAVAILABLE, (backend.stat(photo) as StorageResult.Failure).error)
    adapter.mounted = true
    assertTrue(backend.stat(photo).isSuccess)
  }
}

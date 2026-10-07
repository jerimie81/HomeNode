package com.homenode.storage.local

import org.junit.Assert.assertEquals
import org.junit.Test

class StorageLocalSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":storage-local", ":storage-local")
  }
}

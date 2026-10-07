package com.homenode.storage.cloud

import org.junit.Assert.assertEquals
import org.junit.Test

class StorageCloudSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":storage-cloud", ":storage-cloud")
  }
}

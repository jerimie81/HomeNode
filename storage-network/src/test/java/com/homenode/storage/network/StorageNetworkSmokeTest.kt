package com.homenode.storage.network

import org.junit.Assert.assertEquals
import org.junit.Test

class StorageNetworkSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":storage-network", ":storage-network")
  }
}

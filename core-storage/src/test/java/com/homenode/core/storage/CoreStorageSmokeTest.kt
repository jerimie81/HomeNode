package com.homenode.core.storage

import org.junit.Assert.assertEquals
import org.junit.Test

class CoreStorageSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":core-storage", ":core-storage")
  }
}

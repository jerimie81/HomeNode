package com.homenode.core.identity

import org.junit.Assert.assertEquals
import org.junit.Test

class CoreIdentitySmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":core-identity", ":core-identity")
  }
}

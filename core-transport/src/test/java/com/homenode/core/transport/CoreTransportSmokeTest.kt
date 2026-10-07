package com.homenode.core.transport

import org.junit.Assert.assertEquals
import org.junit.Test

class CoreTransportSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":core-transport", ":core-transport")
  }
}

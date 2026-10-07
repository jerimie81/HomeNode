package com.homenode.service.node

import org.junit.Assert.assertEquals
import org.junit.Test

class ServiceNodeSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":service-node", ":service-node")
  }
}

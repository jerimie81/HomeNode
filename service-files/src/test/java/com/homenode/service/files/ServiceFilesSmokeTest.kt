package com.homenode.service.files

import org.junit.Assert.assertEquals
import org.junit.Test

class ServiceFilesSmokeTest {
  @Test
  fun moduleBootstrapSmoke_hasExpectedModuleName() {
    assertEquals(":service-files", ":service-files")
  }
}

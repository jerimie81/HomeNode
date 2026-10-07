package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.homenode.service.node.HomeNodeFacade
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28])
class ExampleRobolectricTest {

  @Test
  fun appNameAndFacadeTruthfulnessInvariants_onApi28() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    assertEquals("HomeNode", context.getString(R.string.app_name))

    val tempDir = Files.createTempDirectory("homenode_robo_test").toFile()
    val facade = HomeNodeFacade(storageDir = tempDir, appContext = context)
    Thread.sleep(150)

    val state = facade.uiState.value
    // 1. Must NOT pre-populate fake mounts or fake logged-in cloud accounts
    assertTrue("No fake mounts may be seeded at startup", state.mounts.isEmpty())

    // 2. Simulation warning banner list must be non-empty when TestTransport / JVM wrapper is active
    assertTrue(
      "SIMULATION warning list must be non-empty whenever any stub adapter is active",
      state.activeSimulationWarnings.isNotEmpty()
    )

    // 3. Connecting cloud provider with placeholder OAuth Client ID must refuse to create a fake READY mount
    facade.connectCloudProviderPkce(
      providerName = "GOOGLE_DRIVE",
      accountLabel = "Test Account",
      appFolderOnly = true,
      readOnly = true,
    )
    Thread.sleep(100)
    assertTrue(
      "Placeholder OAuth Client ID must not create a fake cloud mount",
      facade.uiState.value.mounts.isEmpty()
    )
  }
}

package com.example

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Enforces Knowledge Base §3 module dependency rules across all 9 Gradle modules,
 * including hostile/negative checks against forbidden upward or lateral edges.
 */
class ArchitectureDependencyTest {

  private val allowedDependencies: Map<String, Set<String>> = mapOf(
    ":app" to setOf(":service-node"),
    ":service-node" to setOf(
      ":service-files",
      ":storage-local",
      ":storage-network",
      ":storage-cloud",
      ":core-transport",
      ":core-identity",
      ":core-storage",
    ),
    ":service-files" to setOf(":core-storage", ":core-transport", ":core-identity"),
    ":storage-local" to setOf(":core-storage"),
    ":storage-network" to setOf(":core-storage"),
    ":storage-cloud" to setOf(":core-storage"),
    ":core-identity" to setOf(":core-storage"),
    ":core-transport" to emptySet(),
    ":core-storage" to emptySet(),
  )

  private val projectDependencyRegex =
    Regex("""project\(\s*["'](:[a-zA-Z0-9_-]+)["']\s*\)""")

  private fun parseDeclaredProjectDeps(buildFileContent: String): Set<String> =
    projectDependencyRegex.findAll(buildFileContent).map { it.groupValues[1] }.toSet()

  private fun resolveRepoRoot(): File {
    val cwd = File(System.getProperty("user.dir") ?: ".")
    return if (File(cwd, "settings.gradle.kts").exists()) cwd else cwd.parentFile ?: cwd
  }

  @Test
  fun allNineModules_existAndMatchStrictDependencyPolicy() {
    val root = resolveRepoRoot()
    val settingsFile = File(root, "settings.gradle.kts")
    assertTrue("settings.gradle.kts must exist at repo root", settingsFile.exists())

    for ((modulePath, expectedAllowed) in allowedDependencies) {
      val dirName = modulePath.removePrefix(":")
      val buildFile = File(File(root, dirName), "build.gradle.kts")
      assertTrue("Missing build.gradle.kts for $modulePath", buildFile.exists())
      val actualDeps = parseDeclaredProjectDeps(buildFile.readText())
      val forbidden = actualDeps - expectedAllowed
      assertTrue(
        "Module $modulePath declares forbidden project dependencies: $forbidden (allowed: $expectedAllowed)",
        forbidden.isEmpty()
      )
      assertEquals(
        "Module $modulePath project dependencies must match exact architectural contract",
        expectedAllowed,
        actualDeps
      )
    }
  }

  @Test
  fun hostilePolicyCheck_rejectsAppDirectDependencyOnStorageOrTransport() {
    val simulatedHostileAppGradle = """
      dependencies {
        implementation(project(":service-node"))
        implementation(project(":core-transport"))
        implementation(project(":storage-cloud"))
      }
    """.trimIndent()
    val actual = parseDeclaredProjectDeps(simulatedHostileAppGradle)
    val forbidden = actual - allowedDependencies.getValue(":app")
    assertEquals(setOf(":core-transport", ":storage-cloud"), forbidden)
  }

  @Test
  fun hostilePolicyCheck_rejectsCrossStorageModuleCoupling() {
    val simulatedHostileStorageGradle = """
      dependencies {
        implementation(project(":core-storage"))
        implementation(project(":storage-network"))
        implementation(project(":core-transport"))
      }
    """.trimIndent()
    val actual = parseDeclaredProjectDeps(simulatedHostileStorageGradle)
    val forbidden = actual - allowedDependencies.getValue(":storage-local")
    assertFalse("Must detect lateral/transport coupling in :storage-*", forbidden.isEmpty())
    assertEquals(setOf(":storage-network", ":core-transport"), forbidden)
  }
}

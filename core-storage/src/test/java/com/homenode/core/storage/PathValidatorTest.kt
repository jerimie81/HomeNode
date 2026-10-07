package com.homenode.core.storage

import java.text.Normalizer
import kotlin.random.Random
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PathValidatorTest {

  @Test
  fun validRelativePaths_normalizeToNfcAndPreserveSegments() {
    // Decomposed e + combining acute accent -> NFC single codepoint 'é'
    val decomposed = "docs/resum\u0065\u0301.pdf"
    val result = PathValidator.parseRelative(decomposed)
    assertTrue(result.isSuccess)
    val safe = result.getOrThrow()
    assertEquals(Normalizer.normalize(decomposed, Normalizer.Form.NFC), safe.value)
    assertEquals(listOf("docs", "resumé.pdf"), safe.segments)
  }

  @Test
  fun hostileTraversalCorpus_isRejected() {
    val hostileInputs = listOf(
      "..",
      ".",
      "../etc/passwd",
      "a/../../b",
      "a/./b",
      "a\\b",
      "\\windows\\system32",
      "a//b",
      "/leading/slash",
      "trailing/slash/",
      "a/b\u0000.txt",
      "a/b\n.txt",
      "C:/Users/admin",
      "~/secret",
      "a/%2e%2e/b",
      "a/%2F/b",
      "folder/file.",
      "folder/file ",
      "a/b:c",
      "a/b*c",
      "a".repeat(256),
      (1..33).joinToString("/") { "d" },
      "x".repeat(1025),
    )

    for (input in hostileInputs) {
      val res = PathValidator.parseRelative(input)
      assertTrue("Expected hostile path '$input' to fail validation", res.isFailure)
      val err = (res as StorageResult.Failure).error
      assertEquals(StorageError.PATH_INVALID, err)
    }
  }

  @Test
  fun virtualPathParsing_extractsMountIdAndRelativePath() {
    val mountId = MountId.generate()
    val parsed = PathValidator.parseVirtualPath("/${mountId.value}/photos/2026/img.jpg").getOrThrow()
    assertEquals(mountId, parsed.mountId)
    assertEquals("photos/2026/img.jpg", parsed.relativePath.value)

    val rootParsed = PathValidator.parseVirtualPath("/").getOrThrow()
    assertEquals(null, rootParsed.mountId)
    assertTrue(rootParsed.relativePath.isRoot)

    assertFalse(PathValidator.parseVirtualPath("/not_a_mount_id/file.txt").isSuccess)
  }

  @Test
  fun fuzzPathValidator_neverThrowsUncaughtExceptionAndEnforcesInvariants() {
    val rng = Random(42L)
    val alphabet = "ab./\\%01~:\u0000\n é"
    repeat(1_000) {
      val len = rng.nextInt(0, 64)
      val sb = StringBuilder(len)
      repeat(len) { sb.append(alphabet[rng.nextInt(alphabet.length)]) }
      val candidate = sb.toString()
      val res = PathValidator.parseRelative(candidate)
      if (res is StorageResult.Success) {
        val v = res.value.value
        assertFalse(v.contains(".."))
        assertFalse(v.contains("\\"))
        assertFalse(v.contains("\u0000"))
        assertFalse(v.contains("//"))
      }
    }
  }
}

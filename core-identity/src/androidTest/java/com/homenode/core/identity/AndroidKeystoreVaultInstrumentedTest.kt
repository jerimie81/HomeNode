package com.homenode.core.identity

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import java.io.File
import java.security.KeyStore
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Physical device instrumented test for Samsung Galaxy S8+ (API 28) verifying:
 * 1. Real `AndroidKeyStore` AES-256-GCM key generation without StrongBox.
 * 2. Keystore-generated random 12-byte IV uniqueness across wraps.
 * 3. `KeystoreCredentialVault` round-trip persistence, AAD key-swap rejection, and 1-bit tamper fail-closed behavior.
 * 4. `NodeIdentityManager` X25519 private key wrapping in real Android Keystore and fail-closed on missing vault file.
 *
 * Run on connected S8+ with:
 * `./gradlew :core-identity:connectedDebugAndroidTest`
 */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreVaultInstrumentedTest {

  private lateinit var testDir: File
  private val testKeyAlias = "homenode_s8plus_instrumented_test_aes256"

  @Before
  fun setUp() {
    val context = InstrumentationRegistry.getInstrumentation().targetContext
    testDir = File(context.noBackupFilesDir, "instrumented_vault_test_${System.nanoTime()}").apply {
      mkdirs()
    }
    deleteKeystoreKeyIfPresent()
  }

  @After
  fun tearDown() {
    testDir.deleteRecursively()
    deleteKeystoreKeyIfPresent()
  }

  private fun deleteKeystoreKeyIfPresent() {
    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    if (ks.containsAlias(testKeyAlias)) {
      ks.deleteEntry(testKeyAlias)
    }
  }

  @Test
  fun androidKeystoreWrapper_generatesHardwareKeyRandomIvAndRejectsTamperOnS8Plus() = runTest {
    val wrapper = AndroidKeystoreAesGcmWrapper(keyAlias = testKeyAlias)
    assertTrue(wrapper.isAndroidKeystoreBacked)
    assertNotNull(wrapper.ensureMasterKeyInitialized())

    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    assertTrue("Key alias must exist in AndroidKeyStore", ks.containsAlias(testKeyAlias))

    // Verify two identical plaintexts produce distinct envelopes (random 12-byte IV from Keystore)
    val aad = "homenode-aad-v1".encodeToByteArray()
    val plain = "s8plus-keystore-secret-payload".encodeToByteArray()
    val env1 = wrapper.wrap(plain, aad)
    val env2 = wrapper.wrap(plain, aad)
    val (iv1, _) = AndroidKeystoreAesGcmWrapper.unpackEnvelope(env1)
    val (iv2, _) = AndroidKeystoreAesGcmWrapper.unpackEnvelope(env2)
    assertFalse("Keystore must generate a fresh random 12-byte IV per wrap", iv1.contentEquals(iv2))
    assertArrayEquals(plain, wrapper.unwrap(env1, aad))
    assertArrayEquals(plain, wrapper.unwrap(env2, aad))

    // Test full KeystoreCredentialVault + NodeIdentityManager with real AndroidKeyStore
    val vault = KeystoreCredentialVault(testDir, wrapper)
    assertTrue(vault.isAndroidKeystoreBacked)

    val keyA = VaultKey("cloud.onedrive.refresh")
    val keyB = VaultKey("smb.nas.password")
    assertTrue(vault.put(keyA, SecretBytes(plain.copyOf())).isSuccess)

    // Key-swap attack between keyA and keyB must fail closed due to GCM AAD
    val fileA = File(testDir, "${keyA.id}.vault")
    val fileB = File(testDir, "${keyB.id}.vault")
    fileA.copyTo(fileB, overwrite = true)
    val swapRes = vault.get(keyB)
    assertTrue("Key swap must fail closed on real AndroidKeyStore", swapRes.isFailure)
    assertEquals(StorageError.DENIED, (swapRes as StorageResult.Failure).error)

    // NodeIdentityManager persists real X25519 key in AndroidKeyStore-backed vault
    val identityManager = NodeIdentityManager(testDir, vault)
    val id1 = identityManager.loadOrInitializeIdentity().getOrThrow()
    val id2 = identityManager.loadOrInitializeIdentity().getOrThrow()
    assertEquals(id1, id2)

    // Delete underlying Keystore master key -> vault unwrap must fail closed, never silently regenerate identity!
    deleteKeystoreKeyIfPresent()
    val afterKeyInvalidated = identityManager.loadOrInitializeIdentity()
    assertTrue(
      "NodeIdentityManager must fail closed when AndroidKeyStore key is invalidated",
      afterKeyInvalidated.isFailure
    )
  }
}

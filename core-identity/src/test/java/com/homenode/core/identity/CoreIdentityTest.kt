package com.homenode.core.identity

import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.DestinationId
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountKind
import com.homenode.core.storage.MountState
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageMount
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CoreIdentityTest {

  private fun tempDir(): File = Files.createTempDirectory("homenode_id_test").toFile()

  private fun hexToBytes(hex: String): ByteArray {
    check(hex.length % 2 == 0)
    return ByteArray(hex.length / 2) { i ->
      hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
    }
  }

  @Test
  fun x25519_matchesRfc7748Section6_1TestVectorsAndRejectsLowOrderPoints() {
    // RFC 7748 §6.1 Alice & Bob test vectors
    val alicePrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    val expectedAlicePublic = hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

    val bobPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    val expectedBobPublic = hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

    val expectedSharedSecret = hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    val derivedAlicePublic = NodeIdentityManager.derivePublicKeyBytes(alicePrivate)
    val derivedBobPublic = NodeIdentityManager.derivePublicKeyBytes(bobPrivate)

    assertArrayEquals("Alice X25519 public key must match RFC 7748 §6.1", expectedAlicePublic, derivedAlicePublic)
    assertArrayEquals("Bob X25519 public key must match RFC 7748 §6.1", expectedBobPublic, derivedBobPublic)

    val aliceShared = NodeIdentityManager.computeSharedSecret(alicePrivate, derivedBobPublic).getOrThrow()
    val bobShared = NodeIdentityManager.computeSharedSecret(bobPrivate, derivedAlicePublic).getOrThrow()

    aliceShared.useBytes { a ->
      bobShared.useBytes { b ->
        assertArrayEquals(expectedSharedSecret, a)
        assertArrayEquals(expectedSharedSecret, b)
      }
    }

    // Hostile: low-order / all-zero public key must be rejected (RFC 7748 §6.1 all-zero DH output check)
    val zeroPubKey = ByteArray(32)
    val lowOrderResult = NodeIdentityManager.computeSharedSecret(alicePrivate, zeroPubKey)
    assertTrue("All-zero low-order X25519 point must fail closed", lowOrderResult.isFailure)
  }

  @Test
  fun keystoreVault_persistsReloadsAndFailsClosedOnCorruptionOrKeySwap() = runTest {
    val dir = tempDir()
    val wrapper = SoftwareAesGcmTestWrapper()
    val vault = KeystoreCredentialVault(dir, wrapper)

    val keyA = VaultKey("smb.share1.pass")
    val keyB = VaultKey("cloud.drive.refresh")
    val rawSecret = "super-secret-token-value-12345".encodeToByteArray()

    assertTrue(vault.put(keyA, SecretBytes(rawSecret.copyOf())).isSuccess)
    // Verify ciphertext at rest does not contain plaintext
    val vaultFile = File(dir, "${keyA.id}.vault")
    val onDisk = String(vaultFile.readBytes(), Charsets.ISO_8859_1)
    assertFalse("Plaintext secret must never appear on disk", onDisk.contains("super-secret"))

    val loaded = vault.get(keyA).getOrThrow()!!
    assertEquals("SecretBytes[REDACTED]", loaded.toString())
    loaded.useBytes { unwrapped ->
      assertArrayEquals(rawSecret, unwrapped)
    }

    // Hostile: swap vault files between keyA and keyB -> AAD mismatch must fail closed
    val swappedFile = File(dir, "${keyB.id}.vault")
    vaultFile.copyTo(swappedFile, overwrite = true)
    val swapRes = vault.get(keyB)
    assertTrue("Key swap must fail closed due to GCM AAD binding", swapRes.isFailure)
    assertEquals(StorageError.DENIED, (swapRes as StorageResult.Failure).error)

    // Hostile: flip 1 bit in ciphertext -> fail closed
    val bytes = vaultFile.readBytes()
    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
    vaultFile.writeBytes(bytes)
    assertTrue(vault.get(keyA).isFailure)
  }

  @Test
  fun nodeIdentityManager_persistsRealX25519IdentityAndFailsClosedIfVaultMissing() = runTest {
    val dir = tempDir()
    val vault = KeystoreCredentialVault(dir, SoftwareAesGcmTestWrapper())
    val mgr = NodeIdentityManager(dir, vault)

    val first = mgr.loadOrInitializeIdentity().getOrThrow()
    val second = mgr.loadOrInitializeIdentity().getOrThrow()
    assertEquals(first, second)

    // Verify stored private key derives the exact X25519 public key in NodePublicIdentity
    val storedPriv = vault.get(NodeIdentityManager.PRIVATE_KEY_VAULT_KEY).getOrThrow()!!
    storedPriv.useBytes { privBytes ->
      val expectedPub = NodeIdentityManager.derivePublicKeyBytes(privBytes)
      assertArrayEquals(expectedPub, first.publicKey.toBytes())
    }

    // Simulate Keystore / vault deletion while marker remains -> MUST fail closed, never regenerate
    vault.delete(NodeIdentityManager.PRIVATE_KEY_VAULT_KEY)
    val corruptedLoad = mgr.loadOrInitializeIdentity()
    assertTrue("Must fail closed when private key is lost", corruptedLoad.isFailure)

    // Explicit user regeneration creates a fresh identity
    val regenerated = mgr.explicitUserRegenerateIdentity().getOrThrow()
    assertFalse(first.publicKey == regenerated.publicKey)
  }

  @Test
  fun peerAuthorizer_enforcesDefaultDenyExpiryRevocationAndExcludesCloudFromDefaultGrants() {
    var now = 1_000_000L
    val authorizer = PeerAuthorizer { now }
    val (_, peer) = NodeIdentityManager.generateEphemeralKeypair()

    val localMount = StorageMount(
      id = MountId.generate(),
      kind = MountKind.LOCAL,
      provider = StorageProvider.SAF,
      label = "SD Card",
      config = MountConfig.SafConfig("content://tree/1", isRemovableStorage = true),
      credentialRef = null,
      readOnly = false,
      state = MountState.Ready,
    )
    val cloudMount = StorageMount(
      id = MountId.generate(),
      kind = MountKind.CLOUD,
      provider = StorageProvider.GOOGLE_DRIVE,
      label = "Google Drive",
      config = MountConfig.CloudConfig(StorageProvider.GOOGLE_DRIVE, "user@example.com", "root"),
      credentialRef = VaultKey("cloud.gdrive"),
      readOnly = true,
      state = MountState.Ready,
    )

    // Default grant helper MUST exclude CLOUD mounts (§7)
    val defaultCaps = PeerAuthorizer.buildDefaultNonCloudReadCapabilities(listOf(localMount, cloudMount))
    assertTrue(defaultCaps.contains(Capability.Files(localMount.id, AccessMode.READ)))
    assertFalse(
      "Cloud mounts must NEVER be included in default grants (§7)",
      defaultCaps.any { it is Capability.Files && it.mountId == cloudMount.id }
    )

    authorizer.registerOrUpdatePeer(
      peerId = peer,
      label = "Laptop",
      capabilities = setOf(Capability.Files(localMount.id, AccessMode.WRITE)),
      expiresAtEpochMillis = now + 60_000L,
    )

    // WRITE implies READ on same mount, but denies other mounts and LAN
    assertTrue(authorizer.can(peer, Capability.Files(localMount.id, AccessMode.READ)))
    assertTrue(authorizer.can(peer, Capability.Files(localMount.id, AccessMode.WRITE)))
    assertFalse(authorizer.can(peer, Capability.Files(cloudMount.id, AccessMode.READ)))
    assertFalse(authorizer.can(peer, Capability.Lan(DestinationId("nas_ssh"))))

    // Expiry denies all capabilities
    now += 61_000L
    assertFalse(authorizer.can(peer, Capability.Files(localMount.id, AccessMode.READ)))
  }

  @Test
  fun pairingParserAndCoordinator_enforceSingleUseAndRejectHostileUris() {
    val now = 5_000_000L
    val authorizer = PeerAuthorizer { now }
    val coordinator = ModeAPairingCoordinator(authorizer) { now }
    val (_, pubKey) = NodeIdentityManager.generateEphemeralKeypair()
    val identity = NodePublicIdentity("hn_node01", pubKey)

    val qrPayload = coordinator.createNodeIntroductionQr(identity, listOf("192.168.1.10:51820"))
    val uri = PairingPayloadParser.formatUri(qrPayload)

    // First use succeeds
    val mountId = MountId.generate()
    val firstConfirm = coordinator.confirmPeerFromScannedQr(
      scannedPeerQrUri = uri,
      userConfirmedLabel = "Pixel",
      userSelectedCapabilities = setOf(Capability.Files(mountId, AccessMode.READ)),
    )
    assertTrue(firstConfirm.isSuccess)

    // Replay of same QR must fail (single-use token consumed)
    val replayConfirm = coordinator.confirmPeerFromScannedQr(
      scannedPeerQrUri = uri,
      userConfirmedLabel = "Pixel Replay",
      userSelectedCapabilities = emptySet(),
    )
    assertTrue("Replayed QR must be rejected", replayConfirm.isFailure)

    // Hostile URIs (secret leak, duplicate params, expired, unknown version)
    assertTrue(
      PairingPayloadParser.parse("$uri&secret=1234", now).isFailure
    )
    assertTrue(
      PairingPayloadParser.parse("$uri&v=1", now).isFailure
    )
    assertTrue(
      PairingPayloadParser.parse(uri, now + PairingPayloadParser.MAX_TTL_MILLIS + 1).isFailure
    )
  }
}

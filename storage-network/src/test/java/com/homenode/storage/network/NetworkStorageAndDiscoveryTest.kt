package com.homenode.storage.network

import com.homenode.core.storage.InMemoryCredentialVault
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.SafePath
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NetworkStorageAndDiscoveryTest {

  @Test
  fun lanAddressPolicy_rejectsHostnamesLoopbackTunnelSubnetAndPublicIps() {
    assertTrue(LanStorageAddressPolicy.validateLanTarget("nas.local", 445).isFailure)
    assertTrue(LanStorageAddressPolicy.validateLanTarget("127.0.0.1", 445).isFailure)
    assertTrue(LanStorageAddressPolicy.validateLanTarget("169.254.1.10", 445).isFailure)
    assertTrue(LanStorageAddressPolicy.validateLanTarget("10.66.0.2", 445).isFailure)
    assertTrue(LanStorageAddressPolicy.validateLanTarget("8.8.8.8", 445).isFailure)
    assertTrue(
      LanStorageAddressPolicy.validateLanTarget(
        hostIpLiteral = "192.168.1.5",
        port = 445,
        ownInterfaceIps = setOf("192.168.1.5"),
      ).isFailure
    )
    assertTrue(LanStorageAddressPolicy.validateLanTarget("192.168.1.50", 445).isSuccess)
    assertTrue(LanStorageAddressPolicy.validateLanTarget("10.0.10.25", 22).isSuccess)
  }

  @Test
  fun smbBackend_rejectsSmb1AndUnsignedWhenRequired() = runTest {
    val vault = InMemoryCredentialVault()
    val credKey = VaultKey("smb.nas1")
    vault.put(credKey, SecretBytes("nas-pass".encodeToByteArray()))
    val adapter = FakeSmbSessionAdapter(dialectToNegotiate = SmbDialect.SMB_1_FORBIDDEN)
    val config = MountConfig.SmbConfig(
      hostIpLiteral = "192.168.1.50",
      port = 445,
      shareName = "media",
      username = "alice",
      requireSigningOrEncryption = true,
    )
    val smb = SmbFileBackend(config, credKey, vault, adapter)

    // SMB1 must be rejected
    assertEquals(StorageError.DENIED, (smb.list(SafePath.ROOT) as StorageResult.Failure).error)

    // SMB 3.1.1 with signing succeeds
    adapter.dialectToNegotiate = SmbDialect.SMB_3_1_1
    assertTrue(smb.list(SafePath.ROOT).isSuccess)
  }

  @Test
  fun webDavAndSftp_enforceHttpsDefaultCertPinningAndHostKeyPinning() = runTest {
    val vault = InMemoryCredentialVault()
    val credKey = VaultKey("net.cred")
    vault.put(credKey, SecretBytes("secret".encodeToByteArray()))

    // Cleartext HTTP WebDAV blocked by default
    val cleartextConfig = MountConfig.WebDavConfig(
      baseUrl = "http://192.168.1.60:5005/dav",
      hostIpLiteral = "192.168.1.60",
      port = 5005,
      username = "alice",
      allowCleartextLan = false,
    )
    val webDavBlocked = WebDavFileBackend(cleartextConfig, credKey, vault)
    assertEquals(StorageError.DENIED, (webDavBlocked.stat(SafePath.ROOT) as StorageResult.Failure).error)

    // SFTP host key mismatch fails closed
    val sftpConfig = MountConfig.SftpConfig(
      hostIpLiteral = "192.168.1.70",
      port = 22,
      username = "alice",
      pinnedHostKeyFingerprint = "SHA256:expectedPin111",
    )
    val sftpMitm = SftpFileBackend(
      config = sftpConfig,
      credentialKey = credKey,
      vault = vault,
      serverPresentedHostKeyProvider = { "SHA256:attackerKey999" },
    )
    assertEquals(StorageError.DENIED, (sftpMitm.stat(SafePath.ROOT) as StorageResult.Failure).error)
  }

  @Test
  fun networkDiscovery_rejectsNonForegroundNonRfc1918AndSanitizesMaliciousMdnsNames() = runTest {
    var now = 100_000L
    val mdns = object : MdnsDiscoverySource {
      override suspend fun queryMdnsServices(): List<DiscoveredService> = listOf(
        DiscoveredService(
          hostIp = "192.168.1.20",
          port = 445,
          protocolGuess = StorageProvider.SMB,
          advertisedName = "MyNAS\u0000<script>alert(1)</script>\n" + "X".repeat(80),
          source = DiscoverySource.MDNS,
        )
      )
    }
    val prober = object : TcpPortProber {
      override suspend fun isPortOpen(hostIp: String, port: Int, timeoutMs: Int): Boolean =
        hostIp == "192.168.1.10" && port == 22
    }
    val discovery = NetworkDiscovery(mdns, prober) { now }

    // Background / peer-triggered scan must be denied
    assertEquals(
      StorageError.DENIED,
      (discovery.scanLanForStorage("192.168.1", userInitiatedInForeground = false) as StorageResult.Failure).error
    )

    // Non-RFC1918 subnet must be denied
    assertEquals(
      StorageError.DENIED,
      (discovery.scanLanForStorage("8.8.8", userInitiatedInForeground = true) as StorageResult.Failure).error
    )

    // Valid foreground scan succeeds and sanitizes untrusted mDNS name
    val found = discovery.scanLanForStorage(
      subnetPrefix24 = "192.168.1",
      userInitiatedInForeground = true,
      maxHostsToProbe = 15,
    ).getOrThrow()
    assertEquals(2, found.size)
    val sanitizedName = found.first { it.source == DiscoverySource.MDNS }.advertisedName
    assertFalse(sanitizedName.contains("<"))
    assertFalse(sanitizedName.contains("\u0000"))
    assertTrue(sanitizedName.length <= NetworkDiscovery.MAX_ADVERTISED_NAME_LEN)

    // Immediate second scan hits cooldown rate limit
    now += 1_000L
    assertEquals(
      StorageError.RATE_LIMITED,
      (discovery.scanLanForStorage("192.168.1", userInitiatedInForeground = true) as StorageResult.Failure).error
    )
  }
}

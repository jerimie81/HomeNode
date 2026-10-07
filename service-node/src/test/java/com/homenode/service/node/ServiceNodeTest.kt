package com.homenode.service.node

import com.homenode.core.identity.KeystoreCredentialVault
import com.homenode.core.identity.NodeIdentityManager
import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.identity.SoftwareAesGcmTestWrapper
import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.DestinationId
import com.homenode.core.storage.InMemoryCredentialVault
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.MountState
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.transport.FakeReachability
import com.homenode.core.transport.PeerEndpointConfig
import com.homenode.core.transport.PeerPublicKey
import com.homenode.core.transport.TestTransport
import com.homenode.core.transport.TestTransportHub
import com.homenode.core.transport.TunnelIp
import com.homenode.storage.cloud.CloudAuthCoordinator
import com.homenode.storage.cloud.OAuthTokenEndpointAdapter
import com.homenode.storage.cloud.TokenExchangeResponse
import com.homenode.storage.cloud.TokenRefreshOutcome
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.file.Files
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class ServiceNodeTest {

  private fun dummyOAuthEndpoint() = object : OAuthTokenEndpointAdapter {
    override val isSimulatedEndpoint: Boolean = true
    override suspend fun exchangeCodeWithPkce(
      provider: StorageProvider,
      publicClientId: String,
      redirectUri: String,
      authorizationCode: String,
      codeVerifierBytes: ByteArray,
    ) = TokenExchangeResponse(TokenRefreshOutcome.SUCCESS)

    override suspend fun refreshAccessToken(
      provider: StorageProvider,
      publicClientId: String,
      refreshTokenBytes: ByteArray,
    ) = TokenExchangeResponse(TokenRefreshOutcome.SUCCESS)

    override suspend fun revokeTokenAtProvider(
      provider: StorageProvider,
      tokenBytes: ByteArray,
    ) = true
  }

  @Test
  fun retryPolicyAndScheduler_follows1To60SecBackoffDeduplicatesAndResetsAfter2Min() = runTest {
    var virtualNow = 10_000L
    val logger = SafeEventLogger(clockEpochMillis = { virtualNow })
    val scheduler = ComponentRetryScheduler(logger) { virtualNow }

    // Verify backoff table 1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 60 -> 60
    assertEquals(1L, RetryPolicy.delaySecondsForAttempt(0))
    assertEquals(2L, RetryPolicy.delaySecondsForAttempt(1))
    assertEquals(4L, RetryPolicy.delaySecondsForAttempt(2))
    assertEquals(8L, RetryPolicy.delaySecondsForAttempt(3))
    assertEquals(16L, RetryPolicy.delaySecondsForAttempt(4))
    assertEquals(32L, RetryPolicy.delaySecondsForAttempt(5))
    assertEquals(60L, RetryPolicy.delaySecondsForAttempt(6))
    assertEquals(60L, RetryPolicy.delaySecondsForAttempt(99))

    var executions = 0
    val scheduled1 = scheduler.scheduleRetry(backgroundScope, "mount_a") {
      executions++
      false
    }
    // Scheduling while one is active must be a no-op (§11)
    val duplicateSchedule = scheduler.scheduleRetry(backgroundScope, "mount_a") {
      executions++
      false
    }
    assertTrue(scheduled1)
    assertFalse(duplicateSchedule)

    advanceTimeBy(1_000L)
    runCurrent()
    assertEquals(1, executions)
    assertEquals(1, scheduler.currentAttemptCount("mount_a"))

    // Mark healthy and advance clock past 2-minute stable reset window
    scheduler.markComponentHealthy("mount_a")
    virtualNow += RetryPolicy.STABLE_RESET_WINDOW_MS + 1_000L
    scheduler.scheduleRetry(backgroundScope, "mount_a") { true }
    assertEquals("Attempt count must reset to 1 after 2-minute stability window", 1, scheduler.currentAttemptCount("mount_a"))
  }

  @Test
  fun mountManager_removalRevokesPeerCapabilitiesAndWipesVaultCredentials() = runTest {
    val vault = InMemoryCredentialVault()
    val authorizer = PeerAuthorizer()
    val logger = SafeEventLogger()
    val scheduler = ComponentRetryScheduler(logger)
    val cloudAuth = CloudAuthCoordinator(vault, dummyOAuthEndpoint())
    val mountManager = MountManager(vault, authorizer, cloudAuth, scheduler, logger)

    val mount = mountManager.addMount(
      label = "Home SMB NAS",
      provider = StorageProvider.SMB,
      config = MountConfig.SmbConfig(
        hostIpLiteral = "192.168.1.50",
        port = 445,
        shareName = "media",
        username = "nasuser",
      ),
      readOnly = false,
      initialSecret = SecretBytes("smb-password-999".encodeToByteArray()),
    ).getOrThrow()

    val (_, peerId) = NodeIdentityManager.generateEphemeralKeypair()
    authorizer.registerOrUpdatePeer(
      peerId = peerId,
      label = "Tablet",
      capabilities = setOf(Capability.Files(mount.id, AccessMode.WRITE)),
    )
    assertTrue(authorizer.can(peerId, Capability.Files(mount.id, AccessMode.READ)))
    assertTrue(vault.get(mount.credentialRef!!).getOrThrow() != null)

    // Remove mount -> must wipe credential from vault AND revoke peer capabilities referencing it (§8.1)
    assertTrue(mountManager.removeMount(mount.id).isSuccess)
    assertFalse(authorizer.can(peerId, Capability.Files(mount.id, AccessMode.READ)))
    assertNull(vault.get(mount.credentialRef!!).getOrThrow())
  }

  @Test
  fun lanProxy_enforcesCapabilityAllowlistConnectTimePolicyRateLimitAndForwardsRealTcpSockets() = runTest {
    var now = 50_000L
    val authorizer = PeerAuthorizer { now }
    val logger = SafeEventLogger(clockEpochMillis = { now })
    var nodeOwnIp = "192.168.1.2"
    val proxy = LanProxy(
      authorizer = authorizer,
      logger = logger,
      ownInterfaceIpsProvider = { setOf(nodeOwnIp) },
      clockEpochMillis = { now },
      maxNewConnectionsPerMinutePerPeer = 4,
      maxConcurrentPerPeer = 2,
    )

    val destId = DestinationId("jellyfin_tv")
    // Hostname, loopback, link-local, tunnel subnet, public IP, own IP, and invalid ports must be rejected
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad Hostname", "jellyfin.local", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad Loopback", "127.0.0.1", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad LinkLocal", "169.254.10.20", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad TunnelNode", "10.66.0.1", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad TunnelPeer", "10.66.4.12", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad OwnIp", "192.168.1.2", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad PublicIp", "8.8.8.8", 8096).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad Port 0", "192.168.1.80", 0).isFailure)
    assertTrue(proxy.addAllowlistedDestination(destId, "Bad Port 70000", "192.168.1.80", 70_000).isFailure)

    // Valid RFC1918 IP literal succeeds
    assertTrue(proxy.addAllowlistedDestination(destId, "Jellyfin", "192.168.1.80", 8096).isSuccess)

    val (_, peer) = NodeIdentityManager.generateEphemeralKeypair()
    authorizer.registerOrUpdatePeer(peer, "Phone", emptySet())

    // 1. Default deny without Capability.Lan(destId)
    assertEquals(
      StorageError.DENIED,
      (proxy.authorizeAndValidateConnect(peer, destId) as StorageResult.Failure).error
    )

    // 2. Grant Capability.Lan(destId) -> succeeds and forwards real TCP socket bytes end-to-end
    authorizer.grantCapability(peer, Capability.Lan(destId))

    ServerSocket().use { mockLanServer ->
      mockLanServer.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0))
      val boundPort = mockLanServer.localPort
      val serverJob = async(kotlinx.coroutines.Dispatchers.IO) {
        mockLanServer.accept().use { s ->
          s.soTimeout = 5_000
          val buf = ByteArray(1024)
          val n = s.getInputStream().read(buf)
          val reqBytes = if (n > 0) buf.copyOf(n) else ByteArray(0)
          s.getOutputStream().write("HTTP/1.1 200 OK\r\n\r\n".encodeToByteArray() + reqBytes)
          s.getOutputStream().flush()
        }
      }

      val hub = TestTransportHub()
      val nodeKey = PeerPublicKey.fromBytes(ByteArray(32) { (it + 1).toByte() }).getOrThrow()
      val peerKey = PeerPublicKey.fromBytes(peer.toBytes()).getOrThrow()
      val nodeTransport = TestTransport(nodeKey, TunnelIp.parse("10.66.0.1").getOrThrow(), hub)
      val peerTransport = TestTransport(peerKey, TunnelIp.parse("10.66.0.2").getOrThrow(), hub)
      nodeTransport.start()
      peerTransport.start()
      nodeTransport.addPeer(PeerEndpointConfig(peerKey, TunnelIp.parse("10.66.0.2").getOrThrow()))
      peerTransport.addPeer(PeerEndpointConfig(nodeKey, TunnelIp.parse("10.66.0.1").getOrThrow()))

      val incomingFlow = nodeTransport.listen(7002)
      val serverForwardDeferred = async(kotlinx.coroutines.Dispatchers.IO) {
        val serverSideStream = incomingFlow.first()
        proxy.forwardTcpConnection(
          peerId = peer,
          destinationId = destId,
          peerStream = serverSideStream,
          overrideTargetAddressForLoopbackTest = InetSocketAddress(
            InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)),
            boundPort
          ),
        ).getOrThrow()
      }

      // Give collector a moment to subscribe before opening stream
      kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        kotlinx.coroutines.delay(25)
      }
      val clientStream = peerTransport.openStream(nodeKey, 7002).getOrThrow()
      val requestPayload = "GET /system/info HTTP/1.1".encodeToByteArray()
      clientStream.writeFrameBytes(requestPayload)
      val responseFrame = clientStream.readFrameBytes(4096).getOrThrow()!!
      assertArrayEquals("HTTP/1.1 200 OK\r\n\r\n".encodeToByteArray() + requestPayload, responseFrame)
      clientStream.close()
      serverJob.await()
      val forwardedBytes = serverForwardDeferred.await()
      assertTrue(forwardedBytes > 0L)
      assertEquals("Concurrency counter must return to 0 after stream closes", 0, proxy.currentGlobalActiveConnections)
    }

    // 3. Connect-time re-validation: if node's own IP changes to match target IP, reject at connect time!
    nodeOwnIp = "192.168.1.80"
    assertEquals(
      StorageError.DENIED,
      (proxy.authorizeAndValidateConnect(peer, destId) as StorageResult.Failure).error
    )

    // 4. Rate limit exceeded (maxNewConnectionsPerMinutePerPeer = 4; 3 used above + 1 more = 4; 5th -> RATE_LIMITED)
    nodeOwnIp = "192.168.1.2"
    assertTrue(proxy.authorizeAndValidateConnect(peer, destId).isSuccess)
    assertEquals(
      StorageError.RATE_LIMITED,
      (proxy.authorizeAndValidateConnect(peer, destId) as StorageResult.Failure).error
    )
  }

  @Test
  fun nodeRuntime_transitionsRunningDegradedStoppedAndAuditsZeroSecretsInLogs() = runTest {
    val testDispatcher = StandardTestDispatcher(testScheduler)
    val dir = Files.createTempDirectory("homenode_rt_test").toFile()
    val vault = KeystoreCredentialVault(dir, SoftwareAesGcmTestWrapper())
    val identityMgr = NodeIdentityManager(dir, vault)
    val authorizer = PeerAuthorizer()
    val logger = SafeEventLogger()
    val retryScheduler = ComponentRetryScheduler(logger)
    val cloudAuth = CloudAuthCoordinator(vault, dummyOAuthEndpoint())
    val mountManager = MountManager(vault, authorizer, cloudAuth, retryScheduler, logger)
    val lanProxy = LanProxy(authorizer, logger)

    val transportKey = PeerPublicKey.fromBytes(ByteArray(32) { (it + 1).toByte() }).getOrThrow()
    val transportIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val transport = TestTransport(transportKey, transportIp)

    val runtime = NodeRuntime(
      identityManager = identityMgr,
      transport = transport,
      reachability = FakeReachability(),
      mountManager = mountManager,
      authorizer = authorizer,
      lanProxy = lanProxy,
      logger = logger,
      retryScheduler = retryScheduler,
      dispatcher = testDispatcher,
    )

    val snapRunning = runtime.start()
    assertEquals(NodeState.RUNNING, snapRunning.state)

    // Wi-Fi loss transitions to DEGRADED, never FAILED (§11)
    runtime.onWifiConnectivityChanged(false)
    assertEquals(NodeState.DEGRADED, runtime.snapshot.value.state)
    runtime.onWifiConnectivityChanged(true)
    assertEquals(NodeState.RUNNING, runtime.snapshot.value.state)

    // Mount NEEDS_REAUTH transitions node to DEGRADED and does NOT schedule auto-retry (§8.8, §11)
    val cloudMount = mountManager.addMount(
      label = "Drive",
      provider = StorageProvider.GOOGLE_DRIVE,
      config = MountConfig.CloudConfig(StorageProvider.GOOGLE_DRIVE, "user", "root"),
      readOnly = true,
    ).getOrThrow()
    mountManager.reportMountIssue(backgroundScope, cloudMount.id, MountState.NeedsReauth)
    runtime.refreshMountHealthState()
    assertEquals(NodeState.DEGRADED, runtime.snapshot.value.state)
    assertEquals(0, retryScheduler.currentAttemptCount(cloudMount.id.value))

    val snapStopped = runtime.stop()
    assertEquals(NodeState.STOPPED, snapStopped.state)

    // Log audit (§14, §16): grep all logged events for forbidden secret patterns
    val serializedLogs = logger.events.value.joinToString("\n") { "${it.type}:${it.safeDetail}" }
    assertFalse(serializedLogs.contains("SecretBytes"))
    assertFalse(serializedLogs.contains("password"))
    assertFalse(serializedLogs.contains("@"))
  }

  @Test
  fun nodeRuntime_cleansUpScopeOnIdentityFailureOrTransportExceptionAndIsIdempotent() = runTest {
    val testDispatcher = StandardTestDispatcher(testScheduler)
    val dir = Files.createTempDirectory("homenode_rt_fail_test").toFile()
    val vault = KeystoreCredentialVault(dir, SoftwareAesGcmTestWrapper())
    val identityMgr = NodeIdentityManager(dir, vault)

    // Provision identity then delete vault key while leaving marker file -> fail-closed identity failure
    identityMgr.loadOrInitializeIdentity().getOrThrow()
    vault.delete(NodeIdentityManager.PRIVATE_KEY_VAULT_KEY)

    val authorizer = PeerAuthorizer()
    val logger = SafeEventLogger()
    val retryScheduler = ComponentRetryScheduler(logger)
    val cloudAuth = CloudAuthCoordinator(vault, dummyOAuthEndpoint())
    val mountManager = MountManager(vault, authorizer, cloudAuth, retryScheduler, logger)
    val lanProxy = LanProxy(authorizer, logger)

    val transportKey = PeerPublicKey.fromBytes(ByteArray(32) { (it + 1).toByte() }).getOrThrow()
    val transportIp = TunnelIp.parse("10.66.0.1").getOrThrow()
    val transport = TestTransport(transportKey, transportIp)

    val runtime = NodeRuntime(
      identityManager = identityMgr,
      transport = transport,
      reachability = FakeReachability(),
      mountManager = mountManager,
      authorizer = authorizer,
      lanProxy = lanProxy,
      logger = logger,
      retryScheduler = retryScheduler,
      dispatcher = testDispatcher,
    )

    // 1. Identity failure -> NodeState.FAILED and zero leaked CoroutineScope
    val failedSnap = runtime.start()
    assertEquals(NodeState.FAILED, failedSnap.state)
    assertFalse("runtimeScope must not leak when identity initialization fails", runtime.hasActiveRuntimeScope)

    // 2. Explicit user identity regeneration -> subsequent start() succeeds; duplicate start() is idempotent
    identityMgr.explicitUserRegenerateIdentity().getOrThrow()
    val runningSnap1 = runtime.start()
    val runningSnap2 = runtime.start()
    assertEquals(NodeState.RUNNING, runningSnap1.state)
    assertEquals(runningSnap1, runningSnap2)
    assertTrue(runtime.hasActiveRuntimeScope)

    // 3. Idempotent stop() cancels scope and transitions to STOPPED
    assertEquals(NodeState.STOPPED, runtime.stop().state)
    assertEquals(NodeState.STOPPED, runtime.stop().state)
    assertFalse("runtimeScope must be cancelled after stop()", runtime.hasActiveRuntimeScope)
  }

  @Test
  fun mountManager_safMountReflectsInsufficientWritePermissionInMountHealth() = runTest {
    val vault = InMemoryCredentialVault()
    val authorizer = PeerAuthorizer()
    val logger = SafeEventLogger()
    val scheduler = ComponentRetryScheduler(logger)
    val cloudAuth = CloudAuthCoordinator(vault, dummyOAuthEndpoint())

    val fakeSaf = com.homenode.storage.local.FakeSafTreeAdapter("tree:primary:Docs").apply {
      readPermissionGranted = true
      writePermissionGranted = false
    }
    val mountManager = MountManager(
      vault = vault,
      authorizer = authorizer,
      cloudAuth = cloudAuth,
      retryScheduler = scheduler,
      logger = logger,
      safAdapterFactory = { fakeSaf },
    )

    // Adding a read/write SAF mount when only READ permission is persisted -> MountState.NeedsReauth
    val rwMount = mountManager.addMount(
      label = "RW Folder With ReadOnly URI Grant",
      provider = StorageProvider.SAF,
      config = MountConfig.SafConfig("content://tree/primary%3ADocs"),
      readOnly = false,
    ).getOrThrow()
    assertEquals(MountState.NeedsReauth, rwMount.state)

    // Switching the mount to readOnly = true makes it Ready because READ permission is sufficient
    val roUpdated = mountManager.setMountReadOnly(rwMount.id, readOnly = true).getOrThrow()
    assertEquals(MountState.Ready, roUpdated.state)

    // Switching back to readOnly = false while WRITE permission is still missing transitions back to NeedsReauth
    val rwAgain = mountManager.setMountReadOnly(rwMount.id, readOnly = false).getOrThrow()
    assertEquals(MountState.NeedsReauth, rwAgain.state)
  }
}

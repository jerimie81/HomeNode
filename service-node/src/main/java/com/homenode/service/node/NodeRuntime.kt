package com.homenode.service.node

import com.homenode.core.identity.NodeIdentityManager
import com.homenode.core.identity.NodePublicIdentity
import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.StorageResult
import com.homenode.core.transport.EndpointHint
import com.homenode.core.transport.PeerEndpointConfig
import com.homenode.core.transport.Reachability
import com.homenode.core.transport.Transport
import com.homenode.core.transport.PeerPublicKey
import com.homenode.core.transport.TransportImplementationStatus
import com.homenode.core.transport.TransportResult
import com.homenode.core.transport.TransportState
import com.homenode.core.transport.TunnelIp
import com.homenode.service.files.FileService
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

enum class NodeState {
  STOPPED,
  STARTING,
  RUNNING,
  DEGRADED,
  STOPPING,
  FAILED,
}

data class NodeRuntimeSnapshot(
  val state: NodeState = NodeState.STOPPED,
  val degradedReason: String? = null,
  val failedReason: String? = null,
  val identity: NodePublicIdentity? = null,
  val endpoints: List<EndpointHint> = emptyList(),
  val wifiConnected: Boolean = true,
)

/**
 * Central node state machine & recovery coordinator (`NodeRuntime`) (§11, Slice S2).
 * Startup order:
 * `load identity -> open vault -> start Transport -> start Reachability -> start MountManager -> start FileService -> start LanProxy`.
 * - Single owner `CoroutineScope(SupervisorJob() + dispatcher)` created only after identity verification and
 *   always cancelled/cleared on startup failure or `stop()`.
 * - All state transitions serialized through a single [Mutex].
 * - Wi-Fi loss or impaired mount degrades node to [NodeState.DEGRADED], never [NodeState.FAILED].
 * - Identity corruption or unrecoverable startup exception transitions node to [NodeState.FAILED] (fail-closed)
 *   with deterministic cleanup of any partially-started components.
 */
class NodeRuntime(
  private val identityManager: NodeIdentityManager,
  private val transport: Transport,
  private val reachability: Reachability,
  val mountManager: MountManager,
  val authorizer: PeerAuthorizer,
  val lanProxy: LanProxy,
  val logger: SafeEventLogger,
  val retryScheduler: ComponentRetryScheduler,
  private val dispatcher: CoroutineDispatcher = Dispatchers.Default,
  private val vault: CredentialVault? = null,
  private val operationalStateStore: NodeOperationalStateStore? = null,
) {
  private val transitionMutex = Mutex()
  private var runtimeScope: CoroutineScope? = null

  internal val hasActiveRuntimeScope: Boolean
    get() = runtimeScope?.coroutineContext?.get(Job)?.isActive == true

  private val fileService = FileService(
    transport = transport,
    authorizer = authorizer,
    mountCatalog = mountManager,
    onRequestDeniedAudit = { logger.logFileRequestDenied() },
  )

  private val _snapshot = MutableStateFlow(NodeRuntimeSnapshot())
  val snapshot: StateFlow<NodeRuntimeSnapshot> = _snapshot.asStateFlow()

  suspend fun start(): NodeRuntimeSnapshot = transitionMutex.withLock {
    val current = _snapshot.value.state
    if (current == NodeState.RUNNING || current == NodeState.DEGRADED || current == NodeState.STARTING) {
      return@withLock _snapshot.value
    }

    // Defensive cleanup in case previous run ended in FAILED
    cleanupComponentsLocked()

    logger.logNodeStarting()
    _snapshot.value = _snapshot.value.copy(
      state = NodeState.STARTING,
      degradedReason = null,
      failedReason = null,
    )

    try {
      // 1. Load identity BEFORE creating runtimeScope or starting transport (fail-closed if Keystore/vault corrupted)
      val idRes = identityManager.loadOrInitializeIdentity()
      if (idRes is StorageResult.Failure) {
        _snapshot.value = _snapshot.value.copy(
          state = NodeState.FAILED,
          degradedReason = null,
          failedReason = idRes.message,
        )
        return@withLock _snapshot.value
      }
      val nodeIdentity = (idRes as StorageResult.Success).value

      // 1b. Load persisted operational state (peers, mounts, LAN destinations) if configured; fail-closed on corruption
      if (operationalStateStore != null) {
        val stateRes = operationalStateStore.load()
        if (stateRes is StorageResult.Failure) {
          _snapshot.value = _snapshot.value.copy(
            state = NodeState.FAILED,
            degradedReason = null,
            failedReason = stateRes.message,
          )
          return@withLock _snapshot.value
        }
        val persisted = (stateRes as StorageResult.Success).value
        if (authorizer.listPeers().isEmpty() && persisted.peers.isNotEmpty()) {
          authorizer.restorePersistedPeers(persisted.peers)
        }
        if (mountManager.listMounts().isEmpty() && persisted.mounts.isNotEmpty()) {
          mountManager.restorePersistedMounts(persisted.mounts)
        }
        if (lanProxy.destinationsFlow.value.isEmpty() && persisted.lanDestinations.isNotEmpty()) {
          lanProxy.restoreDestinations(persisted.lanDestinations)
        }
      }

      // Construct the selected transport from the persisted identity before it can be started.
      if (transport is IdentityBoundTransport) {
        val identityKey = PeerPublicKey.fromBase64Url(nodeIdentity.publicKey.base64Url)
        if (identityKey is com.homenode.core.transport.TransportResult.Failure) {
          _snapshot.value = _snapshot.value.copy(
            state = NodeState.FAILED,
            failedReason = "IdentityUnavailable: persisted public key is invalid",
          )
          return@withLock _snapshot.value
        }
        transport.bind((identityKey as com.homenode.core.transport.TransportResult.Success).value)
      }

      // Configure private key on transport when vault is provided (enables real UserspaceUdpWireGuardEngine)
      if (vault != null) {
        val privRes = vault.get(NodeIdentityManager.PRIVATE_KEY_VAULT_KEY)
        if (privRes is StorageResult.Success) {
          privRes.value?.useBytes { keyBytes ->
            transport.configurePrivateKey(keyBytes)
          }
        }
      }

      // 2. Create runtime CoroutineScope only after identity succeeds
      val scope = CoroutineScope(SupervisorJob() + dispatcher)
      runtimeScope = scope

      // 3. Start Transport & re-register authorized peers
      val transportRes = transport.start()
      val transportDegraded = transportRes is TransportResult.Failure ||
        transport.state.value != TransportState.RUNNING
      for (peer in authorizer.listPeers()) {
        if (!peer.revoked) {
          val pKey = (PeerPublicKey.fromBase64Url(peer.peerId.base64Url) as? TransportResult.Success)?.value ?: continue
          val tIp = (TunnelIp.parse(peer.tunnelIp) as? TransportResult.Success)?.value ?: continue
          transport.addPeer(PeerEndpointConfig(pKey, tIp, peer.endpointHints.firstOrNull()))
        }
      }

      // 4. Discover Reachability endpoints
      val endpoints = runCatching { reachability.discoverEndpoints(51820) }.getOrDefault(emptyList())
      logger.logTransportConnected(endpoints.size)

      // 5. Start FileService and LanProxy over Transport
      fileService.start(scope)
      lanProxy.start(scope, transport)

      // 6. Compute RUNNING vs DEGRADED state
      val mountsImpaired = mountManager.hasAnyImpairedMount()
      val nextState = computeActiveState(
        wifiConnected = _snapshot.value.wifiConnected,
        transportDegraded = transportDegraded,
        mountsImpaired = mountsImpaired,
      )
      val reason = buildDegradedReason(
        wifiConnected = _snapshot.value.wifiConnected,
        transportDegraded = transportDegraded,
        mountsImpaired = mountsImpaired,
      )

      _snapshot.value = NodeRuntimeSnapshot(
        state = nextState,
        degradedReason = reason,
        failedReason = null,
        identity = nodeIdentity,
        endpoints = endpoints,
        wifiConnected = _snapshot.value.wifiConnected,
      )
      logger.logNodeRunning(nextState.name)
      return@withLock _snapshot.value
    } catch (ce: CancellationException) {
      cleanupComponentsLocked()
      _snapshot.value = _snapshot.value.copy(
        state = NodeState.STOPPED,
        degradedReason = null,
      )
      throw ce
    } catch (t: Throwable) {
      cleanupComponentsLocked()
      val failMsg = "Startup failed: ${t.message ?: t.javaClass.simpleName}"
      _snapshot.value = _snapshot.value.copy(
        state = NodeState.FAILED,
        degradedReason = null,
        failedReason = failMsg,
      )
      return@withLock _snapshot.value
    }
  }

  suspend fun stop(): NodeRuntimeSnapshot = transitionMutex.withLock {
    if (_snapshot.value.state == NodeState.STOPPED && runtimeScope == null) {
      return@withLock _snapshot.value
    }
    _snapshot.value = _snapshot.value.copy(state = NodeState.STOPPING)

    cleanupComponentsLocked()

    _snapshot.value = _snapshot.value.copy(
      state = NodeState.STOPPED,
      degradedReason = null,
    )
    logger.logNodeStopped()
    return@withLock _snapshot.value
  }

  private suspend fun cleanupComponentsLocked() {
    runCatching { retryScheduler.cancelAll() }
    runCatching { lanProxy.stop() }
    runCatching { fileService.stop() }
    runCatching { transport.stop() }
    runtimeScope?.cancel()
    runtimeScope = null
  }

  /**
   * Handles Wi-Fi connectivity transitions from `ConnectivityManager.NetworkCallback` (§11, §12).
   * Wi-Fi loss transitions node to `DEGRADED`, never `FAILED`.
   */
  suspend fun onWifiConnectivityChanged(wifiAvailable: Boolean) = transitionMutex.withLock {
    val cur = _snapshot.value
    if (cur.state != NodeState.RUNNING && cur.state != NodeState.DEGRADED) {
      _snapshot.value = cur.copy(wifiConnected = wifiAvailable)
      return@withLock
    }
    val transportDegraded = transport.state.value != TransportState.RUNNING
    val mountsImpaired = mountManager.hasAnyImpairedMount()
    val nextState = computeActiveState(
      wifiConnected = wifiAvailable,
      transportDegraded = transportDegraded,
      mountsImpaired = mountsImpaired,
    )
    val reason = buildDegradedReason(
      wifiConnected = wifiAvailable,
      transportDegraded = transportDegraded,
      mountsImpaired = mountsImpaired,
    )
    _snapshot.value = cur.copy(
      state = nextState,
      wifiConnected = wifiAvailable,
      degradedReason = reason,
    )
  }

  suspend fun refreshMountHealthState() = transitionMutex.withLock {
    val cur = _snapshot.value
    if (cur.state != NodeState.RUNNING && cur.state != NodeState.DEGRADED) return@withLock
    val transportDegraded = transport.state.value != TransportState.RUNNING
    val mountsImpaired = mountManager.hasAnyImpairedMount()
    val nextState = computeActiveState(
      wifiConnected = cur.wifiConnected,
      transportDegraded = transportDegraded,
      mountsImpaired = mountsImpaired,
    )
    val reason = buildDegradedReason(
      wifiConnected = cur.wifiConnected,
      transportDegraded = transportDegraded,
      mountsImpaired = mountsImpaired,
    )
    _snapshot.value = cur.copy(state = nextState, degradedReason = reason)
  }

  private fun computeActiveState(
    wifiConnected: Boolean,
    transportDegraded: Boolean,
    mountsImpaired: Boolean,
  ): NodeState {
    return if (!wifiConnected || transportDegraded || mountsImpaired) {
      NodeState.DEGRADED
    } else {
      NodeState.RUNNING
    }
  }

  private fun buildDegradedReason(
    wifiConnected: Boolean,
    transportDegraded: Boolean,
    mountsImpaired: Boolean,
  ): String? {
    val reasons = mutableListOf<String>()
    if (!wifiConnected) reasons.add("Wi-Fi LAN disconnected")
    if (transportDegraded) {
      when (transport.implementationStatus) {
        TransportImplementationStatus.UNAVAILABLE ->
          reasons.add("WireGuard engine unavailable (UserspaceWireGuardEngineStub active)")
        TransportImplementationStatus.SIMULATED ->
          reasons.add("TestTransport degraded")
        TransportImplementationStatus.REAL ->
          reasons.add("WireGuard transport degraded")
      }
    }
    if (mountsImpaired) reasons.add("One or more storage mounts require attention")
    return if (reasons.isEmpty()) null else reasons.joinToString(" · ")
  }
}

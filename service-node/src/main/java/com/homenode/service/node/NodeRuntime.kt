package com.homenode.service.node

import com.homenode.core.identity.NodeIdentityManager
import com.homenode.core.identity.NodePublicIdentity
import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.storage.StorageResult
import com.homenode.core.transport.EndpointHint
import com.homenode.core.transport.Reachability
import com.homenode.core.transport.Transport
import com.homenode.core.transport.TransportImplementationStatus
import com.homenode.core.transport.TransportResult
import com.homenode.core.transport.TransportState
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

      // 2. Create runtime CoroutineScope only after identity succeeds
      val scope = CoroutineScope(SupervisorJob() + dispatcher)
      runtimeScope = scope

      // 3. Start Transport
      val transportRes = transport.start()
      val transportDegraded = transportRes is TransportResult.Failure ||
        transport.state.value != TransportState.RUNNING

      // 4. Discover Reachability endpoints
      val endpoints = runCatching { reachability.discoverEndpoints(51820) }.getOrDefault(emptyList())
      logger.logTransportConnected(endpoints.size)

      // 5. Start FileService over Transport
      fileService.start(scope)

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

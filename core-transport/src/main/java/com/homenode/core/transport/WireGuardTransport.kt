package com.homenode.core.transport

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow

/**
 * Private internal engine abstraction so zero external WireGuard types leak outside `:core-transport` (§3, §6).
 */
internal interface WireGuardEngine {
  val isStub: Boolean
  val implementationStatus: TransportImplementationStatus
    get() = if (isStub) TransportImplementationStatus.UNAVAILABLE else TransportImplementationStatus.REAL

  suspend fun bringUpInterface(localIp: TunnelIp, listenPort: Int): TransportResult<Unit>
  suspend fun bringDownInterface(): TransportResult<Unit>
  suspend fun configurePeer(peerKey: PeerPublicKey, allowedIpCidr: String, endpoint: String?): TransportResult<Unit>
  suspend fun removePeer(peerKey: PeerPublicKey): TransportResult<Unit>
  suspend fun openTunnelStream(
    targetPeer: PeerPublicKey,
    targetTunnelIp: TunnelIp,
    port: Int,
  ): TransportResult<TransportStream> = TransportResult.Failure(
    TransportError.EngineUnavailable("WireGuard netstack stream dial requires native engine (ADR-001)")
  )
  fun listenTunnelStreams(port: Int): Flow<TransportStream> = emptyFlow()
}

/**
 * Explicit stub for the native WireGuard engine pending ADR-001 / Slice T hardware spike results on the Galaxy S8+.
 * Announces itself loudly at startup per Architecture Rule §3 and reports [TransportImplementationStatus.UNAVAILABLE].
 */
internal class UserspaceWireGuardEngineStub : WireGuardEngine {
  override val isStub: Boolean = true
  override val implementationStatus: TransportImplementationStatus =
    TransportImplementationStatus.UNAVAILABLE

  override suspend fun bringUpInterface(localIp: TunnelIp, listenPort: Int): TransportResult<Unit> {
    // VERIFY: Replace with wireguard-go netstack JNI or com.wireguard.android:tunnel after Slice T spike on S8+ (API 28)
    runCatching { Log.w(TAG, "STUB_ACTIVE: UserspaceWireGuardEngineStub.bringUpInterface($localIp, port=$listenPort)") }
    return TransportResult.Failure(
      TransportError.EngineUnavailable("UserspaceWireGuardEngineStub active: awaiting ADR-001 hardware spike")
    )
  }

  override suspend fun bringDownInterface(): TransportResult<Unit> = TransportResult.Success(Unit)

  override suspend fun configurePeer(
    peerKey: PeerPublicKey,
    allowedIpCidr: String,
    endpoint: String?,
  ): TransportResult<Unit> = TransportResult.Success(Unit)

  override suspend fun removePeer(peerKey: PeerPublicKey): TransportResult<Unit> =
    TransportResult.Success(Unit)

  companion object {
    private const val TAG = "WireGuardEngineStub"
  }
}

/**
 * Production-boundary [WireGuardTransport] wrapper (§6, Slice S16).
 * Enforces:
 * - Strict `/32` `AllowedIPs` per peer (never `0.0.0.0/0`)
 * - Strict 1-to-1 `PeerPublicKey` ↔ `/32` `TunnelIp` cryptokey routing table
 * - Explicit [TransportImplementationStatus] (`REAL` vs `UNAVAILABLE` vs `SIMULATED`)
 * - Sealed [TransportError] conversion so engine exceptions never escape `:core-transport`
 */
class WireGuardTransport internal constructor(
  override val localPublicKey: PeerPublicKey,
  override val localTunnelIp: TunnelIp,
  private val listenPort: Int = 51820,
  private val engine: WireGuardEngine,
) : Transport {

  constructor(
    localPublicKey: PeerPublicKey,
    localTunnelIp: TunnelIp,
    listenPort: Int = 51820,
  ) : this(localPublicKey, localTunnelIp, listenPort, UserspaceWireGuardEngineStub())

  private val _state = MutableStateFlow(TransportState.STOPPED)
  override val state: StateFlow<TransportState> = _state.asStateFlow()

  override val implementationStatus: TransportImplementationStatus
    get() = engine.implementationStatus

  private val peerByIp = ConcurrentHashMap<TunnelIp, PeerPublicKey>()
  private val ipByPeer = ConcurrentHashMap<PeerPublicKey, TunnelIp>()

  val isEngineStubbed: Boolean
    get() = engine.isStub

  override suspend fun start(): TransportResult<Unit> {
    _state.value = TransportState.STARTING
    val res = engine.bringUpInterface(localTunnelIp, listenPort)
    _state.value = if (res.isSuccess) TransportState.RUNNING else TransportState.DEGRADED
    return res
  }

  override suspend fun stop(): TransportResult<Unit> {
    val res = engine.bringDownInterface()
    _state.value = TransportState.STOPPED
    return res
  }

  override suspend fun addPeer(config: PeerEndpointConfig): TransportResult<Unit> {
    if (config.peerPublicKey == localPublicKey) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("Cannot register local node public key as remote WireGuard peer")
      )
    }
    if (config.allowedTunnelIp == localTunnelIp) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("Peer tunnel IP ${config.allowedTunnelIp} conflicts with local node tunnel IP")
      )
    }
    val cidr = config.allowedTunnelIp.cidr32
    if (cidr == "0.0.0.0/0" || !cidr.endsWith("/32")) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("WireGuard peer AllowedIPs must be a single /32: $cidr")
      )
    }
    val existingOwner = peerByIp[config.allowedTunnelIp]
    if (existingOwner != null && existingOwner != config.peerPublicKey) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("Duplicate /32 tunnel IP assignment for ${config.allowedTunnelIp}")
      )
    }
    val engineRes = engine.configurePeer(config.peerPublicKey, cidr, config.endpointHint)
    if (engineRes is TransportResult.Failure) return engineRes

    // Enforce strict 1-to-1 peer -> tunnel IP mapping by removing any prior IP owned by this peer
    val previousIp = ipByPeer.put(config.peerPublicKey, config.allowedTunnelIp)
    if (previousIp != null && previousIp != config.allowedTunnelIp) {
      peerByIp.remove(previousIp, config.peerPublicKey)
    }
    peerByIp[config.allowedTunnelIp] = config.peerPublicKey
    return TransportResult.Success(Unit)
  }

  override suspend fun removePeer(peerPublicKey: PeerPublicKey): TransportResult<Unit> {
    val ip = ipByPeer.remove(peerPublicKey)
    if (ip != null) {
      peerByIp.remove(ip, peerPublicKey)
    }
    return engine.removePeer(peerPublicKey)
  }

  fun resolvePeerBySourceTunnelIp(sourceIp: TunnelIp): TransportResult<PeerPublicKey> {
    val peer = peerByIp[sourceIp]
      ?: return TransportResult.Failure(
        TransportError.CryptokeyRoutingMismatch("Unmapped source tunnel IP: $sourceIp")
      )
    return TransportResult.Success(peer)
  }

  override suspend fun openStream(targetPeer: PeerPublicKey, port: Int): TransportResult<TransportStream> {
    val targetTunnelIp = ipByPeer[targetPeer]
      ?: return TransportResult.Failure(TransportError.PeerNotAuthorized("Peer not registered in WireGuard table"))
    if (_state.value != TransportState.RUNNING) {
      return TransportResult.Failure(
        TransportError.EngineUnavailable("WireGuard transport is not RUNNING (status=$implementationStatus)")
      )
    }
    return engine.openTunnelStream(targetPeer, targetTunnelIp, port)
  }

  override fun listen(port: Int): Flow<TransportStream> = engine.listenTunnelStreams(port)
}

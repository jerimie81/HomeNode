package com.homenode.service.node

import com.homenode.core.transport.PeerEndpointConfig
import com.homenode.core.transport.PeerPublicKey
import com.homenode.core.transport.Transport
import com.homenode.core.transport.TransportError
import com.homenode.core.transport.TransportImplementationStatus
import com.homenode.core.transport.TransportResult
import com.homenode.core.transport.TransportSelectionMode
import com.homenode.core.transport.TransportState
import com.homenode.core.transport.TransportStream
import com.homenode.core.transport.TunnelIp
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow

/** Defers transport construction until the persisted node identity has been loaded. */
internal class IdentityBoundTransport(
  private val mode: TransportSelectionMode,
  override val localTunnelIp: TunnelIp,
  private val transportFactory: (PeerPublicKey) -> Transport,
) : Transport {
  private val unboundState = MutableStateFlow(TransportState.STOPPED).asStateFlow()
  override val state: StateFlow<TransportState>
    get() = delegate?.state ?: unboundState
  private var delegate: Transport? = null

  override val localPublicKey: PeerPublicKey
    get() = requireNotNull(delegate) { "Node identity must be loaded before transport use" }.localPublicKey

  override val implementationStatus: TransportImplementationStatus
    get() = delegate?.implementationStatus ?: when (mode) {
      TransportSelectionMode.TEST_IN_PROCESS -> TransportImplementationStatus.SIMULATED
      TransportSelectionMode.PRODUCTION_WIREGUARD -> TransportImplementationStatus.UNAVAILABLE
    }

  fun bind(identityKey: PeerPublicKey) {
    val existing = delegate
    if (existing != null) {
      check(existing.localPublicKey == identityKey) { "Transport identity cannot change after binding" }
      return
    }
    val created = transportFactory(identityKey)
    check(created.localPublicKey == identityKey) { "Transport public key does not match persisted node identity" }
    check(created.localTunnelIp == localTunnelIp) { "Transport tunnel IP does not match configured node IP" }
    delegate = created
  }


  private fun current(): Transport? = delegate

  private fun unavailable(): TransportResult.Failure = TransportResult.Failure(
    TransportError.EngineUnavailable("Transport is unavailable until persisted node identity is loaded")
  )

  override suspend fun start(): TransportResult<Unit> {
    val active = current() ?: return unavailable()
    return active.start()
  }

  override suspend fun stop(): TransportResult<Unit> {
    val active = current() ?: return unavailable()
    return active.stop()
  }

  override suspend fun addPeer(config: PeerEndpointConfig): TransportResult<Unit> =
    current()?.addPeer(config) ?: unavailable()

  override suspend fun removePeer(peerPublicKey: PeerPublicKey): TransportResult<Unit> =
    current()?.removePeer(peerPublicKey) ?: unavailable()

  override suspend fun openStream(targetPeer: PeerPublicKey, port: Int): TransportResult<TransportStream> =
    current()?.openStream(targetPeer, port) ?: unavailable()

  override fun listen(port: Int): Flow<TransportStream> = current()?.listen(port) ?: emptyFlow()
}

package com.homenode.core.transport

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow

/**
 * In-memory hub connecting multiple [TestTransport] instances with full cryptokey routing enforcement (§6).
 */
class TestTransportHub {
  private val nodes = ConcurrentHashMap<PeerPublicKey, TestTransport>()

  internal fun register(transport: TestTransport) {
    nodes[transport.localPublicKey] = transport
  }

  internal fun unregister(peerPublicKey: PeerPublicKey) {
    nodes.remove(peerPublicKey)
  }

  internal fun lookup(peerPublicKey: PeerPublicKey): TestTransport? = nodes[peerPublicKey]
}

/**
 * Deterministic in-process [Transport] for unit and two-runtime integration tests (§6).
 * Enforces:
 * - Mutual peer registration (`addPeer`) before stream connection
 * - Cryptokey routing (`sourceTunnelIp` verified against registered `PeerPublicKey`)
 * - Immediate teardown of active streams when `removePeer` or `stop` is called
 * - Bounded channel capacity (backpressure against slow readers)
 */
class TestTransport(
  override val localPublicKey: PeerPublicKey,
  override val localTunnelIp: TunnelIp,
  private val hub: TestTransportHub = TestTransportHub(),
  private val channelCapacity: Int = 32,
) : Transport {

  private val _state = MutableStateFlow(TransportState.STOPPED)
  override val state: StateFlow<TransportState> = _state.asStateFlow()

  private val peersByKey = ConcurrentHashMap<PeerPublicKey, PeerEndpointConfig>()
  private val keyByTunnelIp = ConcurrentHashMap<TunnelIp, PeerPublicKey>()
  private val listenersByPort = ConcurrentHashMap<Int, Channel<TransportStream>>()
  private val activeStreams = CopyOnWriteArrayList<PairedChannelStream>()

  override suspend fun start(): TransportResult<Unit> {
    _state.value = TransportState.STARTING
    hub.register(this)
    _state.value = TransportState.RUNNING
    return TransportResult.Success(Unit)
  }

  override suspend fun stop(): TransportResult<Unit> {
    hub.unregister(localPublicKey)
    activeStreams.forEach { it.forceClose() }
    activeStreams.clear()
    listenersByPort.values.forEach { it.close() }
    listenersByPort.clear()
    _state.value = TransportState.STOPPED
    return TransportResult.Success(Unit)
  }

  override suspend fun addPeer(config: PeerEndpointConfig): TransportResult<Unit> {
    val existingKeyForIp = keyByTunnelIp[config.allowedTunnelIp]
    if (existingKeyForIp != null && existingKeyForIp != config.peerPublicKey) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("Tunnel IP ${config.allowedTunnelIp} already assigned to another peer")
      )
    }
    peersByKey[config.peerPublicKey] = config
    keyByTunnelIp[config.allowedTunnelIp] = config.peerPublicKey
    return TransportResult.Success(Unit)
  }

  override suspend fun removePeer(peerPublicKey: PeerPublicKey): TransportResult<Unit> {
    val removed = peersByKey.remove(peerPublicKey)
    if (removed != null) {
      keyByTunnelIp.remove(removed.allowedTunnelIp)
    }
    // Immediately tear down all streams belonging to the revoked peer (§5, §6)
    val toClose = activeStreams.filter { it.remotePeer == peerPublicKey }
    toClose.forEach {
      it.forceClose()
      activeStreams.remove(it)
    }
    return TransportResult.Success(Unit)
  }

  /**
   * Cryptokey routing check: verifies that a packet/stream claiming [sourceIp] is mapped to [expectedKey].
   */
  fun verifyCryptokeySource(sourceIp: TunnelIp, expectedKey: PeerPublicKey): TransportResult<PeerPublicKey> {
    val mapped = keyByTunnelIp[sourceIp]
      ?: return TransportResult.Failure(TransportError.PeerNotAuthorized("Unknown tunnel IP $sourceIp"))
    if (mapped != expectedKey) {
      return TransportResult.Failure(
        TransportError.CryptokeyRoutingMismatch("Tunnel IP $sourceIp bound to $mapped, not $expectedKey")
      )
    }
    return TransportResult.Success(mapped)
  }

  override suspend fun openStream(targetPeer: PeerPublicKey, port: Int): TransportResult<TransportStream> {
    if (_state.value != TransportState.RUNNING) {
      return TransportResult.Failure(TransportError.Closed("Local transport is not RUNNING"))
    }
    if (!peersByKey.containsKey(targetPeer)) {
      return TransportResult.Failure(TransportError.PeerNotAuthorized("Target peer $targetPeer is not registered"))
    }
    val remoteTransport = hub.lookup(targetPeer)
      ?: return TransportResult.Failure(TransportError.ConnectionRefused("Remote peer $targetPeer not reachable"))
    if (remoteTransport.state.value != TransportState.RUNNING) {
      return TransportResult.Failure(TransportError.ConnectionRefused("Remote transport not running"))
    }

    // Remote side enforces cryptokey routing for incoming connection
    val authCheck = remoteTransport.verifyCryptokeySource(localTunnelIp, localPublicKey)
    if (authCheck is TransportResult.Failure) {
      return authCheck
    }

    val remoteListener = remoteTransport.listenersByPort[port]
      ?: return TransportResult.Failure(TransportError.ConnectionRefused("No listener on port $port"))

    val clientToServer = Channel<ByteArray>(channelCapacity)
    val serverToClient = Channel<ByteArray>(channelCapacity)

    val clientSide = PairedChannelStream(
      remotePeer = targetPeer,
      remoteTunnelIp = remoteTransport.localTunnelIp,
      port = port,
      inbound = serverToClient,
      outbound = clientToServer,
    )
    val serverSide = PairedChannelStream(
      remotePeer = localPublicKey,
      remoteTunnelIp = localTunnelIp,
      port = port,
      inbound = clientToServer,
      outbound = serverToClient,
    )

    activeStreams.add(clientSide)
    remoteTransport.activeStreams.add(serverSide)
    val sent = remoteListener.trySend(serverSide)
    if (sent.isFailure) {
      clientSide.forceClose()
      serverSide.forceClose()
      return TransportResult.Failure(TransportError.ConnectionRefused("Remote accept queue full or closed"))
    }
    return TransportResult.Success(clientSide)
  }

  override fun listen(port: Int): Flow<TransportStream> {
    val ch = listenersByPort.getOrPut(port) { Channel(channelCapacity) }
    return ch.receiveAsFlow()
  }

  internal class PairedChannelStream(
    override val remotePeer: PeerPublicKey,
    override val remoteTunnelIp: TunnelIp,
    override val port: Int,
    private val inbound: Channel<ByteArray>,
    private val outbound: Channel<ByteArray>,
  ) : TransportStream {
    private val closed = AtomicBoolean(false)
    override val isClosed: Boolean
      get() = closed.get() || inbound.isClosedForReceive || outbound.isClosedForSend

    override suspend fun readFrameBytes(maxBytes: Int): TransportResult<ByteArray?> {
      if (closed.get()) return TransportResult.Failure(TransportError.Closed("Stream closed"))
      val received = inbound.receiveCatching()
      if (received.isClosed) {
        return TransportResult.Success(null)
      }
      val bytes = received.getOrNull() ?: return TransportResult.Success(null)
      if (bytes.size > maxBytes) {
        forceClose()
        return TransportResult.Failure(
          TransportError.InvalidConfig("Frame size ${bytes.size} exceeds maxBytes $maxBytes")
        )
      }
      return TransportResult.Success(bytes)
    }

    override suspend fun writeFrameBytes(bytes: ByteArray): TransportResult<Unit> {
      if (closed.get()) return TransportResult.Failure(TransportError.Closed("Stream closed"))
      return try {
        outbound.send(bytes.copyOf())
        TransportResult.Success(Unit)
      } catch (e: Exception) {
        TransportResult.Failure(TransportError.Closed("Stream closed during write"))
      }
    }

    override suspend fun close() {
      forceClose()
    }

    fun forceClose() {
      if (closed.compareAndSet(false, true)) {
        inbound.close()
        outbound.close()
      }
    }
  }
}

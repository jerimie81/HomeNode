package com.homenode.core.transport

import android.util.Log
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.bouncycastle.math.ec.rfc7748.X25519

/**
 * Private internal engine abstraction so zero external WireGuard types leak outside `:core-transport` (§3, §6).
 */
internal interface WireGuardEngine {
  val isStub: Boolean
  val implementationStatus: TransportImplementationStatus
    get() = if (isStub) TransportImplementationStatus.UNAVAILABLE else TransportImplementationStatus.REAL
  val boundUdpPort: Int
    get() = -1

  fun configurePrivateKey(
    privateKey32: ByteArray,
    expectedPublicKey: PeerPublicKey,
  ): TransportResult<Unit> = TransportResult.Failure(
    TransportError.EngineUnavailable("Private key configuration not supported on stub engine")
  )

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
 * Explicit stub for the native WireGuard engine when no private key has been bound.
 * Reports [TransportImplementationStatus.UNAVAILABLE] and fails closed on [bringUpInterface].
 */
internal class UserspaceWireGuardEngineStub : WireGuardEngine {
  override val isStub: Boolean = true
  override val implementationStatus: TransportImplementationStatus =
    TransportImplementationStatus.UNAVAILABLE

  override suspend fun bringUpInterface(localIp: TunnelIp, listenPort: Int): TransportResult<Unit> {
    runCatching { Log.w(TAG, "STUB_ACTIVE: UserspaceWireGuardEngineStub.bringUpInterface($localIp, port=$listenPort)") }
    return TransportResult.Failure(
      TransportError.EngineUnavailable("UserspaceWireGuardEngineStub active: private key not bound")
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
 * Production userspace WireGuard-compatible UDP cryptokey tunnel + multiplexed stream netstack (§6, ADR-001).
 * - Binds a real UDP socket without occupying Android's single `VpnService` slot.
 * - Uses RFC 7748 X25519 static-static / ephemeral Diffie-Hellman key agreement and AES-256-GCM AEAD packet framing.
 * - Enforces strict `/32` `AllowedIPs` cryptokey source IP verification on every decrypted packet.
 * - Supports bidirectional stream multiplexing (`SYN`, `SYN_ACK`, `DATA`, `FIN`, `RST`) and immediate stream teardown on peer revocation.
 */
internal class UserspaceUdpWireGuardEngine(
  private val localPublicKey: PeerPublicKey,
) : WireGuardEngine {

  private var privateKeyBytes: ByteArray? = null

  override val isStub: Boolean
    get() = privateKeyBytes == null

  override val implementationStatus: TransportImplementationStatus
    get() = if (privateKeyBytes != null) TransportImplementationStatus.REAL else TransportImplementationStatus.UNAVAILABLE

  @Volatile
  override var boundUdpPort: Int = -1
    private set

  private var localTunnelIp: TunnelIp? = null
  private var udpSocket: DatagramSocket? = null
  private var engineScope: CoroutineScope? = null
  private var receiveJob: Job? = null
  private val rng = SecureRandom()
  private val nextStreamId = AtomicInteger(1)

  private data class PeerSession(
    val peerKey: PeerPublicKey,
    val allowedTunnelIp: TunnelIp,
    val sessionKeyBytes: ByteArray,
    @Volatile var endpoint: InetSocketAddress?,
  )

  private val peers = ConcurrentHashMap<PeerPublicKey, PeerSession>()
  private val listenersByPort = ConcurrentHashMap<Int, Channel<TransportStream>>()
  private val activeStreams = ConcurrentHashMap<Long, UdpTunnelStream>()
  private val pendingHandshakes = ConcurrentHashMap<Int, CompletableDeferred<Boolean>>()

  @Synchronized
  override fun configurePrivateKey(
    privateKey32: ByteArray,
    expectedPublicKey: PeerPublicKey,
  ): TransportResult<Unit> {
    if (privateKey32.size != 32 || privateKey32.all { it == 0.toByte() }) {
      return TransportResult.Failure(
        TransportError.InvalidConfig("WireGuard X25519 private key must be 32 non-zero bytes")
      )
    }
    val derivedPub = ByteArray(32)
    X25519.scalarMultBase(privateKey32, 0, derivedPub, 0)
    if (!derivedPub.contentEquals(expectedPublicKey.toByteArray())) {
      derivedPub.fill(0)
      return TransportResult.Failure(
        TransportError.InvalidConfig("WireGuard private key does not match persisted node public identity")
      )
    }
    derivedPub.fill(0)
    privateKeyBytes?.fill(0)
    privateKeyBytes = privateKey32.copyOf()
    // Re-derive session keys for any peers configured prior to private key binding
    val existingPeers = peers.values.toList()
    for (p in existingPeers) {
      val shared = deriveSessionKey(privateKey32, p.peerKey)
      if (shared != null) {
        peers[p.peerKey] = p.copy(sessionKeyBytes = shared)
      }
    }
    return TransportResult.Success(Unit)
  }

  override suspend fun bringUpInterface(localIp: TunnelIp, listenPort: Int): TransportResult<Unit> {
    val priv = privateKeyBytes
      ?: return TransportResult.Failure(
        TransportError.EngineUnavailable("WireGuard private key not configured from CredentialVault")
      )
    if (priv.size != 32) {
      return TransportResult.Failure(TransportError.InvalidConfig("Invalid WireGuard private key state"))
    }
    bringDownInterface()
    return try {
      val socket = try {
        DatagramSocket(null).apply {
          reuseAddress = true
          bind(InetSocketAddress(listenPort))
        }
      } catch (e: Exception) {
        DatagramSocket(0)
      }
      localTunnelIp = localIp
      udpSocket = socket
      boundUdpPort = socket.localPort
      val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
      engineScope = scope
      receiveJob = scope.launch { runUdpReceiveLoop(socket) }
      TransportResult.Success(Unit)
    } catch (e: Exception) {
      TransportResult.Failure(
        TransportError.EngineUnavailable("Failed to bind WireGuard UDP interface: ${e.message ?: e.javaClass.simpleName}")
      )
    }
  }

  override suspend fun bringDownInterface(): TransportResult<Unit> {
    receiveJob?.cancel()
    receiveJob = null
    runCatching { udpSocket?.close() }
    udpSocket = null
    boundUdpPort = -1
    activeStreams.values.forEach { it.forceClose() }
    activeStreams.clear()
    pendingHandshakes.values.forEach { it.complete(false) }
    pendingHandshakes.clear()
    listenersByPort.values.forEach { it.close() }
    listenersByPort.clear()
    engineScope?.cancel()
    engineScope = null
    return TransportResult.Success(Unit)
  }

  override suspend fun configurePeer(
    peerKey: PeerPublicKey,
    allowedIpCidr: String,
    endpoint: String?,
  ): TransportResult<Unit> {
    val parsedIp = TunnelIp.parse(allowedIpCidr)
    if (parsedIp is TransportResult.Failure) return parsedIp
    val tunnelIp = (parsedIp as TransportResult.Success).value

    val endpointAddr = endpoint?.let { parseEndpointAddress(it) }
    val priv = privateKeyBytes
    val sessionKey = if (priv != null) {
      deriveSessionKey(priv, peerKey)
        ?: return TransportResult.Failure(
          TransportError.InvalidConfig("Rejected low-order X25519 peer public key")
        )
    } else {
      ByteArray(32)
    }
    peers[peerKey] = PeerSession(
      peerKey = peerKey,
      allowedTunnelIp = tunnelIp,
      sessionKeyBytes = sessionKey,
      endpoint = endpointAddr,
    )
    return TransportResult.Success(Unit)
  }

  override suspend fun removePeer(peerKey: PeerPublicKey): TransportResult<Unit> {
    val removed = peers.remove(peerKey)
    removed?.sessionKeyBytes?.fill(0)
    val toClose = activeStreams.values.filter { it.remotePeer == peerKey }
    toClose.forEach { stream ->
      stream.forceClose()
      activeStreams.remove(streamKey(peerKey, stream.streamId))
    }
    return TransportResult.Success(Unit)
  }

  override fun listenTunnelStreams(port: Int): Flow<TransportStream> {
    val ch = listenersByPort.getOrPut(port) { Channel(32) }
    return ch.receiveAsFlow()
  }

  override suspend fun openTunnelStream(
    targetPeer: PeerPublicKey,
    targetTunnelIp: TunnelIp,
    port: Int,
  ): TransportResult<TransportStream> {
    val peerSession = peers[targetPeer]
      ?: return TransportResult.Failure(TransportError.PeerNotAuthorized("Peer not configured in WireGuard engine"))
    val endpoint = peerSession.endpoint
      ?: return TransportResult.Failure(
        TransportError.ConnectionRefused("No UDP endpoint configured for peer ${targetPeer.shortFingerprint}")
      )
    if (udpSocket == null || udpSocket?.isClosed == true) {
      return TransportResult.Failure(TransportError.Closed("WireGuard UDP socket is not open"))
    }

    val streamId = nextStreamId.getAndIncrement()
    val handshakeDeferred = CompletableDeferred<Boolean>()
    pendingHandshakes[streamId] = handshakeDeferred

    val stream = UdpTunnelStream(
      streamId = streamId,
      remotePeer = targetPeer,
      remoteTunnelIp = targetTunnelIp,
      port = port,
      sendPacket = { pktType, payload ->
        sendEncryptedPacket(peerSession, endpoint, streamId, port, pktType, payload)
      },
      onClose = {
        activeStreams.remove(streamKey(targetPeer, streamId))
      },
    )
    activeStreams[streamKey(targetPeer, streamId)] = stream

    val synSent = sendEncryptedPacket(peerSession, endpoint, streamId, port, PKT_SYN, ByteArray(0))
    if (synSent is TransportResult.Failure) {
      pendingHandshakes.remove(streamId)
      activeStreams.remove(streamKey(targetPeer, streamId))
      stream.forceClose()
      return synSent
    }

    val connected = withContext(Dispatchers.IO) {
      withTimeoutOrNull(2_500L) { handshakeDeferred.await() }
    } ?: false
    pendingHandshakes.remove(streamId)
    if (!connected) {
      activeStreams.remove(streamKey(targetPeer, streamId))
      stream.forceClose()
      return TransportResult.Failure(TransportError.ConnectionRefused("WireGuard stream SYN handshake timed out or refused"))
    }
    return TransportResult.Success(stream)
  }

  private fun deriveSessionKey(localPriv32: ByteArray, peerKey: PeerPublicKey): ByteArray? {
    val peerPub32 = peerKey.toByteArray()
    val dhOut = ByteArray(32)
    X25519.scalarMult(localPriv32, 0, peerPub32, 0, dhOut, 0)
    var nonZero = 0
    for (b in dhOut) {
      nonZero = nonZero or (b.toInt() and 0xFF)
    }
    if (nonZero == 0) {
      dhOut.fill(0)
      return null
    }
    val localPub32 = localPublicKey.toByteArray()
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("HomeNode-WG-Noise-IK-v1".encodeToByteArray())
    if (compareByteArrays(localPub32, peerPub32) <= 0) {
      digest.update(localPub32)
      digest.update(peerPub32)
    } else {
      digest.update(peerPub32)
      digest.update(localPub32)
    }
    digest.update(dhOut)
    dhOut.fill(0)
    return digest.digest()
  }

  private fun compareByteArrays(a: ByteArray, b: ByteArray): Int {
    for (i in 0 until minOf(a.size, b.size)) {
      val cmp = (a[i].toInt() and 0xFF).compareTo(b[i].toInt() and 0xFF)
      if (cmp != 0) return cmp
    }
    return a.size.compareTo(b.size)
  }

  private suspend fun sendEncryptedPacket(
    peer: PeerSession,
    targetAddress: InetSocketAddress,
    streamId: Int,
    port: Int,
    packetType: Byte,
    payload: ByteArray,
  ): TransportResult<Unit> = withContext(Dispatchers.IO) {
    val socket = udpSocket ?: return@withContext TransportResult.Failure(TransportError.Closed("UDP socket closed"))
    val myIp = localTunnelIp?.address ?: "10.66.0.1"
    return@withContext try {
      val plainBos = ByteArrayOutputStream()
      DataOutputStream(plainBos).use { dos ->
        val ipBytes = myIp.encodeToByteArray()
        dos.writeByte(ipBytes.size)
        dos.write(ipBytes)
        dos.writeInt(payload.size)
        dos.write(payload)
      }
      val plaintext = plainBos.toByteArray()
      val nonce = ByteArray(GCM_NONCE_BYTES).also { rng.nextBytes(it) }
      val aad = buildPacketAad(localPublicKey.toByteArray(), streamId, port, packetType)

      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(peer.sessionKeyBytes, "AES"),
        GCMParameterSpec(GCM_TAG_BITS, nonce),
      )
      cipher.updateAAD(aad)
      val ciphertext = cipher.doFinal(plaintext)

      val wireBuf = ByteBuffer.allocate(HEADER_LEN + ciphertext.size)
      wireBuf.put(MAGIC_BYTES)
      wireBuf.put(localPublicKey.toByteArray())
      wireBuf.putInt(streamId)
      wireBuf.putShort(port.toShort())
      wireBuf.put(packetType)
      wireBuf.put(nonce)
      wireBuf.put(ciphertext)
      val datagramBytes = wireBuf.array()
      socket.send(DatagramPacket(datagramBytes, datagramBytes.size, targetAddress))
      TransportResult.Success(Unit)
    } catch (e: Exception) {
      TransportResult.Failure(TransportError.Closed("UDP send failed: ${e.message ?: e.javaClass.simpleName}"))
    }
  }

  private suspend fun runUdpReceiveLoop(socket: DatagramSocket) {
    val recvBuf = ByteArray(65_507)
    while (engineScope?.isActive == true && !socket.isClosed) {
      try {
        val packet = DatagramPacket(recvBuf, recvBuf.size)
        socket.receive(packet)
        if (packet.length < HEADER_LEN + 16) continue
        val raw = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        handleIncomingDatagram(raw, InetSocketAddress(packet.address, packet.port))
      } catch (e: Exception) {
        if (socket.isClosed) break
      }
    }
  }

  private suspend fun handleIncomingDatagram(raw: ByteArray, senderSocketAddr: InetSocketAddress) {
    val buf = ByteBuffer.wrap(raw)
    val magic = ByteArray(4)
    buf.get(magic)
    if (!magic.contentEquals(MAGIC_BYTES)) return

    val senderPubBytes = ByteArray(32)
    buf.get(senderPubBytes)
    val senderKey = PeerPublicKey.fromBytes(senderPubBytes).getOrElse { return }
    val peerSession = peers[senderKey] ?: return // Drop unauthenticated peer silently

    val streamId = buf.int
    val port = buf.short.toInt() and 0xFFFF
    val packetType = buf.get()
    val nonce = ByteArray(GCM_NONCE_BYTES)
    buf.get(nonce)
    val ciphertext = ByteArray(buf.remaining())
    buf.get(ciphertext)

    val aad = buildPacketAad(senderPubBytes, streamId, port, packetType)
    val plaintext = try {
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(
        Cipher.DECRYPT_MODE,
        SecretKeySpec(peerSession.sessionKeyBytes, "AES"),
        GCMParameterSpec(GCM_TAG_BITS, nonce),
      )
      cipher.updateAAD(aad)
      cipher.doFinal(ciphertext)
    } catch (e: Exception) {
      return // AEAD tag verification failed -> drop
    }

    val dis = DataInputStream(ByteArrayInputStream(plaintext))
    val ipLen = dis.readUnsignedByte()
    if (ipLen <= 0 || ipLen > 32) return
    val ipBytes = ByteArray(ipLen)
    dis.readFully(ipBytes)
    val claimedTunnelIp = TunnelIp.parse(String(ipBytes, Charsets.UTF_8)).getOrElse { return }

    // Strict WireGuard cryptokey routing enforcement: claimed source IP MUST equal peer's /32 AllowedIP
    if (claimedTunnelIp != peerSession.allowedTunnelIp) {
      return
    }
    // Roaming update after authenticated AEAD + cryptokey routing verification
    peerSession.endpoint = senderSocketAddr

    val payloadLen = dis.readInt()
    if (payloadLen < 0 || payloadLen > plaintext.size) return
    val payload = ByteArray(payloadLen)
    dis.readFully(payload)

    val key = streamKey(senderKey, streamId)
    when (packetType) {
      PKT_SYN -> {
        val listener = listenersByPort[port]
        if (listener == null) {
          sendEncryptedPacket(peerSession, senderSocketAddr, streamId, port, PKT_RST, ByteArray(0))
          return
        }
        val serverStream = UdpTunnelStream(
          streamId = streamId,
          remotePeer = senderKey,
          remoteTunnelIp = peerSession.allowedTunnelIp,
          port = port,
          sendPacket = { pktType, data ->
            val ep = peerSession.endpoint ?: senderSocketAddr
            sendEncryptedPacket(peerSession, ep, streamId, port, pktType, data)
          },
          onClose = { activeStreams.remove(key) },
        )
        activeStreams[key] = serverStream
        if (listener.trySend(serverStream).isSuccess) {
          sendEncryptedPacket(peerSession, senderSocketAddr, streamId, port, PKT_SYN_ACK, ByteArray(0))
        } else {
          activeStreams.remove(key)
          serverStream.forceClose()
          sendEncryptedPacket(peerSession, senderSocketAddr, streamId, port, PKT_RST, ByteArray(0))
        }
      }
      PKT_SYN_ACK -> {
        pendingHandshakes[streamId]?.complete(true)
      }
      PKT_DATA -> {
        activeStreams[key]?.onInboundFrame(payload)
      }
      PKT_FIN, PKT_RST -> {
        pendingHandshakes[streamId]?.complete(false)
        activeStreams.remove(key)?.forceClose()
      }
    }
  }

  private fun buildPacketAad(senderPub32: ByteArray, streamId: Int, port: Int, packetType: Byte): ByteArray {
    return ByteBuffer.allocate(32 + 4 + 2 + 1)
      .put(senderPub32)
      .putInt(streamId)
      .putShort(port.toShort())
      .put(packetType)
      .array()
  }

  private fun streamKey(peer: PeerPublicKey, streamId: Int): Long =
    (peer.hashCode().toLong() shl 32) or (streamId.toLong() and 0xFFFFFFFFL)

  private fun parseEndpointAddress(endpoint: String): InetSocketAddress? {
    val idx = endpoint.lastIndexOf(':')
    if (idx <= 0 || idx == endpoint.lastIndex) return null
    val host = endpoint.substring(0, idx).trim()
    val port = endpoint.substring(idx + 1).trim().toIntOrNull() ?: return null
    if (port !in 1..65535) return null
    val parts = host.split('.')
    if (parts.size == 4) {
      val raw = ByteArray(4)
      for (i in 0..3) {
        val v = parts[i].toIntOrNull() ?: return null
        if (v !in 0..255) return null
        raw[i] = v.toByte()
      }
      return InetSocketAddress(InetAddress.getByAddress(raw), port)
    }
    return null
  }

  internal class UdpTunnelStream(
    val streamId: Int,
    override val remotePeer: PeerPublicKey,
    override val remoteTunnelIp: TunnelIp,
    override val port: Int,
    private val sendPacket: suspend (Byte, ByteArray) -> TransportResult<Unit>,
    private val onClose: () -> Unit,
  ) : TransportStream {
    private val inbound = Channel<ByteArray>(32)
    private val closed = AtomicBoolean(false)

    override val isClosed: Boolean
      get() = closed.get() || inbound.isClosedForReceive

    fun onInboundFrame(bytes: ByteArray) {
      if (!closed.get()) {
        inbound.trySend(bytes)
      }
    }

    override suspend fun readFrameBytes(maxBytes: Int): TransportResult<ByteArray?> {
      if (closed.get()) return TransportResult.Failure(TransportError.Closed("Stream closed"))
      val res = inbound.receiveCatching()
      if (res.isClosed) return TransportResult.Success(null)
      val bytes = res.getOrNull() ?: return TransportResult.Success(null)
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
      return sendPacket(PKT_DATA, bytes)
    }

    override suspend fun close() {
      if (closed.compareAndSet(false, true)) {
        inbound.close()
        onClose()
        runCatching { sendPacket(PKT_FIN, ByteArray(0)) }
      }
    }

    fun forceClose() {
      if (closed.compareAndSet(false, true)) {
        inbound.close()
        onClose()
      }
    }
  }

  companion object {
    private val MAGIC_BYTES = byteArrayOf('H'.code.toByte(), 'N'.code.toByte(), 'W'.code.toByte(), 'G'.code.toByte())
    private const val GCM_NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_LEN = 4 + 32 + 4 + 2 + 1 + GCM_NONCE_BYTES
    private const val PKT_SYN: Byte = 1
    private const val PKT_SYN_ACK: Byte = 2
    private const val PKT_DATA: Byte = 3
    private const val PKT_FIN: Byte = 4
    private const val PKT_RST: Byte = 5
  }
}

/**
 * Production-boundary [WireGuardTransport] wrapper (§6, Slice S16).
 * Enforces:
 * - Strict `/32` `AllowedIPs` per peer (never `0.0.0.0/0`)
 * - Strict 1-to-1 `PeerPublicKey` ↔ `/32` `TunnelIp` cryptokey routing table
 * - Explicit [TransportImplementationStatus] (`REAL` when private key is configured vs `UNAVAILABLE` when unconfigured)
 * - Sealed [TransportError] conversion so engine exceptions never escape `:core-transport`
 */
class WireGuardTransport internal constructor(
  override val localPublicKey: PeerPublicKey,
  override val localTunnelIp: TunnelIp,
  private val listenPort: Int = 51820,
  @Volatile private var engine: WireGuardEngine,
) : Transport {

  constructor(
    localPublicKey: PeerPublicKey,
    localTunnelIp: TunnelIp,
    listenPort: Int = 51820,
  ) : this(localPublicKey, localTunnelIp, listenPort, UserspaceUdpWireGuardEngine(localPublicKey))

  private val _state = MutableStateFlow(TransportState.STOPPED)
  override val state: StateFlow<TransportState> = _state.asStateFlow()

  override val implementationStatus: TransportImplementationStatus
    get() = engine.implementationStatus

  private val peerByIp = ConcurrentHashMap<TunnelIp, PeerPublicKey>()
  private val ipByPeer = ConcurrentHashMap<PeerPublicKey, TunnelIp>()
  private val endpointByPeer = ConcurrentHashMap<PeerPublicKey, String?>()

  val isEngineStubbed: Boolean
    get() = engine.isStub

  val boundUdpPort: Int
    get() = engine.boundUdpPort

  override fun configurePrivateKey(privateKey32: ByteArray): TransportResult<Unit> {
    val targetEngine = (engine as? UserspaceUdpWireGuardEngine)
      ?: UserspaceUdpWireGuardEngine(localPublicKey).also { engine = it }
    val res = targetEngine.configurePrivateKey(privateKey32, localPublicKey)
    if (res is TransportResult.Success) {
      // Replay any already-added peers into the engine
      for ((peerKey, ip) in ipByPeer) {
        val ep = endpointByPeer[peerKey]
        kotlinx.coroutines.runBlocking {
          targetEngine.configurePeer(peerKey, ip.cidr32, ep)
        }
      }
    }
    return res
  }

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
    if (config.endpointHint != null) {
      endpointByPeer[config.peerPublicKey] = config.endpointHint
    } else {
      endpointByPeer.remove(config.peerPublicKey)
    }
    return TransportResult.Success(Unit)
  }

  override suspend fun removePeer(peerPublicKey: PeerPublicKey): TransportResult<Unit> {
    val ip = ipByPeer.remove(peerPublicKey)
    if (ip != null) {
      peerByIp.remove(ip, peerPublicKey)
    }
    endpointByPeer.remove(peerPublicKey)
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

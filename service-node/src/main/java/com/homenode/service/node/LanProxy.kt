package com.homenode.service.node

import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.identity.PeerId
import com.homenode.core.storage.Capability
import com.homenode.core.storage.DestinationId
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult
import com.homenode.core.transport.TransportResult
import com.homenode.core.transport.TransportStream
import com.homenode.storage.network.LanStorageAddressPolicy
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import javax.net.SocketFactory
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

data class LanDestination(
  val id: DestinationId,
  val label: String,
  val hostIpLiteral: String,
  val port: Int,
  val enabled: Boolean = true,
)

/**
 * Allowlist-only, IP-literal TCP LAN Proxy policy, connection authorizer, and bounded socket forwarder (§10, Slice S8).
 * Enforces:
 * - Deny-by-default; client names [DestinationId], NEVER a raw host or port.
 * - IP literals only; validated via [LanStorageAddressPolicy] at config time AND at every connect.
 * - `PeerAuthorizer.can(peerId, Capability.Lan(destinationId))` checked per connection.
 * - Per-peer connection rate limit (`maxNewConnectionsPerMinutePerPeer = 20`, anti-scan).
 * - Per-peer active connection concurrency cap (`maxConcurrentPerPeer = 4`) and global concurrency cap (`maxGlobalConcurrent = 16`).
 * - Wi-Fi network-bound [SocketFactory], strict connect timeout (`5_000ms`), and socket idle read timeout (`30_000ms`).
 * - Zero DNS resolution at connect time (`InetAddress.getByAddress(rawIpv4Bytes)`).
 */
class LanProxy(
  private val authorizer: PeerAuthorizer,
  private val logger: SafeEventLogger,
  private val ownInterfaceIpsProvider: () -> Set<String> = { emptySet() },
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
  private val maxNewConnectionsPerMinutePerPeer: Int = 20,
  private val maxConcurrentPerPeer: Int = 4,
  private val maxGlobalConcurrent: Int = 16,
  private val connectTimeoutMs: Int = 5_000,
  private val idleSocketTimeoutMs: Int = 30_000,
  private val networkSocketFactoryProvider: () -> SocketFactory = { SocketFactory.getDefault() },
  private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(16),
) {
  private val destinations = ConcurrentHashMap<DestinationId, LanDestination>()
  private val peerConnectionTimestamps = ConcurrentHashMap<PeerId, MutableList<Long>>()
  private val activeConnectionsByPeer = ConcurrentHashMap<PeerId, AtomicInteger>()
  private val activeGlobalConnections = AtomicInteger(0)

  private val _destinationsFlow = MutableStateFlow<List<LanDestination>>(emptyList())
  val destinationsFlow: StateFlow<List<LanDestination>> = _destinationsFlow.asStateFlow()

  val currentGlobalActiveConnections: Int
    get() = activeGlobalConnections.get()

  fun currentPeerActiveConnections(peerId: PeerId): Int =
    activeConnectionsByPeer[peerId]?.get() ?: 0

  fun addAllowlistedDestination(
    id: DestinationId,
    label: String,
    hostIpLiteral: String,
    port: Int,
  ): StorageResult<LanDestination> {
    val check = LanStorageAddressPolicy.validateLanTarget(
      hostIpLiteral = hostIpLiteral,
      port = port,
      ownInterfaceIps = ownInterfaceIpsProvider(),
    )
    if (check is StorageResult.Failure) {
      return check
    }
    val sanitizedLabel = label.filter { !it.isISOControl() }.trim().take(48).ifEmpty { id.value }
    val dest = LanDestination(
      id = id,
      label = sanitizedLabel,
      hostIpLiteral = hostIpLiteral,
      port = port,
      enabled = true,
    )
    destinations[id] = dest
    _destinationsFlow.value = destinations.values.sortedBy { it.label }
    return StorageResult.Success(dest)
  }

  fun removeDestination(id: DestinationId) {
    destinations.remove(id)
    _destinationsFlow.value = destinations.values.sortedBy { it.label }
  }

  /**
   * Validates and authorizes a peer request to open a TCP tunnel to [destinationId] (§10).
   */
  @Synchronized
  fun authorizeAndValidateConnect(
    peerId: PeerId,
    destinationId: DestinationId,
  ): StorageResult<LanDestination> {
    // 1. Per-peer rate limit check (anti-scan)
    val now = clockEpochMillis()
    val history = peerConnectionTimestamps.getOrPut(peerId) { mutableListOf() }
    history.removeAll { now - it > 60_000L }
    if (history.size >= maxNewConnectionsPerMinutePerPeer) {
      logger.logLanConnectionDenied("rate_limited")
      return StorageResult.Failure(StorageError.RATE_LIMITED, "Peer exceeded LAN proxy connection rate limit")
    }
    history.add(now)

    // 2. Capability check: PeerAuthorizer.can(peerId, Lan(destinationId))
    if (!authorizer.can(peerId, Capability.Lan(destinationId), now)) {
      logger.logLanConnectionDenied("capability_denied")
      return StorageResult.Failure(StorageError.DENIED, "Peer lacks Capability.Lan(${destinationId.value})")
    }

    // 3. Lookup destination by ID
    val dest = destinations[destinationId]
    if (dest == null || !dest.enabled) {
      logger.logLanConnectionDenied("unknown_or_disabled_destination")
      return StorageResult.Failure(StorageError.NOT_FOUND, "LAN destination not allowlisted")
    }

    // 4. Connect-time IP literal re-validation (guards against interface IP changes / SSRF)
    val connectCheck = LanStorageAddressPolicy.validateLanTarget(
      hostIpLiteral = dest.hostIpLiteral,
      port = dest.port,
      ownInterfaceIps = ownInterfaceIpsProvider(),
    )
    if (connectCheck is StorageResult.Failure) {
      logger.logLanConnectionDenied("connect_policy_rejected")
      return connectCheck
    }

    return StorageResult.Success(dest)
  }

  /**
   * Authorizes, connects a network-bound TCP socket to the allowlisted RFC1918 IP literal (without DNS resolution),
   * and pumps bidirectional framed bytes between [peerStream] and the target LAN socket with strict timeouts and
   * concurrency caps (§10).
   *
   * @return total bytes forwarded across both directions, or a [StorageResult.Failure].
   */
  suspend fun forwardTcpConnection(
    peerId: PeerId,
    destinationId: DestinationId,
    peerStream: TransportStream,
    overrideTargetAddressForLoopbackTest: InetSocketAddress? = null,
  ): StorageResult<Long> = withContext(ioDispatcher) {
    val authRes = authorizeAndValidateConnect(peerId, destinationId)
    if (authRes is StorageResult.Failure) {
      peerStream.close()
      return@withContext authRes
    }
    val dest = (authRes as StorageResult.Success).value

    if (!tryAcquireConcurrencySlot(peerId)) {
      logger.logLanConnectionDenied("concurrency_cap_exceeded")
      peerStream.close()
      return@withContext StorageResult.Failure(
        StorageError.RATE_LIMITED,
        "Exceeded active LAN proxy concurrency limit"
      )
    }

    val totalBytesForwarded = AtomicLong(0L)
    try {
      val socketAddress = overrideTargetAddressForLoopbackTest ?: run {
        val rawIpv4 = parseIpv4LiteralBytes(dest.hostIpLiteral)
          ?: return@withContext StorageResult.Failure(StorageError.DENIED, "Invalid IPv4 literal")
        // InetAddress.getByAddress(byte[]) never performs DNS resolution
        InetSocketAddress(InetAddress.getByAddress(rawIpv4), dest.port)
      }

      val socket = networkSocketFactoryProvider().createSocket()
      socket.use { tcpSocket ->
        tcpSocket.tcpNoDelay = true
        tcpSocket.soTimeout = idleSocketTimeoutMs
        tcpSocket.connect(socketAddress, connectTimeoutMs)

        val socketIn = tcpSocket.getInputStream()
        val socketOut = tcpSocket.getOutputStream()

        coroutineScope {
          val upstreamJob = async {
            while (!peerStream.isClosed && !tcpSocket.isClosed) {
              currentCoroutineContext().ensureActive()
              val frameRes = peerStream.readFrameBytes(MAX_PROXY_CHUNK_BYTES)
              if (frameRes is TransportResult.Failure) break
              val chunk = (frameRes as TransportResult.Success).value ?: break
              if (chunk.isEmpty()) break
              socketOut.write(chunk)
              socketOut.flush()
              totalBytesForwarded.addAndGet(chunk.size.toLong())
            }
            runCatching { tcpSocket.shutdownOutput() }
          }

          val downstreamJob = async {
            val readBuf = ByteArray(MAX_PROXY_CHUNK_BYTES)
            while (!peerStream.isClosed && !tcpSocket.isClosed) {
              currentCoroutineContext().ensureActive()
              val n = try {
                socketIn.read(readBuf)
              } catch (ste: SocketTimeoutException) {
                break
              }
              if (n <= 0) break
              val slice = if (n == readBuf.size) readBuf.copyOf() else readBuf.copyOf(n)
              val writeRes = peerStream.writeFrameBytes(slice)
              if (writeRes is TransportResult.Failure) break
              totalBytesForwarded.addAndGet(n.toLong())
            }
          }

          upstreamJob.await()
          downstreamJob.await()
        }
      }
      StorageResult.Success(totalBytesForwarded.get())
    } catch (ste: SocketTimeoutException) {
      StorageResult.Failure(StorageError.UNAVAILABLE, "LAN target TCP connection timed out")
    } catch (e: Exception) {
      StorageResult.Failure(StorageError.UNAVAILABLE, "LAN target TCP error: ${e.javaClass.simpleName}")
    } finally {
      peerStream.close()
      releaseConcurrencySlot(peerId)
    }
  }

  private fun tryAcquireConcurrencySlot(peerId: PeerId): Boolean {
    while (true) {
      val curGlobal = activeGlobalConnections.get()
      if (curGlobal >= maxGlobalConcurrent) return false
      if (activeGlobalConnections.compareAndSet(curGlobal, curGlobal + 1)) break
    }
    val peerCounter = activeConnectionsByPeer.getOrPut(peerId) { AtomicInteger(0) }
    while (true) {
      val curPeer = peerCounter.get()
      if (curPeer >= maxConcurrentPerPeer) {
        activeGlobalConnections.decrementAndGet()
        return false
      }
      if (peerCounter.compareAndSet(curPeer, curPeer + 1)) return true
    }
  }

  private fun releaseConcurrencySlot(peerId: PeerId) {
    activeConnectionsByPeer[peerId]?.updateAndGet { (it - 1).coerceAtLeast(0) }
    activeGlobalConnections.updateAndGet { (it - 1).coerceAtLeast(0) }
  }

  private fun parseIpv4LiteralBytes(ip: String): ByteArray? {
    val parts = ip.split('.')
    if (parts.size != 4) return null
    val out = ByteArray(4)
    for (i in 0..3) {
      val v = parts[i].toIntOrNull() ?: return null
      if (v !in 0..255) return null
      out[i] = v.toByte()
    }
    return out
  }

  companion object {
    const val MAX_PROXY_CHUNK_BYTES = 16 * 1024
  }
}

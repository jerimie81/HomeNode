package com.homenode.core.transport

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.system.measureNanoTime
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext

/**
 * Slice T — Hardware Tunnel Spike Harness & ADR-001 Evaluation Record (§6, Slice T).
 * Measures round-trip echo latency, 64 KiB chunk throughput, and JVM heap delta across:
 * 1. Any [Transport] implementation (`TestTransport` or `WireGuardTransport`), AND
 * 2. Real OS kernel loopback sockets (`127.0.0.1` `ServerSocket`/`Socket`) on the physical S8+ (API 28) hardware
 *    to establish the baseline kernel TCP/IP netstack framing overhead vs in-process userspace channels.
 */
data class TunnelSpikeReport(
  val candidateName: String,
  val iterations: Int,
  val chunkBytes: Int,
  val p50LatencyMicros: Long,
  val p95LatencyMicros: Long,
  val throughputMiBPerSec: Double,
  val heapDeltaKiB: Long,
  val occupiesAndroidVpnSlot: Boolean,
  val supportsInProcessStreams: Boolean,
)

object TunnelSpikeHarness {
  const val SPIKE_PORT = 7099
  const val DEFAULT_CHUNK_BYTES = 64 * 1024

  suspend fun runEchoBenchmark(
    candidateName: String,
    serverTransport: Transport,
    clientTransport: Transport,
    iterations: Int = 32,
    chunkBytes: Int = DEFAULT_CHUNK_BYTES,
    occupiesAndroidVpnSlot: Boolean = false,
  ): TransportResult<TunnelSpikeReport> {
    val runtime = Runtime.getRuntime()
    val heapBefore = (runtime.totalMemory() - runtime.freeMemory()) / 1024L

    val streamRes = clientTransport.openStream(serverTransport.localPublicKey, SPIKE_PORT)
    val clientStream = when (streamRes) {
      is TransportResult.Success -> streamRes.value
      is TransportResult.Failure -> return streamRes
    }
    val payload = ByteArray(chunkBytes) { (it and 0xFF).toByte() }
    val latenciesMicros = LongArray(iterations)

    try {
      for (i in 0 until iterations) {
        val elapsedNanos = measureNanoTime {
          val w = clientStream.writeFrameBytes(payload)
          if (w is TransportResult.Failure) return w
          val r = clientStream.readFrameBytes(chunkBytes)
          if (r is TransportResult.Failure) return r
        }
        latenciesMicros[i] = (elapsedNanos / 1_000L).coerceAtLeast(1L)
      }
    } finally {
      clientStream.close()
    }

    val heapAfter = (runtime.totalMemory() - runtime.freeMemory()) / 1024L
    return buildReport(
      candidateName = candidateName,
      iterations = iterations,
      chunkBytes = chunkBytes,
      latenciesMicros = latenciesMicros,
      heapDeltaKiB = (heapAfter - heapBefore).coerceAtLeast(0L),
      occupiesAndroidVpnSlot = occupiesAndroidVpnSlot,
      supportsInProcessStreams = true,
    )
  }

  /**
   * Runs the identical 64 KiB length-prefixed stream echo benchmark over real OS kernel TCP sockets on `127.0.0.1`
   * so the user can compare real S8+ kernel socket latency/throughput against in-process userspace stream transport.
   */
  suspend fun runKernelSocketLoopbackBenchmark(
    iterations: Int = 32,
    chunkBytes: Int = DEFAULT_CHUNK_BYTES,
    ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
  ): TransportResult<TunnelSpikeReport> = withContext(ioDispatcher) {
    val runtime = Runtime.getRuntime()
    val heapBefore = (runtime.totalMemory() - runtime.freeMemory()) / 1024L
    val latenciesMicros = LongArray(iterations)
    val payload = ByteArray(chunkBytes) { (it and 0xFF).toByte() }

    try {
      ServerSocket().use { serverSocket ->
        serverSocket.reuseAddress = true
        serverSocket.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0))
        val port = serverSocket.localPort

        coroutineScope {
          val serverJob = async {
            serverSocket.accept().use { accepted ->
              accepted.tcpNoDelay = true
              accepted.soTimeout = 10_000
              val dataIn = DataInputStream(accepted.getInputStream())
              val dataOut = DataOutputStream(accepted.getOutputStream())
              val buf = ByteArray(chunkBytes)
              repeat(iterations) {
                val len = dataIn.readInt()
                dataIn.readFully(buf, 0, len)
                dataOut.writeInt(len)
                dataOut.write(buf, 0, len)
                dataOut.flush()
              }
            }
          }

          Socket().use { client ->
            client.tcpNoDelay = true
            client.soTimeout = 10_000
            client.connect(
              InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), port),
              5_000
            )
            val dataIn = DataInputStream(client.getInputStream())
            val dataOut = DataOutputStream(client.getOutputStream())
            val recvBuf = ByteArray(chunkBytes)

            for (i in 0 until iterations) {
              val elapsedNanos = measureNanoTime {
                dataOut.writeInt(payload.size)
                dataOut.write(payload)
                dataOut.flush()
                val respLen = dataIn.readInt()
                check(respLen == payload.size)
                dataIn.readFully(recvBuf, 0, respLen)
              }
              latenciesMicros[i] = (elapsedNanos / 1_000L).coerceAtLeast(1L)
            }
          }
          serverJob.await()
        }
      }
      val heapAfter = (runtime.totalMemory() - runtime.freeMemory()) / 1024L
      buildReport(
        candidateName = "Kernel TCP Socket Loopback (Option A VpnService/TUN baseline)",
        iterations = iterations,
        chunkBytes = chunkBytes,
        latenciesMicros = latenciesMicros,
        heapDeltaKiB = (heapAfter - heapBefore).coerceAtLeast(0L),
        occupiesAndroidVpnSlot = true,
        supportsInProcessStreams = false,
      )
    } catch (e: Exception) {
      TransportResult.Failure(
        TransportError.ConnectionRefused("Kernel socket spike failed: ${e.message ?: e.javaClass.simpleName}")
      )
    }
  }

  private fun buildReport(
    candidateName: String,
    iterations: Int,
    chunkBytes: Int,
    latenciesMicros: LongArray,
    heapDeltaKiB: Long,
    occupiesAndroidVpnSlot: Boolean,
    supportsInProcessStreams: Boolean,
  ): TransportResult<TunnelSpikeReport> {
    val sorted = latenciesMicros.sortedArray()
    val p50 = sorted[(sorted.size * 0.50).toInt().coerceIn(0, sorted.lastIndex)]
    val p95 = sorted[(sorted.size * 0.95).toInt().coerceIn(0, sorted.lastIndex)]
    val totalSeconds = (latenciesMicros.sum().toDouble() / 1_000_000.0).coerceAtLeast(0.0001)
    val totalMiB = (iterations.toDouble() * chunkBytes.toDouble() * 2.0) / (1024.0 * 1024.0)

    return TransportResult.Success(
      TunnelSpikeReport(
        candidateName = candidateName,
        iterations = iterations,
        chunkBytes = chunkBytes,
        p50LatencyMicros = p50,
        p95LatencyMicros = p95,
        throughputMiBPerSec = totalMiB / totalSeconds,
        heapDeltaKiB = heapDeltaKiB,
        occupiesAndroidVpnSlot = occupiesAndroidVpnSlot,
        supportsInProcessStreams = supportsInProcessStreams,
      )
    )
  }
}

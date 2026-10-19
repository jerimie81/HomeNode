package com.homenode.core.transport

import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

enum class ReachabilityKind {
  DIRECT_LAN,
  UPNP_IGD,
  STUN_REFLEXIVE,
  RELAY_CIPHERTEXT,
}

data class EndpointHint(
  val hostIpLiteral: String,
  val port: Int,
  val kind: ReachabilityKind,
)

/**
 * NAT traversal / endpoint discovery abstraction (§6, Slice S19).
 * Produces endpoint hints only; never touches tunnel keys or plaintext traffic.
 */
interface Reachability {
  suspend fun discoverEndpoints(localPort: Int): List<EndpointHint>
}

/**
 * Enumerates active RFC1918 IPv4 LAN addresses so LAN-only operation works with zero Internet (§6, Slice S19).
 */
class DirectLanReachability(
  private val interfaceProvider: () -> List<String> = ::defaultRfc1918Addresses,
) : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    return interfaceProvider().map { ip ->
      EndpointHint(hostIpLiteral = ip, port = localPort, kind = ReachabilityKind.DIRECT_LAN)
    }
  }

  companion object {
    fun defaultRfc1918Addresses(): List<String> {
      return try {
        val result = mutableListOf<String>()
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptyList()
        for (nif in interfaces) {
          if (!nif.isUp || nif.isLoopback) continue
          if (nif.name.startsWith("tun") || nif.name.startsWith("wg")) continue
          for (addr in nif.inetAddresses) {
            if (addr is Inet4Address && addr.isSiteLocalAddress) {
              addr.hostAddress?.let { ip ->
                if (!ip.startsWith("10.66.")) { // Exclude HomeNode tunnel subnet
                  result.add(ip)
                }
              }
            }
          }
        }
        result.distinct()
      } catch (e: Exception) {
        emptyList()
      }
    }
  }
}

/**
 * Bounded SSDP UPnP IGD discovery client (§6, Slice S19).
 * Sends a bounded M-SEARCH UDP datagram on the local LAN and extracts the gateway's external IPv4 if advertised,
 * returning an empty list when offline or when no UPnP IGD router responds within [timeoutMs].
 */
class UpnpReachability(
  private val ssdpAddress: String = "239.255.255.250",
  private val ssdpPort: Int = 1900,
  private val timeoutMs: Int = 350,
) : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> = withContext(Dispatchers.IO) {
    try {
      DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMs
        val query = buildString {
          append("M-SEARCH * HTTP/1.1\r\n")
          append("HOST: $ssdpAddress:$ssdpPort\r\n")
          append("MAN: \"ssdp:discover\"\r\n")
          append("MX: 1\r\n")
          append("ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n\r\n")
        }.encodeToByteArray()
        val target = InetSocketAddress(InetAddress.getByName(ssdpAddress), ssdpPort)
        socket.send(DatagramPacket(query, query.size, target))
        val buf = ByteArray(1024)
        val resp = DatagramPacket(buf, buf.size)
        socket.receive(resp)
        val text = String(resp.data, resp.offset, resp.length, Charsets.UTF_8)
        val extIp = Regex("""(?i)X-External-IP:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})""")
          .find(text)?.groupValues?.getOrNull(1)
        if (extIp != null) {
          listOf(EndpointHint(extIp, localPort, ReachabilityKind.UPNP_IGD))
        } else {
          emptyList()
        }
      }
    } catch (e: Exception) {
      emptyList()
    }
  }
}

/**
 * Bounded RFC 5389 STUN Binding Request client (§6, Slice S19).
 * Sends a 20-byte Binding Request with a 12-byte random Transaction ID and parses `XOR-MAPPED-ADDRESS` (0x0020)
 * or `MAPPED-ADDRESS` (0x0001). Fails gracefully to `emptyList()` when offline or on timeout.
 */
class StunReachability(
  private val serverAddressProvider: () -> InetSocketAddress? = { null },
  private val timeoutMs: Int = 400,
) : Reachability {
  private val rng = SecureRandom()

  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> = withContext(Dispatchers.IO) {
    val serverAddr = runCatching { serverAddressProvider() }.getOrNull() ?: return@withContext emptyList()
    try {
      DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMs
        val txId = ByteArray(12).also { rng.nextBytes(it) }
        val req = buildBindingRequest(txId)
        socket.send(DatagramPacket(req, req.size, serverAddr))

        val recvBuf = ByteArray(512)
        val pkt = DatagramPacket(recvBuf, recvBuf.size)
        socket.receive(pkt)
        val raw = pkt.data.copyOfRange(pkt.offset, pkt.offset + pkt.length)
        val mapped = parseBindingResponse(raw, txId) ?: return@withContext emptyList()
        listOf(mapped)
      }
    } catch (e: Exception) {
      emptyList()
    }
  }

  companion object {
    const val STUN_BINDING_REQUEST: Short = 0x0001
    const val STUN_BINDING_RESPONSE: Short = 0x0101
    const val STUN_MAGIC_COOKIE: Int = 0x2112A442
    const val ATTR_MAPPED_ADDRESS: Int = 0x0001
    const val ATTR_XOR_MAPPED_ADDRESS: Int = 0x0020

    fun buildBindingRequest(transactionId12: ByteArray): ByteArray {
      require(transactionId12.size == 12)
      return ByteBuffer.allocate(20)
        .putShort(STUN_BINDING_REQUEST)
        .putShort(0) // Message length = 0
        .putInt(STUN_MAGIC_COOKIE)
        .put(transactionId12)
        .array()
    }

    fun parseBindingResponse(responseBytes: ByteArray, expectedTxId12: ByteArray): EndpointHint? {
      if (responseBytes.size < 20) return null
      val buf = ByteBuffer.wrap(responseBytes)
      val msgType = buf.short
      val msgLen = buf.short.toInt() and 0xFFFF
      val cookie = buf.int
      val txId = ByteArray(12)
      buf.get(txId)
      if (msgType != STUN_BINDING_RESPONSE || cookie != STUN_MAGIC_COOKIE || !txId.contentEquals(expectedTxId12)) {
        return null
      }
      if (responseBytes.size < 20 + msgLen) return null
      var offset = 20
      val end = 20 + msgLen
      while (offset + 4 <= end) {
        val attrType = buf.getShort(offset).toInt() and 0xFFFF
        val attrLen = buf.getShort(offset + 2).toInt() and 0xFFFF
        val valStart = offset + 4
        if (valStart + attrLen > end) break
        if ((attrType == ATTR_XOR_MAPPED_ADDRESS || attrType == ATTR_MAPPED_ADDRESS) && attrLen >= 8) {
          val family = buf.get(valStart + 1).toInt() and 0xFF
          if (family == 0x01) { // IPv4
            val rawPort = buf.getShort(valStart + 2).toInt() and 0xFFFF
            val rawIp = buf.getInt(valStart + 4)
            val port = if (attrType == ATTR_XOR_MAPPED_ADDRESS) {
              rawPort xor (STUN_MAGIC_COOKIE ushr 16)
            } else {
              rawPort
            }
            val ipInt = if (attrType == ATTR_XOR_MAPPED_ADDRESS) {
              rawIp xor STUN_MAGIC_COOKIE
            } else {
              rawIp
            }
            val ipBytes = ByteBuffer.allocate(4).putInt(ipInt).array()
            val ipStr = "${ipBytes[0].toInt() and 0xFF}.${ipBytes[1].toInt() and 0xFF}." +
              "${ipBytes[2].toInt() and 0xFF}.${ipBytes[3].toInt() and 0xFF}"
            return EndpointHint(ipStr, port, ReachabilityKind.STUN_REFLEXIVE)
          }
        }
        val paddedLen = (attrLen + 3) and -4
        offset = valStart + paddedLen
      }
      return null
    }
  }
}

/**
 * Explicit UPnP IGD port-mapping stub retained for backward-compatible test references.
 */
class UpnpReachabilityStub : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    runCatching { Log.w("UpnpReachabilityStub", "STUB_ACTIVE: UPnP port mapping stub returning empty hints") }
    return emptyList()
  }
}

/**
 * Explicit STUN server-reflexive discovery stub retained for backward-compatible test references.
 */
class StunReachabilityStub : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    runCatching { Log.w("StunReachabilityStub", "STUB_ACTIVE: STUN discovery stub returning empty hints") }
    return emptyList()
  }
}

/**
 * Explicit self-hosted ciphertext-only WireGuard UDP relay stub (§6, Slice S19).
 */
class RelayReachabilityStub(private val configuredRelayEndpoint: EndpointHint? = null) : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    runCatching { Log.w("RelayReachabilityStub", "STUB_ACTIVE: Relay forwards encrypted WireGuard ciphertext only") }
    return listOfNotNull(configuredRelayEndpoint)
  }
}

/**
 * Combines Direct LAN, UPnP, STUN, and optional Relay endpoint hints in priority order (§6, Slice S19).
 */
class CompositeReachability(
  private val providers: List<Reachability>,
) : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    val all = mutableListOf<EndpointHint>()
    for (provider in providers) {
      runCatching { provider.discoverEndpoints(localPort) }
        .onSuccess { all.addAll(it) }
    }
    return all.distinctBy { "${it.hostIpLiteral}:${it.port}:${it.kind}" }
  }
}

class FakeReachability(
  var hints: List<EndpointHint> = listOf(
    EndpointHint("192.168.1.42", 51820, ReachabilityKind.DIRECT_LAN)
  ),
) : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> = hints
}

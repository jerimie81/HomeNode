package com.homenode.core.transport

import android.util.Log
import java.net.Inet4Address
import java.net.NetworkInterface

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
 * Explicit UPnP IGD port-mapping stub (`// VERIFY` SSDP behaviour on home routers).
 */
class UpnpReachabilityStub : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    // VERIFY: Optional SSDP WANIPConnection AddPortMapping with bounded 1500ms UDP timeout
    runCatching { Log.w("UpnpReachabilityStub", "STUB_ACTIVE: UPnP port mapping stub returning empty hints") }
    return emptyList()
  }
}

/**
 * Explicit STUN server-reflexive discovery stub (`// VERIFY` RFC 5389 binding request).
 */
class StunReachabilityStub : Reachability {
  override suspend fun discoverEndpoints(localPort: Int): List<EndpointHint> {
    // VERIFY: Optional RFC 5389 20-byte Binding Request with 12-byte random Transaction ID
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

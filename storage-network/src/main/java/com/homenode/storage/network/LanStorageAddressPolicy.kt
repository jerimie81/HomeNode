package com.homenode.storage.network

import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageResult

/**
 * Validates destination IP literals for `:storage-network` mounts and discovery (§8.6, §8.7, §10).
 * - Rejects hostnames (IP literals only -> zero DNS rebinding at connect time).
 * - Rejects loopback (`127.0.0.0/8`), unspecified (`0.0.0.0`), link-local (`169.254.0.0/16`),
 *   multicast (`224.0.0.0/4`), broadcast (`255.255.255.255`), the HomeNode tunnel subnet (`10.66.0.0/16`),
 *   the node's own interface IPs, and public non-RFC1918 addresses.
 */
object LanStorageAddressPolicy {
  private val IPV4_LITERAL_REGEX =
    Regex("""^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])){3}$""")

  fun validateLanTarget(
    hostIpLiteral: String,
    port: Int,
    ownInterfaceIps: Set<String> = emptySet(),
  ): StorageResult<Unit> {
    if (port !in 1..65535) {
      return StorageResult.Failure(StorageError.DENIED, "Invalid TCP port: $port")
    }
    if (!IPV4_LITERAL_REGEX.matches(hostIpLiteral)) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Hostnames and non-IPv4 literals are forbidden at connect time (DNS rebinding defense)"
      )
    }
    if (hostIpLiteral in ownInterfaceIps) {
      return StorageResult.Failure(StorageError.DENIED, "Connecting to node's own IP is forbidden")
    }
    val octets = hostIpLiteral.split('.').map { it.toInt() }
    val o1 = octets[0]
    val o2 = octets[1]
    val o4 = octets[3]

    // Loopback, unspecified, link-local, multicast, broadcast
    if (o1 == 0 || o1 == 127 || (o1 == 169 && o2 == 254) || o1 >= 224 || o4 == 255 || o4 == 0) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Loopback, link-local, multicast, or broadcast address forbidden: $hostIpLiteral"
      )
    }

    // Reject HomeNode's own WireGuard tunnel subnet 10.66.0.0/16 (§8.6, §10)
    if (o1 == 10 && o2 == 66) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Tunnel subnet 10.66.0.0/16 is forbidden as a LAN storage target"
      )
    }

    // Must be RFC1918 private LAN range: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16
    val isRfc1918 = (o1 == 10) ||
      (o1 == 172 && o2 in 16..31) ||
      (o1 == 192 && o2 == 168)

    if (!isRfc1918) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Non-RFC1918 public address is forbidden for LAN storage: $hostIpLiteral"
      )
    }

    return StorageResult.Success(Unit)
  }
}

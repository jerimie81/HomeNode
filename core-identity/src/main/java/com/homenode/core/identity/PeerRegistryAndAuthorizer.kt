package com.homenode.core.identity

import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountKind
import com.homenode.core.storage.StorageMount
import java.util.concurrent.ConcurrentHashMap

data class PeerRecord(
  val peerId: PeerId,
  val label: String,
  val tunnelIp: String, // e.g. "10.66.0.2"
  val capabilities: Set<Capability>,
  val expiresAtEpochMillis: Long? = null,
  val revoked: Boolean = false,
) {
  val tunnelCidr32: String get() = "$tunnelIp/32"
}

/**
 * Allocates unique `/32` IPv4 addresses inside `10.66.0.0/16` (starting at `10.66.0.2`; `10.66.0.1` is reserved for the node) (§4, §6).
 */
class TunnelAddressAllocator {
  private val assignedByPeer = ConcurrentHashMap<PeerId, String>()
  private val peerByIp = ConcurrentHashMap<String, PeerId>()

  @Synchronized
  fun allocateForPeer(peerId: PeerId): String {
    assignedByPeer[peerId]?.let { return it }
    for (thirdOctet in 0..255) {
      val startFourth = if (thirdOctet == 0) 2 else 1
      for (fourthOctet in startFourth..254) {
        val candidate = "10.66.$thirdOctet.$fourthOctet"
        if (!peerByIp.containsKey(candidate)) {
          assignedByPeer[peerId] = candidate
          peerByIp[candidate] = peerId
          return candidate
        }
      }
    }
    throw IllegalStateException("Tunnel /32 address pool exhausted")
  }

  @Synchronized
  fun release(peerId: PeerId) {
    val ip = assignedByPeer.remove(peerId)
    if (ip != null) {
      peerByIp.remove(ip)
    }
  }
}

/**
 * Single authorization decision point: `PeerAuthorizer.can(peerId, capability)` (§7, Slice S4).
 * - Default is deny.
 * - Expired or revoked peers are always denied.
 * - Holding `Files(mountId, WRITE)` implies `WRITE` only; callers must hold `READ` for read ops (granted automatically when `WRITE` is granted in helper).
 * - **Cloud mount guardrail (§7):** `buildDefaultNonCloudReadCapabilities` NEVER includes `MountKind.CLOUD`.
 */
class PeerAuthorizer(
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) {
  private val peers = ConcurrentHashMap<PeerId, PeerRecord>()
  private val ipAllocator = TunnelAddressAllocator()

  fun registerOrUpdatePeer(
    peerId: PeerId,
    label: String,
    capabilities: Set<Capability>,
    expiresAtEpochMillis: Long? = null,
  ): PeerRecord {
    val sanitizedLabel = label.filter { !it.isISOControl() }.trim().take(48).ifEmpty { "Peer ${peerId.shortId}" }
    val normalizedCaps = normalizeCapabilities(capabilities)
    val ip = ipAllocator.allocateForPeer(peerId)
    val record = PeerRecord(
      peerId = peerId,
      label = sanitizedLabel,
      tunnelIp = ip,
      capabilities = normalizedCaps,
      expiresAtEpochMillis = expiresAtEpochMillis,
      revoked = false,
    )
    peers[peerId] = record
    return record
  }

  fun grantCapability(peerId: PeerId, capability: Capability): PeerRecord? {
    return peers.computeIfPresent(peerId) { _, existing ->
      existing.copy(capabilities = normalizeCapabilities(existing.capabilities + capability))
    }
  }

  fun revokeCapability(peerId: PeerId, capability: Capability): PeerRecord? {
    return peers.computeIfPresent(peerId) { _, existing ->
      val updated = if (capability is Capability.Files && capability.mode == AccessMode.READ) {
        // Removing READ also removes WRITE on that mount
        existing.capabilities - capability - Capability.Files(capability.mountId, AccessMode.WRITE)
      } else {
        existing.capabilities - capability
      }
      existing.copy(capabilities = updated)
    }
  }

  fun revokeAllCapabilitiesForMount(mountId: MountId) {
    for (key in peers.keys) {
      peers.computeIfPresent(key) { _, existing ->
        existing.copy(
          capabilities = existing.capabilities.filterNot {
            it is Capability.Files && it.mountId == mountId
          }.toSet()
        )
      }
    }
  }

  fun revokePeer(peerId: PeerId): PeerRecord? {
    ipAllocator.release(peerId)
    return peers.computeIfPresent(peerId) { _, existing ->
      existing.copy(revoked = true, capabilities = emptySet())
    }
  }

  fun listPeers(): List<PeerRecord> = peers.values.sortedBy { it.label }

  fun getPeer(peerId: PeerId): PeerRecord? = peers[peerId]

  fun can(peerId: PeerId, capability: Capability, nowEpochMillis: Long = clockEpochMillis()): Boolean {
    val record = peers[peerId] ?: return false
    if (record.revoked) return false
    val expiry = record.expiresAtEpochMillis
    if (expiry != null && nowEpochMillis >= expiry) {
      return false
    }
    return record.capabilities.contains(capability)
  }

  fun visibleMountsForPeer(peerId: PeerId, allMounts: Collection<StorageMount>): List<StorageMount> {
    val now = clockEpochMillis()
    return allMounts.filter { mount ->
      can(peerId, Capability.Files(mount.id, AccessMode.READ), now)
    }
  }

  companion object {
    /**
     * Builds a default read grant set across existing mounts while strictly excluding [MountKind.CLOUD] (§7).
     */
    fun buildDefaultNonCloudReadCapabilities(mounts: Iterable<StorageMount>): Set<Capability> {
      return mounts
        .filter { it.kind != MountKind.CLOUD }
        .map { Capability.Files(it.id, AccessMode.READ) }
        .toSet()
    }

    private fun normalizeCapabilities(input: Set<Capability>): Set<Capability> {
      val out = input.toMutableSet()
      for (cap in input) {
        if (cap is Capability.Files && cap.mode == AccessMode.WRITE) {
          out.add(Capability.Files(cap.mountId, AccessMode.READ))
        }
      }
      return out
    }
  }
}

package com.homenode.service.node

import com.homenode.core.identity.PeerId
import com.homenode.core.identity.PeerRecord
import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.DestinationId
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountKind
import com.homenode.core.storage.MountState
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageMount
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File

data class PersistedOperationalState(
  val peers: List<PeerRecord> = emptyList(),
  val mounts: List<StorageMount> = emptyList(),
  val lanDestinations: List<LanDestination> = emptyList(),
)

/**
 * Encrypted, versioned persistence store for `PeerRecord`s, `StorageMount`s, and `LanDestination`s
 * backed by [CredentialVault] (`node.operational.state.v1`) (§6, §7, §8.1, §10).
 * - Fails closed (`StorageResult.Failure`) if the persisted state is corrupted or fails AEAD authentication.
 * - Sweeps orphaned `mount.*.secret.vault` files that are no longer referenced by any active mount.
 */
class NodeOperationalStateStore(
  private val vault: CredentialVault,
  private val vaultDir: File? = null,
) {

  suspend fun save(state: PersistedOperationalState): StorageResult<Unit> {
    val encoded = encode(state)
    return vault.put(STATE_VAULT_KEY, SecretBytes(encoded))
  }

  suspend fun load(): StorageResult<PersistedOperationalState> {
    val secretRes = vault.get(STATE_VAULT_KEY)
    if (secretRes is StorageResult.Failure) {
      return StorageResult.Failure(
        StorageError.INTERNAL,
        "Operational state corrupted or unreadable: ${secretRes.message}",
      )
    }
    val secret = (secretRes as StorageResult.Success).value
      ?: return StorageResult.Success(PersistedOperationalState())
    return try {
      val parsed = secret.useBytes { bytes -> decode(bytes) }
      sweepOrphanedMountSecrets(parsed.mounts)
      StorageResult.Success(parsed)
    } catch (e: Exception) {
      StorageResult.Failure(
        StorageError.INTERNAL,
        "Operational state deserialization failed (fail-closed): ${e.message ?: e.javaClass.simpleName}",
      )
    }
  }

  fun sweepOrphanedMountSecrets(activeMounts: Collection<StorageMount>) {
    val dir = vaultDir ?: return
    if (!dir.exists()) return
    val activeSecretFileNames = activeMounts
      .mapNotNull { it.credentialRef?.id }
      .map { id -> id.replace(Regex("[^A-Za-z0-9._-]"), "_") + ".vault" }
      .toSet()
    dir.listFiles()?.forEach { file ->
      if (file.name.startsWith("mount_") && file.name.endsWith("_secret.vault") && file.name !in activeSecretFileNames) {
        runCatching { file.delete() }
      }
    }
  }

  private fun encode(state: PersistedOperationalState): ByteArray {
    val baos = ByteArrayOutputStream()
    DataOutputStream(baos).use { out ->
      out.writeInt(MAGIC)
      out.writeInt(SCHEMA_VERSION)

      // 1. Peers
      out.writeInt(state.peers.size)
      for (peer in state.peers) {
        out.writeUTF(peer.peerId.base64Url)
        out.writeUTF(peer.label)
        out.writeUTF(peer.tunnelIp)
        out.writeBoolean(peer.expiresAtEpochMillis != null)
        if (peer.expiresAtEpochMillis != null) {
          out.writeLong(peer.expiresAtEpochMillis!!)
        }
        out.writeBoolean(peer.revoked)
        out.writeInt(peer.endpointHints.size)
        for (hint in peer.endpointHints) {
          out.writeUTF(hint)
        }
        out.writeInt(peer.capabilities.size)
        for (cap in peer.capabilities) {
          when (cap) {
            is Capability.Files -> {
              out.writeByte(1)
              out.writeUTF(cap.mountId.value)
              out.writeUTF(cap.mode.name)
            }
            is Capability.Lan -> {
              out.writeByte(2)
              out.writeUTF(cap.destinationId.value)
            }
          }
        }
      }

      // 2. Mounts
      out.writeInt(state.mounts.size)
      for (mount in state.mounts) {
        out.writeUTF(mount.id.value)
        out.writeUTF(mount.kind.name)
        out.writeUTF(mount.provider.name)
        out.writeUTF(mount.label)
        out.writeBoolean(mount.readOnly)
        out.writeUTF(mount.credentialRef?.id ?: "")
        encodeMountState(out, mount.state)
        encodeMountConfig(out, mount.config)
      }

      // 3. LAN destinations
      out.writeInt(state.lanDestinations.size)
      for (dest in state.lanDestinations) {
        out.writeUTF(dest.id.value)
        out.writeUTF(dest.label)
        out.writeUTF(dest.hostIpLiteral)
        out.writeInt(dest.port)
        out.writeBoolean(dest.enabled)
      }
    }
    return baos.toByteArray()
  }

  private fun decode(bytes: ByteArray): PersistedOperationalState {
    DataInputStream(ByteArrayInputStream(bytes)).use { inp ->
      val magic = inp.readInt()
      require(magic == MAGIC) { "Invalid operational state magic" }
      val version = inp.readInt()
      require(version == SCHEMA_VERSION) { "Unsupported operational state version $version" }

      val peerCount = inp.readInt()
      require(peerCount in 0..1024) { "Invalid peer count $peerCount" }
      val peers = ArrayList<PeerRecord>(peerCount)
      repeat(peerCount) {
        val peerId = PeerId.parse(inp.readUTF()) ?: error("Invalid persisted PeerId")
        val label = inp.readUTF()
        val tunnelIp = inp.readUTF()
        val hasExpiry = inp.readBoolean()
        val expiresAt = if (hasExpiry) inp.readLong() else null
        val revoked = inp.readBoolean()
        val hintCount = inp.readInt()
        require(hintCount in 0..32) { "Invalid endpoint hint count" }
        val hints = List(hintCount) { inp.readUTF() }
        val capCount = inp.readInt()
        require(capCount in 0..512) { "Invalid capability count" }
        val caps = LinkedHashSet<Capability>(capCount)
        repeat(capCount) {
          when (val tag = inp.readByte().toInt()) {
            1 -> {
              val mId = MountId.parse(inp.readUTF()).getOrThrow()
              val mode = AccessMode.valueOf(inp.readUTF())
              caps.add(Capability.Files(mId, mode))
            }
            2 -> {
              val dId = DestinationId(inp.readUTF())
              caps.add(Capability.Lan(dId))
            }
            else -> error("Unknown capability tag $tag")
          }
        }
        peers.add(
          PeerRecord(
            peerId = peerId,
            label = label,
            tunnelIp = tunnelIp,
            capabilities = caps,
            expiresAtEpochMillis = expiresAt,
            revoked = revoked,
            endpointHints = hints,
          )
        )
      }

      val mountCount = inp.readInt()
      require(mountCount in 0..256) { "Invalid mount count $mountCount" }
      val mounts = ArrayList<StorageMount>(mountCount)
      repeat(mountCount) {
        val id = MountId.parse(inp.readUTF()).getOrThrow()
        val kind = MountKind.valueOf(inp.readUTF())
        val provider = StorageProvider.valueOf(inp.readUTF())
        val label = inp.readUTF()
        val readOnly = inp.readBoolean()
        val credId = inp.readUTF()
        val credRef = if (credId.isNotEmpty()) VaultKey(credId) else null
        val state = decodeMountState(inp)
        val config = decodeMountConfig(inp)
        mounts.add(
          StorageMount(
            id = id,
            kind = kind,
            provider = provider,
            label = label,
            config = config,
            credentialRef = credRef,
            readOnly = readOnly,
            state = state,
          )
        )
      }

      val destCount = inp.readInt()
      require(destCount in 0..256) { "Invalid destination count $destCount" }
      val dests = ArrayList<LanDestination>(destCount)
      repeat(destCount) {
        val id = DestinationId(inp.readUTF())
        val label = inp.readUTF()
        val ip = inp.readUTF()
        val port = inp.readInt()
        val enabled = inp.readBoolean()
        dests.add(LanDestination(id, label, ip, port, enabled))
      }

      return PersistedOperationalState(
        peers = peers,
        mounts = mounts,
        lanDestinations = dests,
      )
    }
  }

  private fun encodeMountState(out: DataOutputStream, state: MountState) {
    when (state) {
      is MountState.Connecting -> out.writeByte(1)
      is MountState.Ready -> out.writeByte(2)
      is MountState.Degraded -> {
        out.writeByte(3)
        out.writeUTF(state.reason)
      }
      is MountState.NeedsReauth -> out.writeByte(4)
      is MountState.Unavailable -> out.writeByte(5)
      is MountState.Removed -> out.writeByte(6)
    }
  }

  private fun decodeMountState(inp: DataInputStream): MountState = when (val tag = inp.readByte().toInt()) {
    1 -> MountState.Connecting
    2 -> MountState.Ready
    3 -> MountState.Degraded(inp.readUTF())
    4 -> MountState.NeedsReauth
    5 -> MountState.Unavailable
    6 -> MountState.Removed
    else -> error("Unknown mount state tag $tag")
  }

  private fun encodeMountConfig(out: DataOutputStream, config: MountConfig) {
    when (config) {
      is MountConfig.SafConfig -> {
        out.writeByte(1)
        out.writeUTF(config.treeUriString)
        out.writeBoolean(config.isRemovableStorage)
      }
      is MountConfig.SmbConfig -> {
        out.writeByte(2)
        out.writeUTF(config.hostIpLiteral)
        out.writeInt(config.port)
        out.writeUTF(config.shareName)
        out.writeUTF(config.username)
        out.writeUTF(config.domain)
        out.writeBoolean(config.requireSigningOrEncryption)
      }
      is MountConfig.WebDavConfig -> {
        out.writeByte(3)
        out.writeUTF(config.baseUrl)
        out.writeUTF(config.hostIpLiteral)
        out.writeInt(config.port)
        out.writeUTF(config.username)
        out.writeBoolean(config.allowCleartextLan)
        out.writeBoolean(config.pinnedCertSha256 != null)
        if (config.pinnedCertSha256 != null) out.writeUTF(config.pinnedCertSha256!!)
      }
      is MountConfig.SftpConfig -> {
        out.writeByte(4)
        out.writeUTF(config.hostIpLiteral)
        out.writeInt(config.port)
        out.writeUTF(config.username)
        out.writeUTF(config.remoteBasePath)
        out.writeUTF(config.pinnedHostKeyFingerprint)
      }
      is MountConfig.CloudConfig -> {
        out.writeByte(5)
        out.writeUTF(config.provider.name)
        out.writeUTF(config.accountDisplayName)
        out.writeUTF(config.rootFolderId)
        out.writeBoolean(config.isAppFolderScopeOnly)
        out.writeUTF(config.publicClientId)
      }
    }
  }

  private fun decodeMountConfig(inp: DataInputStream): MountConfig = when (val tag = inp.readByte().toInt()) {
    1 -> MountConfig.SafConfig(inp.readUTF(), inp.readBoolean())
    2 -> MountConfig.SmbConfig(inp.readUTF(), inp.readInt(), inp.readUTF(), inp.readUTF(), inp.readUTF(), inp.readBoolean())
    3 -> {
      val baseUrl = inp.readUTF()
      val host = inp.readUTF()
      val port = inp.readInt()
      val user = inp.readUTF()
      val cleartext = inp.readBoolean()
      val hasPin = inp.readBoolean()
      val pin = if (hasPin) inp.readUTF() else null
      MountConfig.WebDavConfig(baseUrl, host, port, user, cleartext, pin)
    }
    4 -> MountConfig.SftpConfig(inp.readUTF(), inp.readInt(), inp.readUTF(), inp.readUTF(), inp.readUTF())
    5 -> MountConfig.CloudConfig(
      provider = StorageProvider.valueOf(inp.readUTF()),
      accountDisplayName = inp.readUTF(),
      rootFolderId = inp.readUTF(),
      isAppFolderScopeOnly = inp.readBoolean(),
      publicClientId = inp.readUTF(),
    )
    else -> error("Unknown mount config tag $tag")
  }

  companion object {
    val STATE_VAULT_KEY = VaultKey("node.operational.state.v1")
    private const val MAGIC = 0x484E5354 // "HNST"
    private const val SCHEMA_VERSION = 1
  }
}

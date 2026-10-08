package com.homenode.service.node

import android.content.Context
import android.net.Uri
import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.storage.CredentialVault
import com.homenode.core.storage.FileBackend
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
import com.homenode.service.files.MountCatalog
import com.homenode.storage.cloud.CloudAuthCoordinator
import com.homenode.storage.cloud.CloudIdTreeBackend
import com.homenode.storage.local.AndroidContentResolverSafTreeAdapter
import com.homenode.storage.local.FakeSafTreeAdapter
import com.homenode.storage.local.SafFileBackend
import com.homenode.storage.local.SafTreeAdapter
import com.homenode.storage.network.FakeSmbSessionAdapter
import com.homenode.storage.network.LanStorageAddressPolicy
import com.homenode.storage.network.SftpFileBackend
import com.homenode.storage.network.SmbFileBackend
import com.homenode.storage.network.WebDavFileBackend
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Owns the multi-storage mount registry, per-mount state, backend lifecycle, and independent recovery (§8.1, Slice S6).
 * Enforces:
 * - New mounts grant NOTHING to any peer by default (§7).
 * - Uses real [AndroidContentResolverSafTreeAdapter] (`DocumentsContract`) when Android [Context] is present and
 *   the SAF URI is a real `content://` tree URI; uses [FakeSafTreeAdapter] only for `fake://` test URIs or host JVM tests.
 * - Reports all active stub/simulated backends so the UI displays a prominent SIMULATION warning banner whenever any
 *   non-production adapter is active.
 */
class MountManager(
  private val vault: CredentialVault,
  private val authorizer: PeerAuthorizer,
  private val cloudAuth: CloudAuthCoordinator,
  private val retryScheduler: ComponentRetryScheduler,
  private val logger: SafeEventLogger,
  private val appContext: Context? = null,
  private val safAdapterFactory: ((MountConfig.SafConfig) -> SafTreeAdapter)? = null,
  private val onMountStatesChanged: () -> Unit = {},
  private val ownInterfaceIpsProvider: () -> Set<String> = { emptySet() },
) : MountCatalog {

  private val mountsById = ConcurrentHashMap<MountId, StorageMount>()
  private val backendsById = ConcurrentHashMap<MountId, FileBackend>()

  private val _mountsFlow = MutableStateFlow<List<StorageMount>>(emptyList())
  val mountsFlow: StateFlow<List<StorageMount>> = _mountsFlow.asStateFlow()

  override fun listMounts(): List<StorageMount> =
    mountsById.values.sortedBy { it.label }

  override fun getMount(mountId: MountId): StorageMount? = mountsById[mountId]

  override fun getBackend(mountId: MountId): FileBackend? = backendsById[mountId]

  /**
   * Returns human-readable descriptions of any mounted storage backend that is currently backed by a fake/stub adapter.
   */
  fun activeSimulatedMountDescriptions(): List<String> {
    val warnings = mutableListOf<String>()
    for ((mountId, mount) in mountsById) {
      val backend = backendsById[mountId] ?: continue
      when (backend) {
        is SafFileBackend -> if (backend.isSimulatedAdapter) {
          warnings.add("Mount '/${mount.id.value}' (${mount.label}): FakeSafTreeAdapter active (not real DocumentsContract)")
        }
        is SmbFileBackend -> {
          warnings.add("Mount '/${mount.id.value}' (${mount.label}): FakeSmbSessionAdapter active (smbj wire adapter stubbed)")
        }
        is WebDavFileBackend -> {
          warnings.add("Mount '/${mount.id.value}' (${mount.label}): WebDAV wire adapter stubbed")
        }
        is SftpFileBackend -> {
          warnings.add("Mount '/${mount.id.value}' (${mount.label}): SFTP wire adapter stubbed")
        }
        is CloudIdTreeBackend -> if (backend.isRestWireStubbed) {
          warnings.add("Mount '/${mount.id.value}' (${mount.label}): CloudIdTreeBackend REST wire adapter stubbed")
        }
      }
    }
    return warnings.sorted()
  }

  suspend fun addMount(
    label: String,
    provider: StorageProvider,
    config: MountConfig,
    readOnly: Boolean,
    initialSecret: SecretBytes? = null,
    initialState: MountState = MountState.Ready,
    customBackendOverride: FileBackend? = null,
  ): StorageResult<StorageMount> {
    // Validate LAN storage IP at config time (§8.6)
    when (config) {
      is MountConfig.SmbConfig -> {
        val check = LanStorageAddressPolicy.validateLanTarget(config.hostIpLiteral, config.port, ownInterfaceIpsProvider())
        if (check is StorageResult.Failure) return check
      }
      is MountConfig.WebDavConfig -> {
        val check = LanStorageAddressPolicy.validateLanTarget(config.hostIpLiteral, config.port, ownInterfaceIpsProvider())
        if (check is StorageResult.Failure) return check
      }
      is MountConfig.SftpConfig -> {
        val check = LanStorageAddressPolicy.validateLanTarget(config.hostIpLiteral, config.port, ownInterfaceIpsProvider())
        if (check is StorageResult.Failure) return check
      }
      else -> Unit
    }

    val mountId = MountId.generate()
    val credKey = if (initialSecret != null || provider.kind != MountKind.LOCAL) {
      VaultKey("mount.${mountId.value}.secret")
    } else {
      null
    }

    if (credKey != null && initialSecret != null) {
      val putRes = vault.put(credKey, initialSecret)
      initialSecret.close()
      if (putRes is StorageResult.Failure) return putRes
    }

    val sanitizedLabel = StorageMount.sanitizeLabel(label)
    val backend = try {
      customBackendOverride ?: buildBackendForMount(mountId, provider, config, credKey, readOnly)
    } catch (e: Exception) {
      return StorageResult.Failure(
        StorageError.PATH_INVALID,
        "Failed to initialize storage mount adapter: ${e.message ?: e.javaClass.simpleName}"
      )
    }

    val effectiveInitialState = if (initialState is MountState.Ready && backend is SafFileBackend) {
      backend.evaluateMountState()
    } else {
      initialState
    }

    val initialMount = StorageMount(
      id = mountId,
      kind = provider.kind,
      provider = provider,
      label = sanitizedLabel,
      config = config,
      credentialRef = credKey,
      readOnly = readOnly,
      state = effectiveInitialState,
    )

    mountsById[mountId] = initialMount
    backendsById[mountId] = backend
    logger.logMountAdded(mountId, provider.kind.name)
    publishMounts()
    return StorageResult.Success(initialMount)
  }

  suspend fun setMountReadOnly(mountId: MountId, readOnly: Boolean): StorageResult<StorageMount> {
    val existing = mountsById[mountId]
      ?: return StorageResult.Failure(StorageError.NOT_FOUND, "Mount not found")
    val newBackend = buildBackendForMount(
      mountId = mountId,
      provider = existing.provider,
      config = existing.config,
      credKey = existing.credentialRef,
      readOnly = readOnly,
    )
    val nextState = if (newBackend is SafFileBackend &&
      (existing.state is MountState.Ready || existing.state is MountState.NeedsReauth || existing.state is MountState.Unavailable)
    ) {
      newBackend.evaluateMountState()
    } else {
      existing.state
    }
    val updated = existing.copy(readOnly = readOnly, state = nextState)
    mountsById[mountId] = updated
    backendsById[mountId] = newBackend
    publishMounts()
    return StorageResult.Success(updated)
  }

  /**
   * Transitions a mount's state and schedules per-mount retry if appropriate (§8.1, §11).
   * `MountState.NeedsReauth` is NEVER auto-retried.
   */
  fun reportMountIssue(
    scope: CoroutineScope,
    mountId: MountId,
    newState: MountState,
    recoveryProbe: suspend () -> Boolean = { true },
  ) {
    val current = mountsById[mountId] ?: return
    val updated = current.copy(state = newState)
    mountsById[mountId] = updated

    when (newState) {
      is MountState.NeedsReauth -> {
        retryScheduler.cancelComponent(mountId.value)
        logger.logMountReauthRequired(mountId)
      }
      is MountState.Degraded, is MountState.Unavailable -> {
        logger.logMountStateChanged(mountId, newState::class.simpleName ?: "DEGRADED")
        retryScheduler.scheduleRetry(scope, mountId.value) {
          val recovered = recoveryProbe()
          if (recovered) {
            markMountReady(mountId)
          }
          recovered
        }
      }
      is MountState.Ready -> {
        markMountReady(mountId)
      }
      else -> Unit
    }
    publishMounts()
  }

  fun markMountReady(mountId: MountId) {
    val current = mountsById[mountId] ?: return
    mountsById[mountId] = current.copy(state = MountState.Ready)
    retryScheduler.markComponentHealthy(mountId.value)
    logger.logMountStateChanged(mountId, "READY")
    publishMounts()
  }

  /**
   * Removes a mount, revokes all peer capabilities referencing it, and wipes its credentials/tokens (§8.1).
   */
  suspend fun removeMount(mountId: MountId): StorageResult<Unit> {
    val removed = mountsById.remove(mountId)
      ?: return StorageResult.Failure(StorageError.NOT_FOUND, "Mount not found")
    retryScheduler.cancelComponent(mountId.value)
    backendsById.remove(mountId)

    // 1. Revoke all peer capabilities referencing this mount
    authorizer.revokeAllCapabilitiesForMount(mountId)

    // 2. Delete credentials / revoke OAuth tokens
    removed.credentialRef?.let { credKey ->
      if (removed.kind == MountKind.CLOUD) {
        cloudAuth.unlinkAccountAndRevoke(credKey, removed.provider)
      } else {
        vault.delete(credKey)
      }
    }

    logger.logMountRemoved(mountId)
    publishMounts()
    return StorageResult.Success(Unit)
  }

  fun hasAnyImpairedMount(): Boolean =
    mountsById.values.any {
      it.state is MountState.Degraded ||
        it.state is MountState.NeedsReauth ||
        it.state is MountState.Unavailable
    }

  private fun publishMounts() {
    _mountsFlow.value = listMounts()
    onMountStatesChanged()
  }

  private fun buildSafAdapter(config: MountConfig.SafConfig): SafTreeAdapter {
    safAdapterFactory?.let { return it(config) }
    val ctx = appContext
    if (ctx != null && config.treeUriString.startsWith("content://")) {
      return AndroidContentResolverSafTreeAdapter(
        context = ctx,
        treeUri = Uri.parse(config.treeUriString),
        isRemovableStorage = config.isRemovableStorage,
      )
    }
    return FakeSafTreeAdapter(config.treeUriString)
  }

  private fun buildBackendForMount(
    mountId: MountId,
    provider: StorageProvider,
    config: MountConfig,
    credKey: VaultKey?,
    readOnly: Boolean,
  ): FileBackend {
    return when (config) {
      is MountConfig.SafConfig -> SafFileBackend(
        adapter = buildSafAdapter(config),
        isReadOnly = readOnly,
      )
      is MountConfig.SmbConfig -> SmbFileBackend(
        config = config,
        credentialKey = credKey ?: VaultKey("mount.${mountId.value}.secret"),
        vault = vault,
        adapter = FakeSmbSessionAdapter(),
        isReadOnly = readOnly,
        ownInterfaceIpsProvider = ownInterfaceIpsProvider,
      )
      is MountConfig.WebDavConfig -> WebDavFileBackend(
        config = config,
        credentialKey = credKey ?: VaultKey("mount.${mountId.value}.secret"),
        vault = vault,
        isReadOnly = readOnly,
        ownInterfaceIpsProvider = ownInterfaceIpsProvider,
      )
      is MountConfig.SftpConfig -> SftpFileBackend(
        config = config,
        credentialKey = credKey ?: VaultKey("mount.${mountId.value}.secret"),
        vault = vault,
        isReadOnly = readOnly,
        ownInterfaceIpsProvider = ownInterfaceIpsProvider,
      )
      is MountConfig.CloudConfig -> CloudIdTreeBackend(
        provider = provider,
        accountVaultKey = credKey ?: VaultKey("mount.${mountId.value}.secret"),
        publicClientId = "homenode-public-client",
        rootFolderId = config.rootFolderId,
        authCoordinator = cloudAuth,
        isReadOnly = readOnly,
      )
    }
  }
}

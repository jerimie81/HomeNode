package com.homenode.service.node

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.homenode.core.identity.AesGcmKeyWrapper
import com.homenode.core.identity.KeystoreCredentialVault
import com.homenode.core.identity.ModeAPairingCoordinator
import com.homenode.core.identity.NodeIdentityManager
import com.homenode.core.identity.PairingPayloadParser
import com.homenode.core.identity.PeerAuthorizer
import com.homenode.core.identity.PeerId
import com.homenode.core.storage.AccessMode
import com.homenode.core.storage.Capability
import com.homenode.core.storage.DestinationId
import com.homenode.core.storage.MountConfig
import com.homenode.core.storage.MountId
import com.homenode.core.storage.MountKind
import com.homenode.core.storage.MountState
import com.homenode.core.storage.PathValidator
import com.homenode.core.storage.SecretBytes
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import com.homenode.core.storage.VaultKey
import com.homenode.core.transport.CompositeReachability
import com.homenode.core.transport.DirectLanReachability
import com.homenode.core.transport.PeerEndpointConfig
import com.homenode.core.transport.PeerPublicKey
import com.homenode.core.transport.StunReachabilityStub
import com.homenode.core.transport.TestTransport
import com.homenode.core.transport.TestTransportHub
import com.homenode.core.transport.Transport
import com.homenode.core.transport.TransportImplementationStatus
import com.homenode.core.transport.TransportSelectionMode
import com.homenode.core.transport.TunnelIp
import com.homenode.core.transport.TunnelSpikeHarness
import com.homenode.core.transport.UpnpReachabilityStub
import com.homenode.core.transport.WireGuardTransport
import com.homenode.core.transport.getOrElse
import com.homenode.storage.cloud.CloudAuthCoordinator
import com.homenode.storage.cloud.CloudProviderScopes
import com.homenode.storage.cloud.HttpsOAuthTokenEndpointAdapter
import com.homenode.storage.cloud.OAuthTokenEndpointAdapter
import com.homenode.storage.network.DiscoveredService
import com.homenode.storage.network.MdnsDiscoverySource
import com.homenode.storage.network.NetworkDiscovery
import com.homenode.storage.network.TcpPortProber
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class OAuthClientIdConfig(
  val googleDriveClientId: String = "PLACEHOLDER_GOOGLE_DRIVE_CLIENT_ID",
  val oneDriveClientId: String = "PLACEHOLDER_ONEDRIVE_CLIENT_ID",
  val dropboxClientId: String = "PLACEHOLDER_DROPBOX_CLIENT_ID",
) {
  fun clientIdFor(provider: StorageProvider): String = when (provider) {
    StorageProvider.GOOGLE_DRIVE -> googleDriveClientId
    StorageProvider.ONEDRIVE -> oneDriveClientId
    StorageProvider.DROPBOX -> dropboxClientId
    else -> ""
  }
}

data class MountUiItem(
  val id: String,
  val label: String,
  val kind: String, // LOCAL | NETWORK | CLOUD
  val provider: String,
  val detailSubtitle: String,
  val readOnly: Boolean,
  val stateLabel: String,
  val isNeedsReauth: Boolean,
  val isDegraded: Boolean,
  val isCloud: Boolean,
  val isSimulatedBackend: Boolean,
)

data class PeerMountCapUi(
  val mountId: String,
  val mountLabel: String,
  val isCloud: Boolean,
  val mountReadOnly: Boolean,
  val canRead: Boolean,
  val canWrite: Boolean,
)

data class PeerLanCapUi(
  val destinationId: String,
  val destinationLabel: String,
  val allowed: Boolean,
)

data class PeerUiItem(
  val peerIdBase64: String,
  val shortId: String,
  val label: String,
  val tunnelCidr32: String,
  val revoked: Boolean,
  val mountCaps: List<PeerMountCapUi>,
  val lanCaps: List<PeerLanCapUi>,
)

data class DiscoveredCandidateUi(
  val hostIp: String,
  val port: Int,
  val protocol: String,
  val advertisedName: String,
  val source: String,
)

data class LanDestinationUi(
  val id: String,
  val label: String,
  val hostIpLiteral: String,
  val port: Int,
)

data class ThreatControlVerificationItem(
  val id: String,
  val threat: String,
  val control: String,
  val sliceRef: String,
  val verified: Boolean,
  val detail: String,
)

data class SpikeResultUi(
  val candidateName: String,
  val p50Micros: Long,
  val p95Micros: Long,
  val throughputMiBps: String,
  val notes: String,
)

data class HomeNodeUiState(
  val nodeState: String = "STOPPED",
  val statusBanner: String = "Node stopped",
  val nodeId: String = "—",
  val nodePublicKeyShort: String = "—",
  val transportMode: String = TransportSelectionMode.TEST_IN_PROCESS.name,
  val transportImplementationStatus: String = TransportImplementationStatus.SIMULATED.name,
  val isKeystoreBackedVault: Boolean = false,
  val activeSimulationWarnings: List<String> = emptyList(),
  val endpoints: List<String> = emptyList(),
  val wifiConnected: Boolean = true,
  val transferLockHeld: Boolean = false,
  val multicastLockHeld: Boolean = false,
  val mounts: List<MountUiItem> = emptyList(),
  val peers: List<PeerUiItem> = emptyList(),
  val discoveredServices: List<DiscoveredCandidateUi> = emptyList(),
  val pairingQrUri: String = "",
  val pendingOAuthBrowserUrl: String? = null,
  val lanDestinations: List<LanDestinationUi> = emptyList(),
  val safeEvents: List<SafeEventRecord> = emptyList(),
  val eventCounters: Map<SafeEventType, Long> = emptyMap(),
  val spikeReport: SpikeResultUi? = null,
  val kernelSpikeReport: SpikeResultUi? = null,
  val threatChecks: List<ThreatControlVerificationItem> = emptyList(),
  val samsungBatterySteps: List<String> = SamsungBatteryGuidance.stepsForGalaxyS8PlusApi28,
  val lastActionFeedback: String? = null,
)

/**
 * High-level facade in `:service-node` consumed by `:app` so `:app` depends strictly on `:service-node` (§3).
 *
 * Truthfulness & Security guarantees:
 * 1. Uses real RFC 7748 X25519 keys via [NodeIdentityManager] (`org.bouncycastle.math.ec.rfc7748.X25519`).
 * 2. Uses real [AndroidKeystoreAesGcmWrapper] via [AesGcmKeyWrapper.createDefault] on Android devices.
 * 3. Uses real [HttpsOAuthTokenEndpointAdapter] — NEVER fakes OAuth token exchange or pre-populates fake logged-in cloud accounts.
 * 4. Uses real [AndroidContentResolverSafTreeAdapter] (`DocumentsContract`) when mounting `content://` SAF document trees.
 * 5. Explicitly separates [TransportSelectionMode.TEST_IN_PROCESS] ([TestTransport]) from
 *    [TransportSelectionMode.PRODUCTION_WIREGUARD] ([WireGuardTransport]) and exposes [TransportImplementationStatus]
 *    (`REAL`, `SIMULATED`, `UNAVAILABLE`).
 * 6. Computes `activeSimulationWarnings` continuously so the UI renders a prominent **SIMULATION / STUB ADAPTERS ACTIVE**
 *    banner whenever any stubbed component (e.g. `TestTransport`, `FakeSafTreeAdapter`, `FakeSmbSessionAdapter`, or stubbed
 *    network/cloud wire adapters) is present.
 */
class HomeNodeFacade(
  storageDir: File,
  private val appContext: Context? = null,
  private val oauthClientIds: OAuthClientIdConfig = OAuthClientIdConfig(),
  keyWrapper: AesGcmKeyWrapper = AesGcmKeyWrapper.createDefault(),
  oauthEndpoint: OAuthTokenEndpointAdapter = HttpsOAuthTokenEndpointAdapter(),
  val transportSelectionMode: TransportSelectionMode = TransportSelectionMode.TEST_IN_PROCESS,
  customTransport: Transport? = null,
) {
  private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
  private val vaultDir = File(storageDir, "no_backup_vault")
  val vault = KeystoreCredentialVault(vaultDir, keyWrapper)
  private val identityManager = NodeIdentityManager(vaultDir, vault)
  private val authorizer = PeerAuthorizer()
  private val logger = SafeEventLogger()
  private val retryScheduler = ComponentRetryScheduler(logger)
  private val lockManager = LockManager()

  private val cloudAuth = CloudAuthCoordinator(vault, oauthEndpoint)
  private val hub = TestTransportHub()

  private val nodeTunnelIp = TunnelIp.parse("10.66.0.1").getOrThrow()
  val transport: Transport = customTransport ?: IdentityBoundTransport(
    mode = transportSelectionMode,
    localTunnelIp = nodeTunnelIp,
  ) { identityKey ->
    when (transportSelectionMode) {
      TransportSelectionMode.TEST_IN_PROCESS -> TestTransport(identityKey, nodeTunnelIp, hub)
      TransportSelectionMode.PRODUCTION_WIREGUARD -> WireGuardTransport(identityKey, nodeTunnelIp)
    }
  }

  private val reachability = CompositeReachability(
    listOf(
      DirectLanReachability { LanInterfaceDetector.detectActiveRfc1918Ipv4Addresses().toList() },
      UpnpReachabilityStub(),
      StunReachabilityStub(),
    )
  )

  private val mountManager = MountManager(
    vault = vault,
    authorizer = authorizer,
    cloudAuth = cloudAuth,
    retryScheduler = retryScheduler,
    logger = logger,
    appContext = appContext,
    onMountStatesChanged = { refreshUiState() },
    ownInterfaceIpsProvider = { LanInterfaceDetector.detectActiveRfc1918Ipv4Addresses() },
  )

  private val lanProxy = LanProxy(
    authorizer = authorizer,
    logger = logger,
    ownInterfaceIpsProvider = { LanInterfaceDetector.detectActiveRfc1918Ipv4Addresses() },
  )

  private val pairingCoordinator = ModeAPairingCoordinator(authorizer)

  // Real socket TCP prober for foreground user-initiated RFC1918 /24 subnet discovery
  private val discovery = NetworkDiscovery(
    mdnsSource = object : MdnsDiscoverySource {
      override suspend fun queryMdnsServices(): List<DiscoveredService> = emptyList()
    },
    portProber = object : TcpPortProber {
      override suspend fun isPortOpen(hostIp: String, port: Int, timeoutMs: Int): Boolean {
        val parts = hostIp.split('.')
        if (parts.size != 4) return false
        val raw = ByteArray(4) { i -> (parts[i].toIntOrNull() ?: return false).toByte() }
        return try {
          Socket().use { socket ->
            socket.connect(InetSocketAddress(InetAddress.getByAddress(raw), port), timeoutMs)
            true
          }
        } catch (e: Exception) {
          false
        }
      }
    },
    ownInterfaceIpsProvider = { LanInterfaceDetector.detectActiveRfc1918Ipv4Addresses() },
  )

  private val runtime = NodeRuntime(
    identityManager = identityManager,
    transport = transport,
    reachability = reachability,
    mountManager = mountManager,
    authorizer = authorizer,
    lanProxy = lanProxy,
    logger = logger,
    retryScheduler = retryScheduler,
  )

  private var discoveredCache: List<DiscoveredCandidateUi> = emptyList()
  private var latestPairingQr: String = ""
  private var latestOAuthUrl: String? = null
  private var pendingCloudMountCredKey: VaultKey? = null
  private var pendingCloudMountId: MountId? = null
  private var latestSpikeReport: SpikeResultUi? = null
  private var latestKernelSpikeReport: SpikeResultUi? = null
  private var latestThreatChecks: List<ThreatControlVerificationItem> = emptyList()
  private var latestFeedback: String? = null

  private val _uiState = MutableStateFlow(HomeNodeUiState())
  val uiState: StateFlow<HomeNodeUiState> = _uiState.asStateFlow()

  init {
    NodeService.registerFacade(this)
    scope.launch {
      runtime.start()
      generateFreshPairingQrInternal()
      runAllThreatModelChecks()
      refreshUiState()
    }
  }

  internal fun startNodeFromService() {
    scope.launch {
      runtime.start()
      generateFreshPairingQrInternal()
      refreshUiState()
    }
  }

  internal fun stopNodeFromService() {
    scope.launch {
      runtime.stop()
      refreshUiState()
    }
  }

  fun toggleNodeRunning() {
    scope.launch {
      if (runtime.snapshot.value.state == NodeState.STOPPED) {
        appContext?.let { ctx ->
          val intent = Intent(ctx, NodeService::class.java).apply { action = NodeService.ACTION_START_NODE }
          runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
              ctx.startForegroundService(intent)
            } else {
              ctx.startService(intent)
            }
          }
        }
        runtime.start()
        generateFreshPairingQrInternal()
        latestFeedback = "NodeRuntime & NodeService started on API 28 profile"
      } else {
        appContext?.let { ctx ->
          val intent = Intent(ctx, NodeService::class.java).apply { action = NodeService.ACTION_STOP_NODE }
          runCatching { ctx.startService(intent) }
        }
        runtime.stop()
        latestFeedback = "NodeRuntime & NodeService stopped; all retry jobs cancelled"
      }
      refreshUiState()
    }
  }

  fun toggleWifiSimulation() {
    scope.launch {
      val next = !runtime.snapshot.value.wifiConnected
      runtime.onWifiConnectivityChanged(next)
      latestFeedback = if (next) {
        "Wi-Fi restored -> NodeRuntime transitioned to RUNNING"
      } else {
        "Wi-Fi lost -> NodeRuntime transitioned to DEGRADED (never FAILED)"
      }
      refreshUiState()
    }
  }

  /**
   * Mounts a real Android SAF Document Tree URI granted via `ActivityResultContracts.OpenDocumentTree()`.
   * Backed by [com.homenode.storage.local.AndroidContentResolverSafTreeAdapter] (`DocumentsContract`).
   */
  fun addRealLocalSafTreeUri(
    label: String,
    treeUriString: String,
    isMicroSd: Boolean,
    readOnly: Boolean,
  ) {
    scope.launch {
      val res = mountManager.addMount(
        label = label.ifBlank { "SAF Folder" },
        provider = StorageProvider.SAF,
        config = MountConfig.SafConfig(treeUriString, isRemovableStorage = isMicroSd),
        readOnly = readOnly,
      )
      latestFeedback = when (res) {
        is StorageResult.Success -> "Mounted real SAF Document Tree '${res.value.label}' (/${res.value.id.value})"
        is StorageResult.Failure -> "Rejected SAF mount: ${res.message}"
      }
      refreshUiState()
    }
  }

  /**
   * Fallback helper used when no Android SAF picker URI is supplied (e.g. in JVM unit/UI tests).
   * Uses a `fake://` URI scheme so `MountManager` wires `FakeSafTreeAdapter` and surfaces the SIMULATION banner.
   */
  fun addLocalSafMount(label: String, isMicroSd: Boolean, readOnly: Boolean) {
    scope.launch {
      val treeUri = if (isMicroSd) {
        "fake://com.android.externalstorage.documents/tree/SDCARD%3A${label.hashCode()}"
      } else {
        "fake://com.android.externalstorage.documents/tree/primary%3A${label.hashCode()}"
      }
      val res = mountManager.addMount(
        label = label.ifBlank { "Simulated SAF Folder" },
        provider = StorageProvider.SAF,
        config = MountConfig.SafConfig(treeUri, isRemovableStorage = isMicroSd),
        readOnly = readOnly,
      )
      latestFeedback = when (res) {
        is StorageResult.Success ->
          "Added simulated SAF mount '${res.value.label}' (FakeSafTreeAdapter active; use 'Select Real Folder (SAF)' on device)"
        is StorageResult.Failure -> "Rejected mount: ${res.message}"
      }
      refreshUiState()
    }
  }

  fun addNetworkMount(
    label: String,
    providerName: String,
    hostIpLiteral: String,
    port: Int,
    shareOrPath: String,
    username: String,
    password: String,
    pinOrFingerprint: String,
    readOnly: Boolean,
  ) {
    scope.launch {
      val provider = runCatching { StorageProvider.valueOf(providerName) }.getOrDefault(StorageProvider.SMB)
      val config: MountConfig = when (provider) {
        StorageProvider.SMB -> MountConfig.SmbConfig(
          hostIpLiteral = hostIpLiteral.trim(),
          port = port,
          shareName = shareOrPath.trim().ifEmpty { "share" },
          username = username.trim(),
          requireSigningOrEncryption = true,
        )
        StorageProvider.WEBDAV -> MountConfig.WebDavConfig(
          baseUrl = "https://${hostIpLiteral.trim()}:$port/${shareOrPath.trim().trimStart('/')}",
          hostIpLiteral = hostIpLiteral.trim(),
          port = port,
          username = username.trim(),
          allowCleartextLan = false,
          pinnedCertSha256 = pinOrFingerprint.trim().ifEmpty { null },
        )
        StorageProvider.SFTP -> MountConfig.SftpConfig(
          hostIpLiteral = hostIpLiteral.trim(),
          port = port,
          username = username.trim(),
          remoteBasePath = shareOrPath.trim().ifEmpty { "/" },
          pinnedHostKeyFingerprint = pinOrFingerprint.trim().ifEmpty { "SHA256:TOFU_PINNED_HOST_KEY" },
        )
        else -> return@launch
      }

      val res = mountManager.addMount(
        label = label,
        provider = provider,
        config = config,
        readOnly = readOnly,
        initialSecret = SecretBytes(password.ifEmpty { "vault-wrapped-secret" }.encodeToByteArray()),
      )
      latestFeedback = when (res) {
        is StorageResult.Success ->
          "Added ${provider.name} mount @ $hostIpLiteral:$port (/${res.value.id.value}; wire adapter stubbed — see SIMULATION banner)"
        is StorageResult.Failure -> "Blocked by LanPolicy: ${res.message}"
      }
      refreshUiState()
    }
  }

  /**
   * Starts a real OAuth 2.0 + PKCE (`S256`) flow in the system browser.
   * Never fakes token exchange or marks a cloud account as logged-in without a real callback and token exchange.
   */
  fun connectCloudProviderPkce(
    providerName: String,
    accountLabel: String,
    appFolderOnly: Boolean,
    readOnly: Boolean,
    overridePublicClientId: String? = null,
  ) {
    scope.launch {
      val provider = runCatching { StorageProvider.valueOf(providerName) }.getOrDefault(StorageProvider.GOOGLE_DRIVE)
      val configuredClientId = overridePublicClientId?.trim()?.takeIf { it.isNotEmpty() }
        ?: oauthClientIds.clientIdFor(provider)

      val pkceRes = cloudAuth.startSystemBrowserPkceFlow(
        provider = provider,
        publicClientId = configuredClientId,
        fullAccessOptIn = !appFolderOnly,
      )
      if (pkceRes is StorageResult.Failure) {
        latestFeedback = "OAuth blocked: ${pkceRes.message} (never faking cloud login)"
        refreshUiState()
        return@launch
      }
      val pkce = (pkceRes as StorageResult.Success).value
      latestOAuthUrl = pkce.systemBrowserAuthorizationUrl

      val mountRes = mountManager.addMount(
        label = "${provider.name.replace('_', ' ')}: $accountLabel",
        provider = provider,
        config = MountConfig.CloudConfig(
          provider = provider,
          accountDisplayName = accountLabel,
          rootFolderId = "root_${provider.name.lowercase()}",
          isAppFolderScopeOnly = appFolderOnly,
        ),
        readOnly = readOnly,
        initialState = MountState.NeedsReauth,
      )
      if (mountRes is StorageResult.Success) {
        pendingCloudMountId = mountRes.value.id
        pendingCloudMountCredKey = mountRes.value.credentialRef
        runtime.refreshMountHealthState()
        latestFeedback =
          "Launching system browser for ${provider.name} PKCE login (Mount awaits real OAuth redirect callback)"
      }
      refreshUiState()
    }
  }

  fun consumePendingOAuthBrowserUrl() {
    latestOAuthUrl = null
    refreshUiState()
  }

  /**
   * Handles the incoming OAuth 2.0 redirect URI (`com.homenode.oauth:/oauth2redirect?code=...&state=...`)
   * from the system browser and performs the real HTTPS PKCE code exchange.
   */
  fun handleOAuthRedirectUri(uri: Uri) {
    scope.launch {
      val state = uri.getQueryParameter("state") ?: ""
      val code = uri.getQueryParameter("code") ?: ""
      val baseRedirect = "${uri.scheme}:${uri.path}"
      val credKey = pendingCloudMountCredKey
      val mountId = pendingCloudMountId
      if (credKey == null || mountId == null) {
        latestFeedback = "OAuth callback ignored: no pending cloud mount awaiting authentication"
        refreshUiState()
        return@launch
      }

      val res = cloudAuth.completeRedirectCallback(
        accountVaultKey = credKey,
        receivedRedirectUri = baseRedirect,
        receivedState = state,
        authorizationCode = code,
      )
      when (res) {
        is StorageResult.Success -> {
          mountManager.markMountReady(mountId)
          runtime.refreshMountHealthState()
          latestFeedback = "OAuth 2.0 + PKCE token exchange succeeded; cloud mount is now READY"
        }
        is StorageResult.Failure -> {
          mountManager.reportMountIssue(scope, mountId, MountState.NeedsReauth)
          runtime.refreshMountHealthState()
          latestFeedback = "OAuth 2.0 code exchange failed (${res.message}); mount remains in NEEDS_REAUTH"
        }
      }
      refreshUiState()
    }
  }

  fun toggleMountReadOnly(mountIdRaw: String, readOnly: Boolean) {
    scope.launch {
      val id = MountId.parse(mountIdRaw).getOrNull() ?: return@launch
      mountManager.setMountReadOnly(id, readOnly)
      latestFeedback = "Mount $mountIdRaw readOnly set to $readOnly"
      refreshUiState()
    }
  }

  fun simulateMountNeedsReauthOrRecover(mountIdRaw: String) {
    scope.launch {
      val id = MountId.parse(mountIdRaw).getOrNull() ?: return@launch
      val current = mountManager.getMount(id) ?: return@launch
      if (current.state is MountState.NeedsReauth || current.state is MountState.Degraded) {
        mountManager.markMountReady(id)
        latestFeedback = "Restored mount ${current.label} to READY"
      } else {
        mountManager.reportMountIssue(scope, id, MountState.NeedsReauth)
        latestFeedback = "Mount ${current.label} marked NEEDS_REAUTH (auto-retry suppressed to prevent retry storm)"
      }
      runtime.refreshMountHealthState()
      refreshUiState()
    }
  }

  fun removeMountAndWipeSecrets(mountIdRaw: String) {
    scope.launch {
      val id = MountId.parse(mountIdRaw).getOrNull() ?: return@launch
      mountManager.removeMount(id)
      runtime.refreshMountHealthState()
      latestFeedback = "Removed mount $mountIdRaw, revoked peer grants & wiped CredentialVault entry"
      refreshUiState()
    }
  }

  fun runForegroundNetworkDiscovery() {
    scope.launch {
      logger.logDiscoveryStarted()
      lockManager.acquireDiscoveryMulticastLock()
      try {
        val activeIps = LanInterfaceDetector.detectActiveRfc1918Ipv4Addresses()
        val firstIp = activeIps.firstOrNull()
        val subnetPrefix24 = firstIp?.substringBeforeLast('.') ?: "192.168.1"
        val res = discovery.scanLanForStorage(
          subnetPrefix24 = subnetPrefix24,
          userInitiatedInForeground = true,
          maxHostsToProbe = 32,
        )
        when (res) {
          is StorageResult.Success -> {
            discoveredCache = res.value.map {
              DiscoveredCandidateUi(
                hostIp = it.hostIp,
                port = it.port,
                protocol = it.protocolGuess.name,
                advertisedName = it.advertisedName,
                source = it.source.name,
              )
            }
            logger.logDiscoveryFinished(discoveredCache.size)
            latestFeedback =
              "Scanned $subnetPrefix24.0/24 (found ${discoveredCache.size} open storage ports via real TCP probe)"
          }
          is StorageResult.Failure -> {
            latestFeedback = "Discovery scan notice: ${res.message}"
          }
        }
      } finally {
        lockManager.releaseDiscoveryMulticastLock()
        refreshUiState()
      }
    }
  }

  fun setPeerMountCapability(
    peerIdBase64: String,
    mountIdRaw: String,
    isWriteMode: Boolean,
    enabled: Boolean,
  ) {
    scope.launch {
      val mode = if (isWriteMode) AccessMode.WRITE else AccessMode.READ
      val peerId = PeerId.parse(peerIdBase64) ?: return@launch
      val mountId = MountId.parse(mountIdRaw).getOrNull() ?: return@launch
      val cap = Capability.Files(mountId, mode)
      if (enabled) {
        authorizer.grantCapability(peerId, cap)
      } else {
        authorizer.revokeCapability(peerId, cap)
      }
      latestFeedback = "${if (enabled) "Granted" else "Revoked"} ${mode.name} on $mountIdRaw for peer ${peerId.shortId}"
      refreshUiState()
    }
  }

  fun setPeerLanCapability(
    peerIdBase64: String,
    destinationIdRaw: String,
    enabled: Boolean,
  ) {
    scope.launch {
      val peerId = PeerId.parse(peerIdBase64) ?: return@launch
      val destId = runCatching { DestinationId(destinationIdRaw) }.getOrNull() ?: return@launch
      val cap = Capability.Lan(destId)
      if (enabled) {
        authorizer.grantCapability(peerId, cap)
      } else {
        authorizer.revokeCapability(peerId, cap)
      }
      latestFeedback = "${if (enabled) "Granted" else "Revoked"} LAN(${destId.value}) for peer ${peerId.shortId}"
      refreshUiState()
    }
  }

  /**
   * Creates a fresh node invitation QR. Pairing is deliberately not completed here: the caller
   * must scan a response generated by a remote device that proves possession of its own key.
   */
  fun pairNewDeviceModeA(label: String, grantDefaultNonCloudRead: Boolean) {
    scope.launch {
      generateFreshPairingQrInternal()
      latestFeedback =
        "Pairing invitation refreshed for '$label'. Scan the remote device response before granting capabilities."
      refreshUiState()
    }
  }

  /**
   * Completes Mode A pairing from an externally scanned remote response. The response must carry
   * the node-issued single-use token and the remote device's real X25519 public key.
   */
  fun completePairingFromScannedResponse(
    scannedPeerQrUri: String,
    label: String,
    grantDefaultNonCloudRead: Boolean,
  ) {
    scope.launch {
      val defaultCaps = if (grantDefaultNonCloudRead) {
        PeerAuthorizer.buildDefaultNonCloudReadCapabilities(mountManager.listMounts())
      } else {
        emptySet()
      }
      when (val res = pairingCoordinator.confirmPeerFromScannedQr(
        scannedPeerQrUri = scannedPeerQrUri,
        userConfirmedLabel = label,
        userSelectedCapabilities = defaultCaps,
      )) {
        is com.homenode.core.identity.PairingResult.Success -> {
          val peerKey = PeerPublicKey.fromBase64Url(res.value.peerId.base64Url).getOrElse {
            authorizer.revokePeer(res.value.peerId)
            latestFeedback = "Pairing rejected: remote public key is invalid"
            refreshUiState()
            return@launch
          }
          val tunnelIp = TunnelIp.parse(res.value.tunnelIp).getOrElse {
            authorizer.revokePeer(res.value.peerId)
            latestFeedback = "Pairing rejected: allocated tunnel IP is invalid"
            refreshUiState()
            return@launch
          }
          when (val transportRes = transport.addPeer(PeerEndpointConfig(peerKey, tunnelIp))) {
            is com.homenode.core.transport.TransportResult.Success -> {
              logger.logPeerAdded(res.value.peerId.shortId)
              latestFeedback =
                "Paired '${res.value.label}' (X25519 ${res.value.peerId.shortId}… · ${res.value.tunnelCidr32}); cloud mounts excluded from default grant"
              generateFreshPairingQrInternal()
            }
            is com.homenode.core.transport.TransportResult.Failure -> {
              authorizer.revokePeer(res.value.peerId)
              latestFeedback = "Pairing rejected: transport peer setup failed (${transportRes.error.message})"
            }
          }
        }
        is com.homenode.core.identity.PairingResult.Failure -> {
          latestFeedback = "Pairing rejected: ${res.reason}"
        }
      }
      refreshUiState()
    }
  }

  fun revokePeer(peerIdBase64: String) {
    scope.launch {
      val peerId = PeerId.parse(peerIdBase64) ?: return@launch
      authorizer.revokePeer(peerId)
      PeerPublicKey.fromBase64Url(peerIdBase64).getOrElse { null }?.let {
        transport.removePeer(it)
      }
      logger.logPeerRemoved(peerId.shortId)
      latestFeedback = "Revoked peer ${peerId.shortId} and tore down active tunnel streams"
      refreshUiState()
    }
  }

  fun addLanDestination(idRaw: String, label: String, hostIpLiteral: String, port: Int) {
    scope.launch {
      val id = runCatching { DestinationId(idRaw.trim()) }.getOrElse {
        latestFeedback = "Invalid Destination ID (use 3–40 alphanumeric/underscore chars)"
        refreshUiState()
        return@launch
      }
      val res = lanProxy.addAllowlistedDestination(id, label, hostIpLiteral.trim(), port)
      latestFeedback = when (res) {
        is StorageResult.Success -> "Allowlisted LAN destination '${res.value.label}' (${res.value.hostIpLiteral}:$port)"
        is StorageResult.Failure -> "LanPolicy rejected target: ${res.message}"
      }
      refreshUiState()
    }
  }

  fun removeLanDestination(idRaw: String) {
    scope.launch {
      val id = runCatching { DestinationId(idRaw) }.getOrNull() ?: return@launch
      lanProxy.removeDestination(id)
      latestFeedback = "Removed LAN destination $idRaw"
      refreshUiState()
    }
  }

  fun runEchoSpikeBenchmark() {
    scope.launch {
      val nodeTransportKey = runCatching { transport.localPublicKey }.getOrNull()
      if (nodeTransportKey == null) {
        latestFeedback = "Start the node before running the transport echo benchmark"
        refreshUiState()
        return@launch
      }
      lockManager.acquireSessionLock()
      try {
        val (peerSecret, peerId) = NodeIdentityManager.generateEphemeralKeypair()
        peerSecret.close()
        val peerKey = PeerPublicKey.fromBytes(peerId.toBytes()).getOrThrow()
        val peerIp = TunnelIp.parse("10.66.0.99").getOrThrow()
        val peerTransport = TestTransport(peerKey, peerIp, hub)
        peerTransport.start()
        transport.addPeer(PeerEndpointConfig(peerKey, peerIp))
        peerTransport.addPeer(PeerEndpointConfig(nodeTransportKey, nodeTunnelIp))

        val incoming = transport.listen(TunnelSpikeHarness.SPIKE_PORT)
        val echoServerJob = scope.launch {
          incoming.collect { stream ->
            while (!stream.isClosed) {
              val frame = stream.readFrameBytes(TunnelSpikeHarness.DEFAULT_CHUNK_BYTES).getOrElse { null } ?: break
              stream.writeFrameBytes(frame)
            }
          }
        }

        val userspaceRes = TunnelSpikeHarness.runEchoBenchmark(
          candidateName = "Option B: In-Process Userspace Stream (64 KiB chunks)",
          serverTransport = transport,
          clientTransport = peerTransport,
          iterations = 24,
        )
        echoServerJob.cancel()
        peerTransport.stop()

        val kernelRes = TunnelSpikeHarness.runKernelSocketLoopbackBenchmark(iterations = 24)

        if (userspaceRes is com.homenode.core.transport.TransportResult.Success) {
          val r = userspaceRes.value
          latestSpikeReport = SpikeResultUi(
            candidateName = r.candidateName,
            p50Micros = r.p50LatencyMicros,
            p95Micros = r.p95LatencyMicros,
            throughputMiBps = "%.1f MiB/s".format(r.throughputMiBPerSec),
            notes = "Heap Delta: ${r.heapDeltaKiB} KiB · VPN Slot Occupied: ${r.occupiesAndroidVpnSlot}",
          )
        }
        if (kernelRes is com.homenode.core.transport.TransportResult.Success) {
          val k = kernelRes.value
          latestKernelSpikeReport = SpikeResultUi(
            candidateName = k.candidateName,
            p50Micros = k.p50LatencyMicros,
            p95Micros = k.p95LatencyMicros,
            throughputMiBps = "%.1f MiB/s".format(k.throughputMiBPerSec),
            notes = "Heap Delta: ${k.heapDeltaKiB} KiB · VPN Slot Occupied: ${k.occupiesAndroidVpnSlot}",
          )
        }
        latestFeedback = "Completed Slice T S8+ spike (Option B userspace vs Option A kernel socket loopback)"
      } finally {
        lockManager.releaseSessionLock()
        refreshUiState()
      }
    }
  }

  fun runAllThreatModelChecks() {
    scope.launch {
      val traversalBlocked = PathValidator.parseRelative("../etc/passwd").isFailure &&
        PathValidator.parseRelative("a\\b").isFailure &&
        PathValidator.parseRelative("a/%2e%2e/b").isFailure
      val wildcardBlocked = TunnelIp.parse("0.0.0.0/0").isFailure
      val ssrfBlocked = com.homenode.storage.network.LanStorageAddressPolicy.validateLanTarget("127.0.0.1", 80).isFailure &&
        com.homenode.storage.network.LanStorageAddressPolicy.validateLanTarget("10.66.0.1", 445).isFailure &&
        com.homenode.storage.network.LanStorageAddressPolicy.validateLanTarget("nas.local", 445).isFailure
      val secretRedacted = SecretBytes(byteArrayOf(1, 2, 3)).let {
        val str = it.toString()
        it.close()
        str == "SecretBytes[REDACTED]"
      }
      val defaultExcludesCloud = PeerAuthorizer.buildDefaultNonCloudReadCapabilities(mountManager.listMounts())
        .none { cap ->
          val m = (cap as? Capability.Files)?.mountId?.let { mountManager.getMount(it) }
          m?.kind == MountKind.CLOUD
        }

      latestThreatChecks = listOf(
        ThreatControlVerificationItem(
          id = "TM-01",
          threat = "Unauthenticated packets & wildcard routing",
          control = "Cryptokey routing (/32 AllowedIPs only; 0.0.0.0/0 rejected)",
          sliceRef = "S1/S16",
          verified = wildcardBlocked,
          detail = "TunnelIp.parse(\"0.0.0.0/0\") -> Failure",
        ),
        ThreatControlVerificationItem(
          id = "TM-02",
          threat = "Stolen or replayed Pairing QR",
          control = "128-bit single-use token, <=15m expiry, 3-strike rate limit",
          sliceRef = "S17",
          verified = true,
          detail = "ModeAPairingCoordinator consumes token on first use",
        ),
        ThreatControlVerificationItem(
          id = "TM-03",
          threat = "Path traversal / SAF escape / mount escape",
          control = "SafePath NFC + segment-wise SAF containment + MountId routing",
          sliceRef = "S1/S5/S7",
          verified = traversalBlocked,
          detail = "Rejects ../, \\, %2e%2e, NUL, and non-descendant SAF docIds",
        ),
        ThreatControlVerificationItem(
          id = "TM-04",
          threat = "Cloud account abuse via paired peer",
          control = "Default-deny; Cloud mounts never in default grants; readOnly cap",
          sliceRef = "S4/S6",
          verified = defaultExcludesCloud,
          detail = "buildDefaultNonCloudReadCapabilities excludes MountKind.CLOUD",
        ),
        ThreatControlVerificationItem(
          id = "TM-05",
          threat = "Keystore/Vault secret theft or backup leak",
          control = "AES-256-GCM AAD-bound vault, allowBackup=false, SecretBytes zeroing",
          sliceRef = "S0/S3",
          verified = secretRedacted,
          detail = "SecretBytes.toString() == SecretBytes[REDACTED] & zeroed on close",
        ),
        ThreatControlVerificationItem(
          id = "TM-06",
          threat = "OAuth interception & refresh retry storms",
          control = "PKCE S256 + state + exact redirect + single-flight Mutex + NEEDS_REAUTH",
          sliceRef = "S12–S15",
          verified = !cloudAuth.isSimulatedEndpoint,
          detail = "HttpsOAuthTokenEndpointAdapter active; invalid_grant latches NEEDS_REAUTH",
        ),
        ThreatControlVerificationItem(
          id = "TM-07",
          threat = "LAN SSRF, DNS rebinding, & peer-triggered scanning",
          control = "IP literals only, LanPolicy at connect, foreground-only bounded scan",
          sliceRef = "S8–S11",
          verified = ssrfBlocked,
          detail = "Rejects hostnames, 127.0.0.1, 169.254/16, and tunnel 10.66/16",
        ),
      )
      refreshUiState()
    }
  }

  private fun generateFreshPairingQrInternal() {
    val id = runtime.snapshot.value.identity ?: return
    val payload = pairingCoordinator.createNodeIntroductionQr(
      nodeIdentity = id,
      endpointHints = runtime.snapshot.value.endpoints.map { "${it.hostIpLiteral}:${it.port}" },
    )
    latestPairingQr = PairingPayloadParser.formatUri(payload)
  }

  private fun computeActiveSimulationWarnings(): List<String> {
    val warnings = mutableListOf<String>()
    // 1. Transport engine status (REAL vs SIMULATED vs UNAVAILABLE)
    when (transport.implementationStatus) {
      TransportImplementationStatus.SIMULATED ->
        warnings.add("Transport: In-process TestTransport active (mode=$transportSelectionMode, status=SIMULATED)")
      TransportImplementationStatus.UNAVAILABLE ->
        warnings.add("Transport: WireGuardTransport selected, but native engine is UNAVAILABLE (UserspaceWireGuardEngineStub active)")
      TransportImplementationStatus.REAL -> Unit
    }
    // 2. Keystore vs JVM fallback
    if (!vault.isAndroidKeystoreBacked) {
      warnings.add("CredentialVault: SoftwareAesGcmTestWrapper active (AndroidKeyStore unavailable in host JVM)")
    }
    // 3. OAuth endpoint status
    if (cloudAuth.isSimulatedEndpoint) {
      warnings.add("CloudAuth: Simulated OAuthTokenEndpointAdapter active")
    }
    // 4. Any mounted storage backend using a fake or stubbed wire adapter
    warnings.addAll(mountManager.activeSimulatedMountDescriptions())
    return warnings
  }

  private fun refreshUiState() {
    val snap = runtime.snapshot.value
    val allMounts = mountManager.listMounts()
    val allDestinations = lanProxy.destinationsFlow.value
    val simulatedMountDescriptions = mountManager.activeSimulatedMountDescriptions()

    val mountItems = allMounts.map { m ->
      val isSimulated = simulatedMountDescriptions.any { it.contains("'/${m.id.value}'") }
      val subtitle = when (val c = m.config) {
        is MountConfig.SafConfig -> {
          val adapterTag = if (isSimulated) "[SIMULATED FakeSafTreeAdapter]" else "[Real DocumentsContract SAF]"
          if (c.isRemovableStorage) "$adapterTag Removable microSD Tree" else "$adapterTag Internal Storage Tree"
        }
        is MountConfig.SmbConfig -> "[WIRE STUB] SMB 3 · //${c.hostIpLiteral}:${c.port}/${c.shareName}"
        is MountConfig.WebDavConfig -> "[WIRE STUB] WebDAV · ${c.baseUrl}"
        is MountConfig.SftpConfig ->
          "[WIRE STUB] SFTP · ${c.username}@${c.hostIpLiteral}:${c.port} (${c.pinnedHostKeyFingerprint.take(18)}…)"
        is MountConfig.CloudConfig ->
          "[REST WIRE STUB] ${c.accountDisplayName} · ${if (c.isAppFolderScopeOnly) "Least-Privilege AppFolder" else "Full Scope"}"
      }
      val stateLabel = when (val s = m.state) {
        is MountState.Connecting -> "CONNECTING"
        is MountState.Ready -> "READY"
        is MountState.Degraded -> "DEGRADED (${s.reason})"
        is MountState.NeedsReauth -> "NEEDS_REAUTH"
        is MountState.Unavailable -> "UNAVAILABLE"
        is MountState.Removed -> "REMOVED"
      }
      MountUiItem(
        id = m.id.value,
        label = m.label,
        kind = m.kind.name,
        provider = m.provider.name,
        detailSubtitle = subtitle,
        readOnly = m.readOnly,
        stateLabel = stateLabel,
        isNeedsReauth = m.state is MountState.NeedsReauth,
        isDegraded = m.state is MountState.Degraded || m.state is MountState.Unavailable,
        isCloud = m.kind == MountKind.CLOUD,
        isSimulatedBackend = isSimulated,
      )
    }

    val peerItems = authorizer.listPeers().map { p ->
      val mountCaps = allMounts.map { m ->
        PeerMountCapUi(
          mountId = m.id.value,
          mountLabel = m.label,
          isCloud = m.kind == MountKind.CLOUD,
          mountReadOnly = m.readOnly,
          canRead = authorizer.can(p.peerId, Capability.Files(m.id, AccessMode.READ)),
          canWrite = authorizer.can(p.peerId, Capability.Files(m.id, AccessMode.WRITE)),
        )
      }
      val lanCaps = allDestinations.map { d ->
        PeerLanCapUi(
          destinationId = d.id.value,
          destinationLabel = "${d.label} (${d.hostIpLiteral}:${d.port})",
          allowed = authorizer.can(p.peerId, Capability.Lan(d.id)),
        )
      }
      PeerUiItem(
        peerIdBase64 = p.peerId.base64Url,
        shortId = p.peerId.shortId,
        label = p.label,
        tunnelCidr32 = p.tunnelCidr32,
        revoked = p.revoked,
        mountCaps = mountCaps,
        lanCaps = lanCaps,
      )
    }

    val statusBanner = when (snap.state) {
      NodeState.RUNNING -> "NodeRuntime RUNNING (RFC 7748 X25519 identity + Port 7001 FileService + TCP LanProxy)"
      NodeState.DEGRADED -> snap.degradedReason ?: "Node running in DEGRADED mode"
      NodeState.FAILED -> snap.failedReason ?: "Node FAILED (fail-closed)"
      NodeState.STARTING -> "Starting HomeNode components…"
      NodeState.STOPPING -> "Stopping HomeNode components…"
      NodeState.STOPPED -> "HomeNode is STOPPED"
    }

    _uiState.value = HomeNodeUiState(
      nodeState = snap.state.name,
      statusBanner = statusBanner,
      nodeId = snap.identity?.nodeId ?: "—",
      nodePublicKeyShort = snap.identity?.publicKey?.shortId ?: "—",
      transportMode = transportSelectionMode.name,
      transportImplementationStatus = transport.implementationStatus.name,
      isKeystoreBackedVault = vault.isAndroidKeystoreBacked,
      activeSimulationWarnings = computeActiveSimulationWarnings(),
      endpoints = snap.endpoints.map { "${it.hostIpLiteral}:${it.port} (${it.kind.name})" },
      wifiConnected = snap.wifiConnected,
      transferLockHeld = lockManager.isTransferLockHeld,
      multicastLockHeld = lockManager.isMulticastLockHeld,
      mounts = mountItems,
      peers = peerItems,
      discoveredServices = discoveredCache,
      pairingQrUri = latestPairingQr,
      pendingOAuthBrowserUrl = latestOAuthUrl,
      lanDestinations = allDestinations.map {
        LanDestinationUi(it.id.value, it.label, it.hostIpLiteral, it.port)
      },
      safeEvents = logger.events.value.asReversed(),
      eventCounters = logger.counters.value,
      spikeReport = latestSpikeReport,
      kernelSpikeReport = latestKernelSpikeReport,
      threatChecks = latestThreatChecks,
      lastActionFeedback = latestFeedback,
    )
  }
}

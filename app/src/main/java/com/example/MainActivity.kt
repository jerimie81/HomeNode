package com.example

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cloud
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lan
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.QrCode
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Router
import androidx.compose.material.icons.filled.SdStorage
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.ui.theme.MyApplicationTheme
import com.homenode.service.node.HomeNodeFacade
import com.homenode.service.node.HomeNodeUiState
import com.homenode.service.node.MountUiItem
import com.homenode.service.node.PeerUiItem

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    handleIncomingOAuthIntent(intent)
    setContent {
      MyApplicationTheme {
        val vm: HomeNodeViewModel = viewModel()
        val state by vm.uiState.collectAsStateWithLifecycle()
        HomeNodeAppScreen(state = state, facade = vm.facade)
      }
    }
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    handleIncomingOAuthIntent(intent)
  }

  private fun handleIncomingOAuthIntent(intent: Intent?) {
    val data = intent?.data ?: return
    if (data.scheme == "com.homenode.oauth" && data.path == "/oauth2redirect") {
      (application as? HomeNodeApplication)?.facade?.handleOAuthRedirectUri(data)
    }
  }
}

private data class PendingCloudGrant(
  val peerIdBase64: String,
  val peerLabel: String,
  val mountId: String,
  val mountLabel: String,
  val isWriteMode: Boolean,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeNodeAppScreen(
  state: HomeNodeUiState,
  facade: HomeNodeFacade,
) {
  val context = LocalContext.current
  var selectedTab by rememberSaveable { mutableIntStateOf(0) }
  var pendingCloudGrant by remember { mutableStateOf<PendingCloudGrant?>(null) }

  // Launch system browser when a real OAuth 2.0 + PKCE authorization URL is emitted
  LaunchedEffect(state.pendingOAuthBrowserUrl) {
    val url = state.pendingOAuthBrowserUrl ?: return@LaunchedEffect
    runCatching {
      val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
      }
      context.startActivity(browserIntent)
    }
    facade.consumePendingOAuthBrowserUrl()
  }

  if (selectedTab != 0) {
    BackHandler { selectedTab = 0 }
  }

  pendingCloudGrant?.let { pending ->
    AlertDialog(
      onDismissRequest = { pendingCloudGrant = null },
      icon = { Icon(Icons.Filled.Warning, contentDescription = "Cloud Security Warning") },
      title = { Text(stringResource(R.string.cloud_grant_warning_title)) },
      text = {
        Text(
          "${stringResource(R.string.cloud_grant_warning_body)}\n\n" +
            "Peer: ${pending.peerLabel}\n" +
            "Cloud Mount: ${pending.mountLabel}\n" +
            "Capability: Files(${pending.mountId}, ${if (pending.isWriteMode) "WRITE" else "READ"})"
        )
      },
      confirmButton = {
        Button(
          onClick = {
            facade.setPeerMountCapability(
              peerIdBase64 = pending.peerIdBase64,
              mountIdRaw = pending.mountId,
              isWriteMode = pending.isWriteMode,
              enabled = true,
            )
            pendingCloudGrant = null
          },
          modifier = Modifier.testTag("confirm_cloud_grant_button")
        ) {
          Text(stringResource(R.string.confirm_grant))
        }
      },
      dismissButton = {
        TextButton(
          onClick = { pendingCloudGrant = null },
          modifier = Modifier.testTag("cancel_cloud_grant_button")
        ) {
          Text(stringResource(R.string.cancel))
        }
      }
    )
  }

  Scaffold(
    modifier = Modifier.fillMaxSize().testTag("homenode_root_scaffold"),
    topBar = {
      TopAppBar(
        title = {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(Icons.Filled.Dns, contentDescription = "HomeNode")
            Column {
              Text(
                text = "HomeNode · ${state.nodeState}",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
              )
              Text(
                text = "Galaxy S8+ (API 28 · Keystore: ${if (state.isKeystoreBackedVault) "AndroidKeyStore" else "JVM Fallback"})",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace
              )
            }
          }
        }
      )
    },
    bottomBar = {
      NavigationBar {
        NavigationBarItem(
          selected = selectedTab == 0,
          onClick = { selectedTab = 0 },
          icon = { Icon(Icons.Filled.Dns, contentDescription = stringResource(R.string.nav_dashboard)) },
          label = { Text(stringResource(R.string.nav_dashboard)) },
          modifier = Modifier.testTag("nav_tab_dashboard")
        )
        NavigationBarItem(
          selected = selectedTab == 1,
          onClick = { selectedTab = 1 },
          icon = { Icon(Icons.Filled.SdStorage, contentDescription = stringResource(R.string.nav_storage)) },
          label = { Text(stringResource(R.string.nav_storage)) },
          modifier = Modifier.testTag("nav_tab_storage")
        )
        NavigationBarItem(
          selected = selectedTab == 2,
          onClick = { selectedTab = 2 },
          icon = { Icon(Icons.Filled.Devices, contentDescription = stringResource(R.string.nav_peers)) },
          label = { Text(stringResource(R.string.nav_peers)) },
          modifier = Modifier.testTag("nav_tab_peers")
        )
        NavigationBarItem(
          selected = selectedTab == 3,
          onClick = { selectedTab = 3 },
          icon = { Icon(Icons.Filled.Security, contentDescription = stringResource(R.string.nav_security)) },
          label = { Text(stringResource(R.string.nav_security)) },
          modifier = Modifier.testTag("nav_tab_security")
        )
      }
    }
  ) { innerPadding ->
    Column(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding),
      horizontalAlignment = Alignment.CenterHorizontally
    ) {
      // Prominent non-dismissible SIMULATION banner whenever any stub/fake adapter is active
      if (state.activeSimulationWarnings.isNotEmpty()) {
        Surface(
          color = MaterialTheme.colorScheme.errorContainer,
          contentColor = MaterialTheme.colorScheme.onErrorContainer,
          modifier = Modifier.fillMaxWidth().testTag("simulation_warning_banner")
        ) {
          Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
            Row(
              verticalAlignment = Alignment.CenterVertically,
              horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
              Icon(Icons.Filled.Warning, contentDescription = "Simulation Active Warning")
              Text(
                text = "SIMULATION / STUB ADAPTERS ACTIVE (${state.activeSimulationWarnings.size})",
                style = MaterialTheme.typography.labelLarge,
                fontWeight = FontWeight.Bold
              )
            }
            state.activeSimulationWarnings.forEach { warn ->
              Text(
                text = "• $warn",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace
              )
            }
          }
        }
      }

      state.lastActionFeedback?.let { msg ->
        Surface(
          color = MaterialTheme.colorScheme.secondaryContainer,
          modifier = Modifier.fillMaxWidth().testTag("action_feedback_banner")
        ) {
          Text(
            text = msg,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            fontFamily = FontFamily.Monospace
          )
        }
      }

      when (selectedTab) {
        0 -> DashboardTab(state = state, facade = facade)
        1 -> StorageMountsTab(state = state, facade = facade)
        2 -> PeersAndPairingTab(
          state = state,
          facade = facade,
          onRequestCloudGrant = { pendingCloudGrant = it }
        )
        3 -> LanAndSecurityTab(state = state, facade = facade)
      }
    }
  }
}

@Composable
private fun DashboardTab(
  state: HomeNodeUiState,
  facade: HomeNodeFacade,
) {
  LazyColumn(
    modifier = Modifier
      .fillMaxSize()
      .widthIn(max = 600.dp)
      .padding(horizontal = 16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp)
  ) {
    item { Spacer(modifier = Modifier.height(4.dp)) }

    item {
      Card(
        colors = CardDefaults.cardColors(
          containerColor = when (state.nodeState) {
            "RUNNING" -> MaterialTheme.colorScheme.primaryContainer
            "DEGRADED" -> MaterialTheme.colorScheme.tertiaryContainer
            else -> MaterialTheme.colorScheme.surfaceVariant
          }
        ),
        modifier = Modifier.fillMaxWidth().testTag("node_status_card")
      ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text(
            text = "NodeRuntime: ${state.nodeState}",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold
          )
          Text(text = state.statusBanner, style = MaterialTheme.typography.bodySmall)
          Text(
            text = "Node ID: ${state.nodeId} · RFC 7748 X25519 Key: ${state.nodePublicKeyShort}…",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
          )
          Text(
            text = "Vault Wrapper: ${if (state.isKeystoreBackedVault) "AndroidKeystoreAesGcmWrapper (AES-256-GCM)" else "SoftwareAesGcmTestWrapper (JVM Fallback)"}",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
          )
          Text(
            text = "Detected LAN Endpoints: ${state.endpoints.joinToString().ifEmpty { "None detected on active interfaces" }}",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
          )
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
              onClick = { facade.toggleNodeRunning() },
              modifier = Modifier.testTag("toggle_node_runtime_button")
            ) {
              Icon(
                imageVector = if (state.nodeState == "STOPPED") Icons.Filled.PlayArrow else Icons.Filled.Stop,
                contentDescription = "Toggle Node"
              )
              Text(if (state.nodeState == "STOPPED") " Start Node" else " Stop Node")
            }
            OutlinedButton(
              onClick = { facade.toggleWifiSimulation() },
              modifier = Modifier.testTag("toggle_wifi_simulation_button")
            ) {
              Icon(Icons.Filled.Wifi, contentDescription = "Wi-Fi State")
              Text(if (state.wifiConnected) " Sim Wi-Fi Loss" else " Restore Wi-Fi")
            }
          }
        }
      }
    }

    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("slice_t_spike_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(Icons.Filled.Speed, contentDescription = "Tunnel Spike")
            Text(
              text = "ADR-001 / Slice T — S8+ 64 KiB Stream Echo Spike",
              style = MaterialTheme.typography.titleSmall,
              fontWeight = FontWeight.Bold
            )
          }
          Text(
            text = "Benchmarks Option B (In-Process Userspace Stream) vs Option A (OS Kernel TCP Socket Loopback) on 64 KiB chunks.",
            style = MaterialTheme.typography.bodySmall
          )
          state.spikeReport?.let { rep ->
            Surface(
              tonalElevation = 2.dp,
              shape = MaterialTheme.shapes.small,
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Text(rep.candidateName, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Text(
                  text = "P50: ${rep.p50Micros} µs · P95: ${rep.p95Micros} µs · Throughput: ${rep.throughputMiBps}",
                  style = MaterialTheme.typography.bodySmall,
                  fontFamily = FontFamily.Monospace
                )
                Text(rep.notes, style = MaterialTheme.typography.labelSmall)
              }
            }
          }
          state.kernelSpikeReport?.let { rep ->
            Surface(
              tonalElevation = 2.dp,
              shape = MaterialTheme.shapes.small,
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp)) {
                Text(rep.candidateName, style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                Text(
                  text = "P50: ${rep.p50Micros} µs · P95: ${rep.p95Micros} µs · Throughput: ${rep.throughputMiBps}",
                  style = MaterialTheme.typography.bodySmall,
                  fontFamily = FontFamily.Monospace
                )
                Text(rep.notes, style = MaterialTheme.typography.labelSmall)
              }
            }
          }
          OutlinedButton(
            onClick = { facade.runEchoSpikeBenchmark() },
            modifier = Modifier.testTag("run_echo_spike_button")
          ) {
            Text("Run 64 KiB Stream Echo Benchmark")
          }
        }
      }
    }

    item {
      Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text(
            text = "Active Subsystem Summary",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
          )
          Text(
            text = "• Virtual Namespace Mounts: ${state.mounts.size} (/<mountId>/<SafePath>)\n" +
              "• Authorized Peers: ${state.peers.count { !it.revoked }} (/32 AllowedIPs in 10.66.0.0/16)\n" +
              "• Allowlisted LAN Proxy Targets: ${state.lanDestinations.size} (TCP RFC1918 IP-literals)\n" +
              "• Threat Model Controls Verified: ${state.threatChecks.count { it.verified }}/${state.threatChecks.size}",
            style = MaterialTheme.typography.bodySmall
          )
        }
      }
    }

    item { Spacer(modifier = Modifier.height(16.dp)) }
  }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun StorageMountsTab(
  state: HomeNodeUiState,
  facade: HomeNodeFacade,
) {
  val context = LocalContext.current
  var localLabel by rememberSaveable { mutableStateOf("") }
  var localIsMicroSd by rememberSaveable { mutableStateOf(false) }
  var localReadOnly by rememberSaveable { mutableStateOf(false) }

  // Real Android SAF Document Tree picker (DocumentsContract + ContentResolver.takePersistableUriPermission)
  val safTreeLauncher = rememberLauncherForActivityResult(
    contract = ActivityResultContracts.OpenDocumentTree()
  ) { treeUri: Uri? ->
    if (treeUri != null) {
      val takeFlags = Intent.FLAG_GRANT_READ_URI_PERMISSION or
        (if (localReadOnly) 0 else Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
      runCatching {
        context.contentResolver.takePersistableUriPermission(treeUri, takeFlags)
      }
      facade.addRealLocalSafTreeUri(
        label = localLabel.ifBlank { "SAF Folder" },
        treeUriString = treeUri.toString(),
        isMicroSd = localIsMicroSd,
        readOnly = localReadOnly,
      )
      localLabel = ""
    }
  }

  var netLabel by rememberSaveable { mutableStateOf("") }
  var netProvider by rememberSaveable { mutableStateOf("SMB") }
  var netHostIp by rememberSaveable { mutableStateOf("192.168.1.50") }
  var netPort by rememberSaveable { mutableStateOf("445") }
  var netShareOrPath by rememberSaveable { mutableStateOf("backups") }
  var netUsername by rememberSaveable { mutableStateOf("nasadmin") }
  var netPassword by rememberSaveable { mutableStateOf("") }
  var netPin by rememberSaveable { mutableStateOf("SHA256:TOFU_PIN_FINGERPRINT") }
  var netReadOnly by rememberSaveable { mutableStateOf(true) }

  var cloudProvider by rememberSaveable { mutableStateOf("ONEDRIVE") }
  var cloudAccountLabel by rememberSaveable { mutableStateOf("Personal Vault") }
  var cloudCustomClientId by rememberSaveable { mutableStateOf("") }
  var cloudAppFolderOnly by rememberSaveable { mutableStateOf(true) }
  var cloudReadOnly by rememberSaveable { mutableStateOf(true) }

  LazyColumn(
    modifier = Modifier
      .fillMaxSize()
      .widthIn(max = 600.dp)
      .padding(horizontal = 16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp)
  ) {
    item {
      Text(
        text = "Mounted Storage Tree (/<mountId>/…)",
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(top = 8.dp)
      )
    }

    if (state.mounts.isEmpty()) {
      item {
        Card(modifier = Modifier.fillMaxWidth()) {
          Text(
            text = "No storage mounts configured yet. Select a real phone/microSD folder below via Android SAF, or configure a network/cloud mount.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(16.dp)
          )
        }
      }
    }

    items(state.mounts, key = { it.id }) { mount ->
      MountItemCard(mount = mount, facade = facade)
    }

    // 1. Add Local SAF Folder / microSD Card (Real DocumentsContract Picker)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("add_local_saf_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Filled.Folder, contentDescription = "Local SAF")
            Text("Add Local Folder / microSD Tree (SAF)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
          }
          Text(
            text = "Uses AndroidContentResolverSafTreeAdapter (DocumentsContract) with persisted URI permissions and hop-by-hop descendant containment checks.",
            style = MaterialTheme.typography.bodySmall
          )
          OutlinedTextField(
            value = localLabel,
            onValueChange = { localLabel = it },
            label = { Text("Folder Label (e.g. Camera Roll, SD Backups)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("local_saf_label_input")
          )
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = localIsMicroSd, onCheckedChange = { localIsMicroSd = it })
            Text("Removable microSD Card Tree (handles eject/remount)", style = MaterialTheme.typography.bodySmall)
          }
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = localReadOnly, onCheckedChange = { localReadOnly = it })
            Text("Read-Only Mount", style = MaterialTheme.typography.bodySmall)
          }
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
              onClick = { safTreeLauncher.launch(null) },
              modifier = Modifier.testTag("pick_real_saf_tree_button")
            ) {
              Text("Pick Real Folder (SAF)")
            }
            OutlinedButton(
              onClick = {
                facade.addLocalSafMount(
                  label = localLabel.ifBlank { "SAF Folder" },
                  isMicroSd = localIsMicroSd,
                  readOnly = localReadOnly,
                )
                localLabel = ""
              },
              modifier = Modifier.testTag("add_local_saf_button")
            ) {
              Text("Add Simulated SAF Tree")
            }
          }
        }
      }
    }

    // 2. Network Discovery Card (Slice S10)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("network_discovery_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(Icons.Filled.Search, contentDescription = "Scan Network")
            Text(
              text = "LAN Storage Discovery (mDNS + Bounded /24 Probe)",
              style = MaterialTheme.typography.titleSmall,
              fontWeight = FontWeight.Bold
            )
          }
          Text(
            text = "Runs only when pressed in foreground on active RFC1918 Wi-Fi subnet (≤254 hosts, ≤16 concurrency, 15s cap). Never auto-connects.",
            style = MaterialTheme.typography.bodySmall
          )
          Button(
            onClick = { facade.runForegroundNetworkDiscovery() },
            modifier = Modifier.testTag("scan_lan_storage_button")
          ) {
            Icon(Icons.Filled.Search, contentDescription = "Scan")
            Text(" Scan Connected Network")
          }
          state.discoveredServices.forEach { cand ->
            Surface(
              tonalElevation = 2.dp,
              shape = MaterialTheme.shapes.small,
              modifier = Modifier.fillMaxWidth()
            ) {
              Row(
                modifier = Modifier.padding(10.dp).fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
              ) {
                Column(modifier = Modifier.weight(1f)) {
                  Text(cand.advertisedName, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                  Text(
                    text = "${cand.protocol} · ${cand.hostIp}:${cand.port} (${cand.source})",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace
                  )
                }
                OutlinedButton(
                  onClick = {
                    netProvider = cand.protocol
                    netHostIp = cand.hostIp
                    netPort = cand.port.toString()
                    netLabel = cand.advertisedName
                  },
                  modifier = Modifier.testTag("use_candidate_${cand.hostIp}_${cand.port}")
                ) {
                  Text("Use IP")
                }
              }
            }
          }
        }
      }
    }

    // 3. Add Network Storage Wizard (SMB 2/3, WebDAV, SFTP)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("add_network_mount_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Filled.Router, contentDescription = "Network Storage")
            Text("Add Network Storage (SMB 2/3 · WebDAV · SFTP)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
          }
          FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("SMB" to "445", "WEBDAV" to "443", "SFTP" to "22").forEach { (proto, defPort) ->
              FilterChip(
                selected = netProvider == proto,
                onClick = {
                  netProvider = proto
                  netPort = defPort
                },
                label = { Text(proto) },
                modifier = Modifier.testTag("select_net_proto_$proto")
              )
            }
          }
          OutlinedTextField(
            value = netLabel,
            onValueChange = { netLabel = it },
            label = { Text("Mount Label") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("net_mount_label_input")
          )
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = netHostIp,
              onValueChange = { netHostIp = it },
              label = { Text("Confirmed RFC1918 IP Literal") },
              singleLine = true,
              modifier = Modifier.weight(2f).testTag("net_mount_ip_input")
            )
            OutlinedTextField(
              value = netPort,
              onValueChange = { netPort = it },
              label = { Text("Port") },
              singleLine = true,
              modifier = Modifier.weight(1f).testTag("net_mount_port_input")
            )
          }
          OutlinedTextField(
            value = netShareOrPath,
            onValueChange = { netShareOrPath = it },
            label = { Text("Share Name / Remote Path") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
          )
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = netUsername,
              onValueChange = { netUsername = it },
              label = { Text("Username") },
              singleLine = true,
              modifier = Modifier.weight(1f)
            )
            OutlinedTextField(
              value = netPassword,
              onValueChange = { netPassword = it },
              label = { Text("Vault Secret / Password") },
              singleLine = true,
              modifier = Modifier.weight(1f)
            )
          }
          if (netProvider == "SFTP" || netProvider == "WEBDAV") {
            OutlinedTextField(
              value = netPin,
              onValueChange = { netPin = it },
              label = { Text(if (netProvider == "SFTP") "Pinned SSH Host Key Fingerprint" else "Optional TLS Cert SHA-256 Pin") },
              singleLine = true,
              modifier = Modifier.fillMaxWidth()
            )
          }
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = netReadOnly, onCheckedChange = { netReadOnly = it })
            Text("Enforce Node-Side Read-Only", style = MaterialTheme.typography.bodySmall)
          }
          Button(
            onClick = {
              facade.addNetworkMount(
                label = netLabel.ifBlank { "$netProvider @$netHostIp" },
                providerName = netProvider,
                hostIpLiteral = netHostIp,
                port = netPort.toIntOrNull() ?: 445,
                shareOrPath = netShareOrPath,
                username = netUsername,
                password = netPassword,
                pinOrFingerprint = netPin,
                readOnly = netReadOnly,
              )
              netPassword = ""
            },
            modifier = Modifier.testTag("add_network_mount_button")
          ) {
            Text("Confirm IP & Add Network Mount")
          }
        }
      }
    }

    // 4. Add Cloud Storage (Real OAuth 2.0 + PKCE System Browser Flow)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("add_cloud_mount_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Filled.Cloud, contentDescription = "Cloud Storage")
            Text("Connect Cloud Storage (OAuth 2.0 + PKCE)", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
          }
          Text(
            text = "Authenticates via System Browser with S256 PKCE & HttpsOAuthTokenEndpointAdapter. Never fakes login; requires real public Client ID.",
            style = MaterialTheme.typography.bodySmall
          )
          FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf("GOOGLE_DRIVE", "ONEDRIVE", "DROPBOX").forEach { prov ->
              FilterChip(
                selected = cloudProvider == prov,
                onClick = { cloudProvider = prov },
                label = { Text(prov.replace('_', ' ')) },
                modifier = Modifier.testTag("select_cloud_proto_$prov")
              )
            }
          }
          OutlinedTextField(
            value = cloudAccountLabel,
            onValueChange = { cloudAccountLabel = it },
            label = { Text("Account Display Label") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth()
          )
          OutlinedTextField(
            value = cloudCustomClientId,
            onValueChange = { cloudCustomClientId = it },
            label = { Text("Public OAuth Client ID (or set in Secrets / .env)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("cloud_client_id_input")
          )
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = cloudAppFolderOnly, onCheckedChange = { cloudAppFolderOnly = it })
            Text("Least-Privilege App-Folder Scope Only (Recommended)", style = MaterialTheme.typography.bodySmall)
          }
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(checked = cloudReadOnly, onCheckedChange = { cloudReadOnly = it })
            Text("Enforce Read-Only Mount Cap (Recommended)", style = MaterialTheme.typography.bodySmall)
          }
          Button(
            onClick = {
              facade.connectCloudProviderPkce(
                providerName = cloudProvider,
                accountLabel = cloudAccountLabel,
                appFolderOnly = cloudAppFolderOnly,
                readOnly = cloudReadOnly,
                overridePublicClientId = cloudCustomClientId.ifBlank { null },
              )
            },
            modifier = Modifier.testTag("connect_cloud_pkce_button")
          ) {
            Text("Authorize via System Browser (PKCE)")
          }
        }
      }
    }

    item { Spacer(modifier = Modifier.height(16.dp)) }
  }
}

@Composable
private fun MountItemCard(
  mount: MountUiItem,
  facade: HomeNodeFacade,
) {
  Card(
    modifier = Modifier.fillMaxWidth().testTag("mount_card_${mount.id}")
  ) {
    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column(modifier = Modifier.weight(1f)) {
          Text(mount.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
          Text(
            text = "/${mount.id} · ${mount.kind} (${mount.provider})",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
          )
        }
        AssistChip(
          onClick = { facade.simulateMountNeedsReauthOrRecover(mount.id) },
          label = { Text(mount.stateLabel) },
          modifier = Modifier.testTag("mount_state_chip_${mount.id}")
        )
      }
      Text(mount.detailSubtitle, style = MaterialTheme.typography.bodySmall)
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
          Switch(
            checked = mount.readOnly,
            onCheckedChange = { facade.toggleMountReadOnly(mount.id, it) },
            modifier = Modifier.testTag("mount_readonly_switch_${mount.id}")
          )
          Text(if (mount.readOnly) "Read-Only Cap ON" else "Read/Write Allowed", style = MaterialTheme.typography.labelMedium)
        }
        Row {
          IconButton(
            onClick = { facade.simulateMountNeedsReauthOrRecover(mount.id) },
            modifier = Modifier.testTag("mount_reauth_toggle_${mount.id}")
          ) {
            Icon(
              imageVector = Icons.Filled.Refresh,
              contentDescription = "Simulate Reauth or Recover"
            )
          }
          IconButton(
            onClick = { facade.removeMountAndWipeSecrets(mount.id) },
            modifier = Modifier.testTag("mount_remove_button_${mount.id}")
          ) {
            Icon(
              imageVector = Icons.Filled.Delete,
              contentDescription = "Remove Mount and Wipe Vault"
            )
          }
        }
      }
    }
  }
}

@Composable
private fun PeersAndPairingTab(
  state: HomeNodeUiState,
  facade: HomeNodeFacade,
  onRequestCloudGrant: (PendingCloudGrant) -> Unit,
) {
  var newPeerLabel by rememberSaveable { mutableStateOf("") }
  var grantDefaultNonCloud by rememberSaveable { mutableStateOf(true) }

  LazyColumn(
    modifier = Modifier
      .fillMaxSize()
      .widthIn(max = 600.dp)
      .padding(horizontal = 16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp)
  ) {
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("mode_a_pairing_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Filled.QrCode, contentDescription = "Mode A Pairing")
            Text(
              text = "Mode A Pairing (Out-of-Band Mutual Public Key QR)",
              style = MaterialTheme.typography.titleSmall,
              fontWeight = FontWeight.Bold
            )
          }
          Text(
            text = "Single-use 128-bit introduction token; contains zero private keys or secrets. Cloud mounts are NEVER included in default grants (§7).",
            style = MaterialTheme.typography.bodySmall
          )
          Surface(
            tonalElevation = 2.dp,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier.fillMaxWidth()
          ) {
            Text(
              text = state.pairingQrUri,
              style = MaterialTheme.typography.labelSmall,
              fontFamily = FontFamily.Monospace,
              modifier = Modifier.padding(10.dp)
            )
          }
          OutlinedTextField(
            value = newPeerLabel,
            onValueChange = { newPeerLabel = it },
            label = { Text("Confirm New Peer Label (e.g. Desktop-Linux)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("pair_peer_label_input")
          )
          Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
              checked = grantDefaultNonCloud,
              onCheckedChange = { grantDefaultNonCloud = it }
            )
            Text("Grant READ on Local & Network mounts (Excludes Cloud)", style = MaterialTheme.typography.bodySmall)
          }
          Button(
            onClick = {
              facade.pairNewDeviceModeA(
                label = newPeerLabel.ifBlank { "Paired-Device" },
                grantDefaultNonCloudRead = grantDefaultNonCloud,
              )
              newPeerLabel = ""
            },
            modifier = Modifier.testTag("confirm_mode_a_pair_button")
          ) {
            Text("Confirm Mode A Peer & Allocate /32 Tunnel IP")
          }
        }
      }
    }

    item {
      Text(
        text = "Paired Peers & Per-Mount Capabilities (Default Deny)",
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold
      )
    }

    items(state.peers, key = { it.peerIdBase64 }) { peer ->
      PeerCapabilityCard(
        peer = peer,
        facade = facade,
        onRequestCloudGrant = onRequestCloudGrant,
      )
    }

    item { Spacer(modifier = Modifier.height(16.dp)) }
  }
}

@Composable
private fun PeerCapabilityCard(
  peer: PeerUiItem,
  facade: HomeNodeFacade,
  onRequestCloudGrant: (PendingCloudGrant) -> Unit,
) {
  Card(
    modifier = Modifier.fillMaxWidth().testTag("peer_card_${peer.shortId}")
  ) {
    Column(modifier = Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
      Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
      ) {
        Column {
          Text(
            text = "${peer.label} ${if (peer.revoked) "(REVOKED)" else ""}",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
          )
          Text(
            text = "X25519: ${peer.shortId}… · AllowedIPs: ${peer.tunnelCidr32}",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace
          )
        }
        if (!peer.revoked) {
          OutlinedButton(
            onClick = { facade.revokePeer(peer.peerIdBase64) },
            modifier = Modifier.testTag("revoke_peer_button_${peer.shortId}")
          ) {
            Text("Revoke")
          }
        }
      }

      if (!peer.revoked) {
        HorizontalDivider()
        Text("Per-Mount Capabilities:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
        peer.mountCaps.forEach { mc ->
          Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
          ) {
            Column(modifier = Modifier.weight(1f)) {
              Text(
                text = "${mc.mountLabel} ${if (mc.isCloud) "[CLOUD]" else ""}",
                style = MaterialTheme.typography.bodySmall,
                fontWeight = if (mc.isCloud) FontWeight.Bold else FontWeight.Normal
              )
              Text(
                text = "/${mc.mountId} ${if (mc.mountReadOnly) "(Node ReadOnly)" else ""}",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace
              )
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
              FilterChip(
                selected = mc.canRead,
                onClick = {
                  val target = !mc.canRead
                  if (target && mc.isCloud) {
                    onRequestCloudGrant(
                      PendingCloudGrant(
                        peerIdBase64 = peer.peerIdBase64,
                        peerLabel = peer.label,
                        mountId = mc.mountId,
                        mountLabel = mc.mountLabel,
                        isWriteMode = false,
                      )
                    )
                  } else {
                    facade.setPeerMountCapability(peer.peerIdBase64, mc.mountId, isWriteMode = false, enabled = target)
                  }
                },
                label = { Text("READ") },
                modifier = Modifier.testTag("cap_read_${peer.shortId}_${mc.mountId}")
              )
              FilterChip(
                selected = mc.canWrite,
                onClick = {
                  val target = !mc.canWrite
                  if (target && mc.isCloud) {
                    onRequestCloudGrant(
                      PendingCloudGrant(
                        peerIdBase64 = peer.peerIdBase64,
                        peerLabel = peer.label,
                        mountId = mc.mountId,
                        mountLabel = mc.mountLabel,
                        isWriteMode = true,
                      )
                    )
                  } else {
                    facade.setPeerMountCapability(peer.peerIdBase64, mc.mountId, isWriteMode = true, enabled = target)
                  }
                },
                label = { Text("WRITE") },
                modifier = Modifier.testTag("cap_write_${peer.shortId}_${mc.mountId}")
              )
            }
          }
        }

        if (peer.lanCaps.isNotEmpty()) {
          HorizontalDivider()
          Text("LAN Proxy Destination Capabilities:", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.SemiBold)
          peer.lanCaps.forEach { lc ->
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Text(lc.destinationLabel, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
              FilterChip(
                selected = lc.allowed,
                onClick = { facade.setPeerLanCapability(peer.peerIdBase64, lc.destinationId, !lc.allowed) },
                label = { Text("ALLOW TCP") },
                modifier = Modifier.testTag("cap_lan_${peer.shortId}_${lc.destinationId}")
              )
            }
          }
        }
      }
    }
  }
}

@Composable
private fun LanAndSecurityTab(
  state: HomeNodeUiState,
  facade: HomeNodeFacade,
) {
  var destId by rememberSaveable { mutableStateOf("") }
  var destLabel by rememberSaveable { mutableStateOf("") }
  var destIp by rememberSaveable { mutableStateOf("192.168.1.90") }
  var destPort by rememberSaveable { mutableStateOf("8080") }

  LazyColumn(
    modifier = Modifier
      .fillMaxSize()
      .widthIn(max = 600.dp)
      .padding(horizontal = 16.dp),
    verticalArrangement = Arrangement.spacedBy(12.dp)
  ) {
    // 1. Allowlisted LAN Proxy Destinations (Slice S8)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("lan_proxy_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Icon(Icons.Filled.Lan, contentDescription = "LAN Proxy")
            Text(
              text = "LanProxy Allowlist (ID-Based · IP Literals Only)",
              style = MaterialTheme.typography.titleSmall,
              fontWeight = FontWeight.Bold
            )
          }
          Text(
            text = "Clients request a DestinationId, never a raw host/port. Validated at config AND connect time (rejects hostnames, 127.0.0.0/8, 169.254/16, own IP, and tunnel subnet 10.66/16).",
            style = MaterialTheme.typography.bodySmall
          )
          state.lanDestinations.forEach { d ->
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween,
              verticalAlignment = Alignment.CenterVertically
            ) {
              Column {
                Text(d.label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
                Text(
                  text = "ID: ${d.id} -> ${d.hostIpLiteral}:${d.port}",
                  style = MaterialTheme.typography.labelSmall,
                  fontFamily = FontFamily.Monospace
                )
              }
              IconButton(
                onClick = { facade.removeLanDestination(d.id) },
                modifier = Modifier.testTag("remove_lan_dest_${d.id}")
              ) {
                Icon(Icons.Filled.Delete, contentDescription = "Remove LAN Destination")
              }
            }
          }
          HorizontalDivider()
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = destId,
              onValueChange = { destId = it },
              label = { Text("Destination ID") },
              singleLine = true,
              modifier = Modifier.weight(1f).testTag("lan_dest_id_input")
            )
            OutlinedTextField(
              value = destLabel,
              onValueChange = { destLabel = it },
              label = { Text("Service Name") },
              singleLine = true,
              modifier = Modifier.weight(1f).testTag("lan_dest_label_input")
            )
          }
          Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
              value = destIp,
              onValueChange = { destIp = it },
              label = { Text("RFC1918 IP Literal") },
              singleLine = true,
              modifier = Modifier.weight(2f).testTag("lan_dest_ip_input")
            )
            OutlinedTextField(
              value = destPort,
              onValueChange = { destPort = it },
              label = { Text("TCP Port") },
              singleLine = true,
              modifier = Modifier.weight(1f).testTag("lan_dest_port_input")
            )
          }
          Button(
            onClick = {
              facade.addLanDestination(
                idRaw = destId.ifBlank { "lan_svc_${state.lanDestinations.size + 1}" },
                label = destLabel.ifBlank { "LAN Service" },
                hostIpLiteral = destIp,
                port = destPort.toIntOrNull() ?: 8080,
              )
              destId = ""
              destLabel = ""
            },
            modifier = Modifier.testTag("add_lan_dest_button")
          ) {
            Text("Validate & Add LAN Destination")
          }
        }
      }
    }

    // 2. Threat Model Verification Matrix (Slice S21)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("threat_matrix_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
          Text(
            text = "Threat-Model Verification Matrix (TM-01 .. TM-07)",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
          )
          state.threatChecks.forEach { tc ->
            Surface(
              tonalElevation = 1.dp,
              shape = MaterialTheme.shapes.small,
              modifier = Modifier.fillMaxWidth()
            ) {
              Column(modifier = Modifier.padding(10.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Row(
                  modifier = Modifier.fillMaxWidth(),
                  horizontalArrangement = Arrangement.SpaceBetween
                ) {
                  Text("${tc.id} (${tc.sliceRef}) · ${tc.threat}", style = MaterialTheme.typography.labelMedium, fontWeight = FontWeight.Bold)
                  Text(
                    text = if (tc.verified) "ACTIVE" else "SIMULATED",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                  )
                }
                Text(tc.control, style = MaterialTheme.typography.bodySmall)
                Text(tc.detail, style = MaterialTheme.typography.labelSmall, fontFamily = FontFamily.Monospace)
              }
            }
          }
        }
      }
    }

    // 3. Safe Structured Event Log (Zero Secrets)
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("safe_event_log_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text(
            text = "Safe Structured Event Log (Zero Secrets / Zero Raw Paths)",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
          )
          state.safeEvents.take(12).forEach { ev ->
            Text(
              text = "[${ev.type.name}] ${ev.safeDetail}",
              style = MaterialTheme.typography.labelSmall,
              fontFamily = FontFamily.Monospace
            )
          }
        }
      }
    }

    // 4. Samsung Galaxy S8+ (API 28) Battery Checklist
    item {
      Card(modifier = Modifier.fillMaxWidth().testTag("s8_battery_guide_card")) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
          Text(
            text = "Samsung Galaxy S8+ (One UI 1.0 / API 28) Always-On Setup",
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold
          )
          state.samsungBatterySteps.forEach { step ->
            Text(step, style = MaterialTheme.typography.bodySmall)
          }
        }
      }
    }

    item { Spacer(modifier = Modifier.height(16.dp)) }
  }
}

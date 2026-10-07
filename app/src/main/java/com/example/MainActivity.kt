package com.example

import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        BootstrapScaffoldScreen()
      }
    }
  }
}

data class ModuleBoundaryEntry(
  val moduleName: String,
  val allowedProjectDeps: String,
  val statusLabel: String,
)

private val S0_MODULES = listOf(
  ModuleBoundaryEntry(":app", ":service-node only", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":service-node", "all lower modules", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":service-files", ":core-storage, :core-transport, :core-identity", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":storage-local", ":core-storage only", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":storage-network", ":core-storage only", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":storage-cloud", ":core-storage only", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":core-identity", ":core-storage (CredentialVault contract)", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":core-transport", "none (zero project-internal deps)", "stubbed (S0 scaffold)"),
  ModuleBoundaryEntry(":core-storage", "none (zero project-internal deps)", "stubbed (S0 scaffold)"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BootstrapScaffoldScreen() {
  Scaffold(
    modifier = Modifier.fillMaxSize().testTag("s0_bootstrap_scaffold"),
    topBar = {
      TopAppBar(
        title = {
          Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
          ) {
            Icon(
              imageVector = Icons.Filled.Dns,
              contentDescription = stringResource(R.string.app_name)
            )
            Text(text = stringResource(R.string.bootstrap_status_title))
          }
        }
      )
    }
  ) { innerPadding ->
    LazyColumn(
      modifier = Modifier
        .fillMaxSize()
        .padding(innerPadding)
        .padding(horizontal = 16.dp),
      verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
      item {
        Card(
          colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.tertiaryContainer
          ),
          modifier = Modifier.fillMaxWidth().testTag("s0_stub_notice_card")
        ) {
          Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Icon(
              imageVector = Icons.Filled.Warning,
              contentDescription = "Stub Warning"
            )
            Column {
              Text(
                text = "STUBBED BUILD — SLICE S0 BOOTSTRAP ONLY",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold
              )
              Text(
                text = stringResource(R.string.bootstrap_status_subtitle),
                style = MaterialTheme.typography.bodySmall
              )
              Text(
                text = "Runtime SDK: API ${Build.VERSION.SDK_INT} (Target hardware: Galaxy S8+ / API 28 max)",
                style = MaterialTheme.typography.labelSmall,
                fontFamily = FontFamily.Monospace
              )
            }
          }
        }
      }

      item {
        Card(
          modifier = Modifier.fillMaxWidth().testTag("s0_security_posture_card")
        ) {
          Row(
            modifier = Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
          ) {
            Icon(
              imageVector = Icons.Filled.Security,
              contentDescription = "Security Posture"
            )
            Column {
              Text(
                text = "Enforced S0 Security Invariants",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold
              )
              Text(
                text = "• android:allowBackup=\"false\" + full extraction exclusion\n" +
                  "• android:usesCleartextTraffic=\"false\" default\n" +
                  "• OAuth client IDs via BuildConfig placeholders (no secrets)\n" +
                  "• Strict 9-module DAG verified by ArchitectureDependencyTest",
                style = MaterialTheme.typography.bodySmall
              )
            }
          }
        }
      }

      item {
        Text(
          text = "Module Dependency Graph (§3)",
          style = MaterialTheme.typography.titleMedium,
          fontWeight = FontWeight.Bold,
          modifier = Modifier.padding(top = 4.dp)
        )
      }

      items(S0_MODULES, key = { it.moduleName }) { entry ->
        Surface(
          tonalElevation = 2.dp,
          shape = MaterialTheme.shapes.medium,
          modifier = Modifier.fillMaxWidth().testTag("module_card_${entry.moduleName.removePrefix(":")}")
        ) {
          Column(modifier = Modifier.padding(12.dp)) {
            Row(
              modifier = Modifier.fillMaxWidth(),
              horizontalArrangement = Arrangement.SpaceBetween
            ) {
              Text(
                text = entry.moduleName,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold
              )
              Text(
                text = entry.statusLabel,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.primary
              )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(
              text = "Allowed project deps: ${entry.allowedProjectDeps}",
              style = MaterialTheme.typography.bodySmall,
              fontFamily = FontFamily.Monospace
            )
          }
        }
      }

      item {
        Spacer(modifier = Modifier.height(16.dp))
      }
    }
  }
}

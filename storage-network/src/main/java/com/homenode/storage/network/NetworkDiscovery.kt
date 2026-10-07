package com.homenode.storage.network

import com.homenode.core.storage.StorageError
import com.homenode.core.storage.StorageProvider
import com.homenode.core.storage.StorageResult
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull

enum class DiscoverySource {
  MDNS,
  SUBNET_PROBE,
}

data class DiscoveredService(
  val hostIp: String,
  val port: Int,
  val protocolGuess: StorageProvider,
  val advertisedName: String,
  val source: DiscoverySource,
)

interface MdnsDiscoverySource {
  suspend fun queryMdnsServices(): List<DiscoveredService>
}

interface TcpPortProber {
  suspend fun isPortOpen(hostIp: String, port: Int, timeoutMs: Int): Boolean
}

/**
 * Network Storage Discovery (`NetworkDiscovery`) (§8.7, ADR-010, Slice S10).
 * Enforces:
 * - Foreground user-initiated invocation only (`userInitiatedInForeground == true`); peers can NEVER trigger a scan.
 * - Active probe strictly restricted to RFC1918 `/24` subnet (`<= 254` hosts, `<= 16` parallel connects, `400ms` timeout, `15s` cap).
 * - Rate limit cooldown between scans (`MIN_COOLDOWN_MS = 10_000L`).
 * - Sanitizes untrusted mDNS advertised names (`<= 48` printable non-control characters).
 * - Discovery results are suggestions only; never auto-connects or sends credentials.
 */
class NetworkDiscovery(
  private val mdnsSource: MdnsDiscoverySource,
  private val portProber: TcpPortProber,
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) {
  private var lastScanEpochMillis: Long = -1L

  suspend fun scanLanForStorage(
    subnetPrefix24: String, // e.g. "192.168.1"
    userInitiatedInForeground: Boolean,
    portsToProbe: List<Int> = DEFAULT_PROBE_PORTS,
    maxHostsToProbe: Int = MAX_SUBNET_HOSTS,
  ): StorageResult<List<DiscoveredService>> {
    if (!userInitiatedInForeground) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Network discovery may only run when user-initiated in the foreground UI (§8.7)"
      )
    }

    val now = clockEpochMillis()
    if (lastScanEpochMillis > 0 && now - lastScanEpochMillis < MIN_COOLDOWN_MS) {
      return StorageResult.Failure(
        StorageError.RATE_LIMITED,
        "Discovery scan rate-limited; wait before scanning again"
      )
    }

    // Validate that subnetPrefix24.1 is a valid RFC1918 LAN address
    val sampleCheck = LanStorageAddressPolicy.validateLanTarget("$subnetPrefix24.1", 445)
    if (sampleCheck is StorageResult.Failure) {
      return StorageResult.Failure(
        StorageError.DENIED,
        "Subnet '$subnetPrefix24.0/24' is not a permitted RFC1918 private LAN subnet"
      )
    }

    lastScanEpochMillis = now
    val boundedHostCount = maxHostsToProbe.coerceIn(1, MAX_SUBNET_HOSTS)
    val boundedPorts = portsToProbe.filter { it in ALLOWED_STORAGE_PORTS }.take(4)
    val semaphore = Semaphore(MAX_CONCURRENCY)

    val combined = withTimeoutOrNull(MAX_SCAN_DURATION_MS) {
      coroutineScope {
        val mdnsDeferred = async {
          mdnsSource.queryMdnsServices()
            .filter { LanStorageAddressPolicy.validateLanTarget(it.hostIp, it.port).isSuccess }
            .map { it.copy(advertisedName = sanitizeUntrustedNetworkName(it.advertisedName)) }
        }

        val probeJobs = (1..boundedHostCount).flatMap { hostOctet ->
          val hostIp = "$subnetPrefix24.$hostOctet"
          boundedPorts.map { port ->
            async {
              currentCoroutineContext().ensureActive()
              semaphore.withPermit {
                if (portProber.isPortOpen(hostIp, port, CONNECT_TIMEOUT_MS)) {
                  val proto = guessProtocolForPort(port)
                  DiscoveredService(
                    hostIp = hostIp,
                    port = port,
                    protocolGuess = proto,
                    advertisedName = "${proto.name} @ $hostIp:$port",
                    source = DiscoverySource.SUBNET_PROBE,
                  )
                } else {
                  null
                }
              }
            }
          }
        }

        val mdnsResults = mdnsDeferred.await()
        val probeResults = probeJobs.awaitAll().filterNotNull()
        (mdnsResults + probeResults).distinctBy { "${it.hostIp}:${it.port}:${it.protocolGuess}" }
      }
    } ?: return StorageResult.Failure(StorageError.TIMEOUT, "Discovery scan timed out")

    return StorageResult.Success(combined)
  }

  companion object {
    const val MAX_SUBNET_HOSTS = 254
    const val MAX_CONCURRENCY = 16
    const val CONNECT_TIMEOUT_MS = 400
    const val MAX_SCAN_DURATION_MS = 15_000L
    const val MIN_COOLDOWN_MS = 10_000L
    const val MAX_ADVERTISED_NAME_LEN = 48

    val DEFAULT_PROBE_PORTS = listOf(445, 22, 443, 5006)
    private val ALLOWED_STORAGE_PORTS = setOf(445, 22, 443, 5005, 5006, 8080, 8443)

    fun sanitizeUntrustedNetworkName(raw: String?): String {
      if (raw.isNullOrBlank()) return "Unnamed Storage Host"
      val cleaned = buildString {
        for (ch in raw) {
          if (!ch.isISOControl() && ch != '\u0000' && ch != '<' && ch != '>' && ch != '"' && ch != '\'') {
            append(ch)
          }
          if (length >= MAX_ADVERTISED_NAME_LEN) break
        }
      }.trim()
      return cleaned.ifEmpty { "Unnamed Storage Host" }
    }

    private fun guessProtocolForPort(port: Int): StorageProvider = when (port) {
      445 -> StorageProvider.SMB
      22 -> StorageProvider.SFTP
      else -> StorageProvider.WEBDAV
    }
  }
}

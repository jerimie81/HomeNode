package com.homenode.service.node

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.homenode.storage.network.LanStorageAddressPolicy
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * Discovers active RFC1918 IPv4 addresses on local network interfaces (`wlan0`, `eth0`, etc.)
 * so `DirectLanReachability` and `LanProxy` bind/validate against the real device IP rather than a hardcoded IP.
 */
object LanInterfaceDetector {
  fun detectActiveRfc1918Ipv4Addresses(): Set<String> {
    return try {
      val result = mutableSetOf<String>()
      val interfaces = NetworkInterface.getNetworkInterfaces() ?: return emptySet()
      for (nif in Collections.list(interfaces)) {
        if (!nif.isUp || nif.isLoopback) continue
        // Skip Android TUN/VPN interfaces so we only report physical LAN/Wi-Fi addresses
        val name = nif.name.lowercase()
        if (name.startsWith("tun") || name.startsWith("wg") || name.startsWith("ppp")) continue
        for (addr in Collections.list(nif.inetAddresses)) {
          if (addr is Inet4Address && !addr.isLoopbackAddress) {
            val hostAddr = addr.hostAddress ?: continue
            if (LanStorageAddressPolicy.validateLanTarget(hostAddr, 445).isSuccess) {
              result.add(hostAddr)
            }
          }
        }
      }
      result
    } catch (e: Exception) {
      emptySet()
    }
  }
}

/**
 * Persists user-selected `desiredState` (`RUNNING` vs `STOPPED`) so `NodeService` and `BootReceiver`
 * respect user Stop across reboots and `START_STICKY` restarts (§12, Slice S18).
 */
class DesiredNodeStateStore(private val stateDir: File) {
  private val file = File(stateDir, "desired_node_state.txt")

  init {
    if (!stateDir.exists()) stateDir.mkdirs()
  }

  @Synchronized
  fun setDesiredRunning(shouldRun: Boolean) {
    file.writeText(if (shouldRun) "RUNNING" else "STOPPED")
  }

  @Synchronized
  fun isDesiredRunning(): Boolean {
    if (!file.exists()) return false
    return file.readText().trim() == "RUNNING"
  }
}

/**
 * Single-owner, reference-counted lock coordinator (`LockManager`) (§12, Slice S18).
 * - Holds Wi-Fi / CPU locks only while active peer transfers or sessions exist.
 * - Holds a multicast lock only during foreground user-initiated network discovery.
 */
class LockManager {
  private val activeSessionRefCount = AtomicInteger(0)
  private val discoveryMulticastActive = AtomicInteger(0)

  val isTransferLockHeld: Boolean
    get() = activeSessionRefCount.get() > 0

  val isMulticastLockHeld: Boolean
    get() = discoveryMulticastActive.get() > 0

  fun acquireSessionLock(): Int = activeSessionRefCount.incrementAndGet()

  fun releaseSessionLock(): Int =
    activeSessionRefCount.updateAndGet { current -> (current - 1).coerceAtLeast(0) }

  fun acquireDiscoveryMulticastLock() {
    discoveryMulticastActive.incrementAndGet()
  }

  fun releaseDiscoveryMulticastLock() {
    discoveryMulticastActive.updateAndGet { current -> (current - 1).coerceAtLeast(0) }
  }

  fun forceReleaseAll() {
    activeSessionRefCount.set(0)
    discoveryMulticastActive.set(0)
  }
}

/**
 * Foreground service hosting `NodeRuntime` on Samsung Galaxy S8+ (API 28) (§2, §12, ADR-006, Slice S18).
 * - Uses `Build.VERSION.SDK_INT` guards so API 28 calls 2-arg `startForeground(id, notification)`.
 * - Uses `START_STICKY` deliberately only when `desiredState == RUNNING`.
 * - Starts and stops the registered [HomeNodeFacade] / `NodeRuntime` instance when commanded.
 */
class NodeService : Service() {
  override fun onBind(intent: Intent?): IBinder? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    val store = DesiredNodeStateStore(noBackupFilesDir)
    if (intent?.action == ACTION_STOP_NODE) {
      store.setDesiredRunning(false)
      registeredFacade?.stopNodeFromService()
      stopForeground(STOP_FOREGROUND_REMOVE)
      stopSelf()
      return START_NOT_STICKY
    }

    if (!store.isDesiredRunning() && intent?.action != ACTION_START_NODE) {
      stopSelf()
      return START_NOT_STICKY
    }

    store.setDesiredRunning(true)
    ensureNotificationChannel()
    val notification = buildForegroundNotification()
    // API 28 (Android 9 on Galaxy S8+) uses 2-argument startForeground without foregroundServiceType (§2, ADR-006)
    startForeground(NOTIFICATION_ID, notification)
    registeredFacade?.startNodeFromService()
    return START_STICKY
  }

  override fun onDestroy() {
    val store = DesiredNodeStateStore(noBackupFilesDir)
    if (!store.isDesiredRunning()) {
      registeredFacade?.stopNodeFromService()
    }
    super.onDestroy()
  }

  private fun ensureNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val mgr = getSystemService(NotificationManager::class.java) ?: return
      val channel = NotificationChannel(
        CHANNEL_ID,
        "HomeNode Tunnel & Storage Service",
        NotificationManager.IMPORTANCE_LOW
      )
      mgr.createNotificationChannel(channel)
    }
  }

  private fun buildForegroundNotification(): Notification {
    return Notification.Builder(this, CHANNEL_ID)
      .setContentTitle("HomeNode Active")
      .setContentText("Encrypted P2P home node listening for authorized peers")
      .setSmallIcon(android.R.drawable.ic_lock_lock)
      .setOngoing(true)
      .build()
  }

  companion object {
    const val CHANNEL_ID = "homenode_fgs_channel"
    const val NOTIFICATION_ID = 7001
    const val ACTION_START_NODE = "com.homenode.action.START_NODE"
    const val ACTION_STOP_NODE = "com.homenode.action.STOP_NODE"

    @Volatile
    private var registeredFacade: HomeNodeFacade? = null

    fun registerFacade(facade: HomeNodeFacade) {
      registeredFacade = facade
    }
  }
}

/**
 * Minimal `BootReceiver` (§12, Slice S18).
 * Checks persisted `desiredState` and hands off to [NodeService]; performs zero network or cryptographic work.
 */
class BootReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent?) {
    if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
    val store = DesiredNodeStateStore(context.noBackupFilesDir)
    if (store.isDesiredRunning()) {
      val serviceIntent = Intent(context, NodeService::class.java).apply {
        action = NodeService.ACTION_START_NODE
      }
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        context.startForegroundService(serviceIntent)
      } else {
        context.startService(serviceIntent)
      }
    }
  }
}

/**
 * Samsung Galaxy S8+ (One UI 1.0 / Android 9) battery optimization guidance (§2, §12).
 */
object SamsungBatteryGuidance {
  val stepsForGalaxyS8PlusApi28 = listOf(
    "1. Open Settings -> Apps -> HomeNode -> Battery -> Enable 'Allow background activity'.",
    "2. Tap 'Optimize battery usage' -> Switch dropdown to 'All' -> Turn OFF optimization for HomeNode.",
    "3. Open Settings -> Device care -> Battery -> Settings (three dots) -> Disable 'Put unused apps to sleep' or remove HomeNode from 'Sleeping apps'.",
    "4. Open Settings -> Connections -> Wi-Fi -> Advanced -> Keep Wi-Fi on during sleep -> 'Always'."
  )
}

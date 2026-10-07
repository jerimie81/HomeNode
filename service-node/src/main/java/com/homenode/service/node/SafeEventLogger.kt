package com.homenode.service.node

import com.homenode.core.storage.MountId
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * Safe event types permitted by Knowledge Base §14.
 * Signatures intentionally accept only opaque IDs, enum labels, or integer counts — NEVER raw paths,
 * keys, passwords, OAuth tokens, authorization codes, account emails, or discovered hostnames.
 */
enum class SafeEventType {
  NODE_STARTING,
  NODE_RUNNING,
  TRANSPORT_CONNECTED,
  PEER_ADDED,
  PEER_REMOVED,
  FILE_REQUEST_DENIED,
  LAN_CONNECTION_DENIED,
  RETRY_SCHEDULED,
  NODE_STOPPED,
  MOUNT_ADDED,
  MOUNT_REMOVED,
  MOUNT_STATE_CHANGED,
  MOUNT_REAUTH_REQUIRED,
  DISCOVERY_STARTED,
  DISCOVERY_FINISHED,
}

data class SafeEventRecord(
  val timestampEpochMillis: Long,
  val type: SafeEventType,
  val safeDetail: String,
)

class SafeEventLogger(
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
  private val maxRetainedEvents: Int = 200,
) {
  private val _events = MutableStateFlow<List<SafeEventRecord>>(emptyList())
  val events: StateFlow<List<SafeEventRecord>> = _events.asStateFlow()

  private val _counters = MutableStateFlow<Map<SafeEventType, Long>>(emptyMap())
  val counters: StateFlow<Map<SafeEventType, Long>> = _counters.asStateFlow()

  fun logNodeStarting() = record(SafeEventType.NODE_STARTING, "node_starting")
  fun logNodeRunning(stateSummary: String) = record(SafeEventType.NODE_RUNNING, sanitizeToken(stateSummary))
  fun logTransportConnected(endpointCount: Int) =
    record(SafeEventType.TRANSPORT_CONNECTED, "endpoints=$endpointCount")
  fun logPeerAdded(shortPeerId: String) =
    record(SafeEventType.PEER_ADDED, "peer=${sanitizeToken(shortPeerId)}")
  fun logPeerRemoved(shortPeerId: String) =
    record(SafeEventType.PEER_REMOVED, "peer=${sanitizeToken(shortPeerId)}")
  fun logFileRequestDenied() = record(SafeEventType.FILE_REQUEST_DENIED, "file_access_denied")
  fun logLanConnectionDenied(reasonCode: String) =
    record(SafeEventType.LAN_CONNECTION_DENIED, "reason=${sanitizeToken(reasonCode)}")
  fun logRetryScheduled(componentId: String, delaySeconds: Long) =
    record(SafeEventType.RETRY_SCHEDULED, "component=${sanitizeToken(componentId)} delaySec=$delaySeconds")
  fun logNodeStopped() = record(SafeEventType.NODE_STOPPED, "node_stopped")
  fun logMountAdded(mountId: MountId, kindName: String) =
    record(SafeEventType.MOUNT_ADDED, "mount=${mountId.value} kind=${sanitizeToken(kindName)}")
  fun logMountRemoved(mountId: MountId) =
    record(SafeEventType.MOUNT_REMOVED, "mount=${mountId.value}")
  fun logMountStateChanged(mountId: MountId, stateName: String) =
    record(SafeEventType.MOUNT_STATE_CHANGED, "mount=${mountId.value} state=${sanitizeToken(stateName)}")
  fun logMountReauthRequired(mountId: MountId) =
    record(SafeEventType.MOUNT_REAUTH_REQUIRED, "mount=${mountId.value}")
  fun logDiscoveryStarted() = record(SafeEventType.DISCOVERY_STARTED, "scan_started")
  fun logDiscoveryFinished(candidateCount: Int) =
    record(SafeEventType.DISCOVERY_FINISHED, "count=$candidateCount")

  private fun record(type: SafeEventType, safeDetail: String) {
    val entry = SafeEventRecord(
      timestampEpochMillis = clockEpochMillis(),
      type = type,
      safeDetail = safeDetail,
    )
    _events.update { current ->
      (current + entry).takeLast(maxRetainedEvents)
    }
    _counters.update { map ->
      map + (type to ((map[type] ?: 0L) + 1L))
    }
  }

  companion object {
    private val SAFE_TOKEN_REGEX = Regex("[^a-zA-Z0-9_=:.-]")

    internal fun sanitizeToken(raw: String): String =
      raw.replace(SAFE_TOKEN_REGEX, "_").take(40)
  }
}

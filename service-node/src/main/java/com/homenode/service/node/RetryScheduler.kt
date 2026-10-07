package com.homenode.service.node

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Deterministic exponential backoff policy (`1s -> 2s -> 4s -> 8s -> 16s -> 32s -> 60s` cap) (§11, Slice S2).
 * - One active retry job per component/mount key; scheduling while one is active is a no-op.
 * - Resets failure attempt counter after [STABLE_RESET_WINDOW_MS] (2 minutes) of stability.
 * - Emits `RETRY_SCHEDULED` via [SafeEventLogger].
 */
object RetryPolicy {
  val BACKOFF_SECONDS = longArrayOf(1L, 2L, 4L, 8L, 16L, 32L, 60L)
  const val STABLE_RESET_WINDOW_MS = 120_000L // 2 minutes (§11)

  fun delaySecondsForAttempt(attemptIndexZeroBased: Int): Long {
    val clamped = attemptIndexZeroBased.coerceIn(0, BACKOFF_SECONDS.lastIndex)
    return BACKOFF_SECONDS[clamped]
  }
}

class ComponentRetryScheduler(
  private val logger: SafeEventLogger,
  private val clockEpochMillis: () -> Long = { System.currentTimeMillis() },
) {
  private data class RetryState(
    var attemptCount: Int = 0,
    var lastSuccessEpochMillis: Long = 0L,
    var activeJob: Job? = null,
  )

  private val states = ConcurrentHashMap<String, RetryState>()

  /**
   * Schedules a retry for [componentKey] in [scope].
   * Returns `true` if a new retry job was scheduled, or `false` if a retry job for [componentKey] is already pending.
   */
  @Synchronized
  fun scheduleRetry(
    scope: CoroutineScope,
    componentKey: String,
    action: suspend () -> Boolean,
  ): Boolean {
    val state = states.getOrPut(componentKey) { RetryState(lastSuccessEpochMillis = clockEpochMillis()) }
    if (state.activeJob?.isActive == true) {
      return false // Duplicate schedule is a no-op (§11)
    }

    val now = clockEpochMillis()
    if (state.lastSuccessEpochMillis > 0L && now - state.lastSuccessEpochMillis >= RetryPolicy.STABLE_RESET_WINDOW_MS) {
      state.attemptCount = 0
    }

    val delaySec = RetryPolicy.delaySecondsForAttempt(state.attemptCount)
    state.attemptCount++
    logger.logRetryScheduled(componentKey, delaySec)

    state.activeJob = scope.launch {
      delay(delaySec * 1000L)
      val succeeded = runCatching { action() }.getOrDefault(false)
      synchronized(this@ComponentRetryScheduler) {
        state.activeJob = null
        if (succeeded) {
          state.lastSuccessEpochMillis = clockEpochMillis()
        }
      }
    }
    return true
  }

  @Synchronized
  fun markComponentHealthy(componentKey: String) {
    val state = states.getOrPut(componentKey) { RetryState() }
    val now = clockEpochMillis()
    if (state.lastSuccessEpochMillis > 0L && now - state.lastSuccessEpochMillis >= RetryPolicy.STABLE_RESET_WINDOW_MS) {
      state.attemptCount = 0
    }
    state.lastSuccessEpochMillis = now
    state.activeJob?.cancel()
    state.activeJob = null
  }

  @Synchronized
  fun cancelComponent(componentKey: String) {
    states.remove(componentKey)?.activeJob?.cancel()
  }

  @Synchronized
  fun cancelAll() {
    states.values.forEach { it.activeJob?.cancel() }
    states.clear()
  }

  @Synchronized
  fun currentAttemptCount(componentKey: String): Int = states[componentKey]?.attemptCount ?: 0
}

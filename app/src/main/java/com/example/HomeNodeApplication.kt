package com.example

import android.app.Application
import android.util.Log

/**
 * Minimal bootstrap [Application] for Slice S0.
 * Announces stubbed status loudly at startup per Architecture Rule §3.
 */
class HomeNodeApplication : Application() {
  override fun onCreate() {
    super.onCreate()
    Log.w(TAG, "BOOTSTRAP_STUB_ACTIVE: HomeNode Slice S0 scaffold initialized (no feature code yet).")
  }

  companion object {
    private const val TAG = "HomeNodeBootstrapStub"
  }
}

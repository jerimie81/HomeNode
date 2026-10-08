plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.ktlint)
}

android {
  namespace = "com.homenode.storage.network"
  compileSdk { version = release(36) { minorApiLevel = 1 } }

  defaultConfig {
    minSdk = 26
    consumerProguardFiles("consumer-rules.pro")
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }
}

// Strict module dependency rule (§3): :storage-network depends ONLY on :core-storage (+ provider libs later).
dependencies {
  implementation(project(":core-storage"))
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}

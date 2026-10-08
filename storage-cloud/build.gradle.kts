plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.ktlint)
}

android {
  namespace = "com.homenode.storage.cloud"
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

// Strict module dependency rule (§3): :storage-cloud depends ONLY on :core-storage (+ provider libs later).
dependencies {
  implementation(project(":core-storage"))
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.okhttp)
  testImplementation(libs.junit)
  testImplementation("org.jetbrains.kotlin:kotlin-test-junit:2.2.10")
  testImplementation(libs.kotlinx.coroutines.test)
}

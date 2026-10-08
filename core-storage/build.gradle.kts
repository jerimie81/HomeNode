plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.ktlint)
}

android {
  namespace = "com.homenode.core.storage"
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

// Strict module dependency rule (§3): :core-storage depends on NO project-internal modules.
dependencies {
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}

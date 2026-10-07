plugins {
  alias(libs.plugins.android.library)
}

android {
  namespace = "com.homenode.service.files"
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

// Strict module dependency rule (§3): :service-files -> :core-storage, :core-transport, :core-identity.
dependencies {
  implementation(project(":core-storage"))
  implementation(project(":core-transport"))
  implementation(project(":core-identity"))
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}

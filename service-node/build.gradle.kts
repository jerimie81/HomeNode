plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.ktlint)
}

android {
  namespace = "com.homenode.service.node"
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

// Strict module dependency rule (§3): :service-node -> everything below.
dependencies {
  implementation(project(":service-files"))
  implementation(project(":storage-local"))
  implementation(project(":storage-network"))
  implementation(project(":storage-cloud"))
  implementation(project(":core-transport"))
  implementation(project(":core-identity"))
  implementation(project(":core-storage"))
  implementation(libs.androidx.core.ktx)
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}

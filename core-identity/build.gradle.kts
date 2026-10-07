plugins {
  alias(libs.plugins.android.library)
}

android {
  namespace = "com.homenode.core.identity"
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

// :core-identity implements CredentialVault (contract in :core-storage) and peer authorization.
dependencies {
  implementation(project(":core-storage"))
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
}

plugins {
  alias(libs.plugins.android.library)
}

android {
  namespace = "com.homenode.core.identity"
  compileSdk { version = release(36) { minorApiLevel = 1 } }

  defaultConfig {
    minSdk = 26
    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    consumerProguardFiles("consumer-rules.pro")
  }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }
}

// :core-identity implements CredentialVault (contract in :core-storage), X25519 identity, and peer authorization.
dependencies {
  implementation(project(":core-storage"))
  implementation(libs.bouncycastle.bcprov)
  implementation(libs.kotlinx.coroutines.core)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
  androidTestImplementation(libs.androidx.junit)
  androidTestImplementation(libs.androidx.runner)
  androidTestImplementation(libs.kotlinx.coroutines.test)
}

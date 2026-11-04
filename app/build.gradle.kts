plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.tulipeni.nexusultra"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.tulipeni.nexusultra"
        minSdk = 26
        targetSdk = 35
        versionCode = 9
        versionName = "6.0.0"
    }

    // Keep Java and Kotlin bytecode targets aligned for the JDK 17 CI runner.
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

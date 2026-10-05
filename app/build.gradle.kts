plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.droidguard"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "dev.droidguard"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("x86_64", "arm64-v8a") }
        externalNativeBuild {
            cmake { arguments += listOf("-DANDROID_STL=c++_static") }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Debug-signed so CI and the benchmark can install it; this is a
            // portfolio build, not a store build.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    // Benchmarks run against an optimised native core even in connectedCheck,
    // which always uses the debug variant.
    testBuildType = (project.findProperty("dg.testBuildType") as String?) ?: "debug"

    buildFeatures {
        aidl = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    // labels.tsv rides along in the test APK so the native core is scored on-device too.
    sourceSets["androidTest"].assets.srcDir("../data")

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test:rules:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

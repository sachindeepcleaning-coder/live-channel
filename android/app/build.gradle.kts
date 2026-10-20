import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val keystoreProps = Properties()
val keystorePropsFile = rootProject.file("keystore.properties")
if (keystorePropsFile.exists()) {
    FileInputStream(keystorePropsFile).use { keystoreProps.load(it) }
}

// Fail with an actionable message instead of AGP's cryptic
// 'SigningConfig "release" is missing required property "storeFile"'.
// The keystore is deliberately git-ignored — see README → Android APK.
gradle.taskGraph.whenReady {
    val wantsRelease = gradle.startParameter.taskNames.any {
        it.contains("release", ignoreCase = true) ||
            it.equals("assemble", ignoreCase = true) ||
            it.equals("bundle", ignoreCase = true) ||
            it.equals("build", ignoreCase = true)
    }
    if (wantsRelease) {
        check(keystorePropsFile.exists()) {
            "Release build requires android/keystore.properties with " +
                "storeFile/storePassword/keyAlias/keyPassword. It is git-ignored on purpose, " +
                "so a fresh clone cannot rebuild the published APK — restore it from your backup " +
                "(the same key is required for users to update in place)."
        }
    }
}

android {
    namespace = "com.tuner.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.tuner.app"
        minSdk = 21
        targetSdk = 34
        versionCode = 5
        versionName = "2.2.1"
    }

    signingConfigs {
        create("release") {
            if (keystorePropsFile.exists()) {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
            // v1 is needed by older devices/installers; v2/v3 for modern Android.
            enableV1Signing = true
            enableV2Signing = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.webkit:webkit:1.10.0")
}

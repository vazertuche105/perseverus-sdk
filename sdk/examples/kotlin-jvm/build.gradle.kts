// Kotlin/JVM sample for perseverus-sdk.
//
// `./gradlew run --args="status"` builds the Rust library (release),
// generates the UniFFI Kotlin bindings into build/generated/uniffi, compiles
// this sample against them and runs it. Requires cargo on PATH (or in
// ~/.cargo/bin) and JDK 17+.

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.20"
    application
}

repositories { mavenCentral() }

dependencies {
    // UniFFI's generated Kotlin talks to the native library through JNA.
    implementation("net.java.dev.jna:jna:5.17.0")
    // Only for reading Sparrow's config in `import-sparrow`.
    implementation("com.google.code.gson:gson:2.11.0")
}

val repoRoot: File = rootDir.resolve("../../..").canonicalFile
val osName = System.getProperty("os.name").lowercase()
val libName = when {
    osName.contains("mac") -> "libperseverus_sdk.dylib"
    osName.contains("win") -> "perseverus_sdk.dll"
    else -> "libperseverus_sdk.so"
}
val libDir: File = repoRoot.resolve("target/release")
val cargo: String = File(System.getProperty("user.home"), ".cargo/bin/cargo").takeIf { it.exists() }?.path ?: "cargo"
val bindingsDir: File = layout.buildDirectory.dir("generated/uniffi").get().asFile

val cargoBuild by tasks.registering(Exec::class) {
    description = "Builds the perseverus-sdk native library (release)."
    workingDir(repoRoot)
    commandLine(cargo, "build", "-p", "perseverus-sdk", "--release", "--lib")
}

val generateBindings by tasks.registering(Exec::class) {
    description = "Generates Kotlin bindings from the compiled library with uniffi-bindgen."
    dependsOn(cargoBuild)
    workingDir(repoRoot)
    outputs.dir(bindingsDir)
    commandLine(
        cargo, "run", "-q", "-p", "perseverus-sdk", "--features", "bindgen", "--bin", "uniffi-bindgen", "--",
        "generate", "--library", libDir.resolve(libName).path, "--language", "kotlin", "--out-dir", bindingsDir.path,
    )
}

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_17) }
    sourceSets.named("main") { kotlin.srcDir(generateBindings) }
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

application {
    mainClass.set("com.btcmedusa.sample.MainKt")
    // --enable-native-access silences the JDK 24+ warning when JNA loads the library.
    applicationDefaultJvmArgs = listOf("-Djna.library.path=${libDir.path}", "--enable-native-access=ALL-UNNAMED")
}

tasks.named<JavaExec>("run") {
    standardInput = System.`in`
}

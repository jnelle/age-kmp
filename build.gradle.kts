plugins {
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.kotlinAtomicfu) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.gobleyCargo) apply false
    alias(libs.plugins.gobleyUniffi) apply false
    alias(libs.plugins.mavenPublish) apply false
}

// The publish plugin reads GROUP and VERSION_NAME when it builds a POM, but leaves the project's
// own coordinates alone. A consumer including this build with includeBuild matches on exactly those
// coordinates, so without this the substitution silently does not happen and the dependency is
// looked up on Maven Central instead.
allprojects {
    group = providers.gradleProperty("GROUP").get()
    version = providers.gradleProperty("VERSION_NAME").get()
}

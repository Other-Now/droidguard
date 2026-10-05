package dev.droidguard.core

/** One matched CVE. `flags` is only meaningful for kernel hits (see [Flags]). */
data class Hit(val cve: String, val target: String, val severity: String, val flags: Int)

/** An app-level hit from a batched match: [index] points into the input arrays. */
data class AppHit(val index: Int, val hit: Hit)

object Flags {
    const val SPL_UNPATCHED = 1
    const val VERSION_IN_RANGE = 2
    const val VERSION_UNKNOWN = 4

    /** Mirrors dg::kernel_vulnerable. Both signals, or patch level when no range is known. */
    fun kernelVulnerable(f: Int): Boolean =
        (f and SPL_UNPATCHED) != 0 && (f and (VERSION_IN_RANGE or VERSION_UNKNOWN)) != 0
}

/**
 * The matcher contract. Two implementations: [NativeMatcher] (the NDK core,
 * over JNI) and [KotlinMatcher] (the same algorithm in Kotlin, kept as the
 * benchmark baseline and as a second opinion in the parity tests).
 */
interface CveMatcher : AutoCloseable {
    fun matchPlatform(release: String, spl: String): List<Hit>
    fun matchKernel(uname: String, spl: String): List<Hit>
    fun matchApp(pkg: String, version: String): List<Hit>
    fun matchApps(pkgs: Array<String>, versions: Array<String>): List<AppHit>
    fun counts(): IntArray // platform, kernel, app rules, aliases
    override fun close() {}
}

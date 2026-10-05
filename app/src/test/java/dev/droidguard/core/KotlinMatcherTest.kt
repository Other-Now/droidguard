package dev.droidguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import java.io.File

/**
 * The Kotlin twin scored against the same hand-labelled cases as the native
 * core's dg_eval. Runs on the JVM, no device. (Gradle runs unit tests with the
 * module directory as the working directory.)
 */
class KotlinMatcherTest {
    companion object {
        private lateinit var m: KotlinMatcher

        @BeforeClass
        @JvmStatic
        fun load() {
            m = KotlinMatcher(File("src/main/assets/rules.tsv").readText())
        }
    }

    private fun hit(kind: String, a: String, b: String, cve: String): Boolean = when (kind) {
        "platform" -> m.matchPlatform(a, b).any { it.cve == cve }
        "kernel" -> m.matchKernel(a, b).any { it.cve == cve && Flags.kernelVulnerable(it.flags) }
        "app" -> m.matchApp(a, b).any { it.cve == cve }
        else -> error("kind $kind")
    }

    @Test
    fun everyLabelledCaseMatches() {
        val lines = File("../data/labels.tsv").readLines()
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .drop(1) // header
        val misses = lines.filter { line ->
            val c = line.split('\t')
            hit(c[0], c[1], c[2], c[3]) != (c[4] == "1")
        }
        assertEquals(75, lines.size)
        assertTrue("misses:\n" + misses.joinToString("\n"), misses.isEmpty())
    }

    @Test
    fun ruleCounts() {
        val c = m.counts()
        assertTrue(c[0] > 4000)
        assertTrue(c[1] > 500)
        assertTrue(c[2] > 5000)
        assertEquals(6, c[3])
    }

    @Test
    fun fullyPatchedDeviceHasNoPlatformFindings() {
        assertTrue(m.matchPlatform("14", "2099-01-01").isEmpty())
    }

    @Test
    fun badHeaderRejected() {
        try {
            KotlinMatcher("cve\tkind\n")
            error("expected rejection")
        } catch (e: IllegalArgumentException) {
            assertTrue(e.message!!.contains("header"))
        }
    }

    @Test
    fun batchedEqualsPerCall() {
        val pkgs = arrayOf("com.android.chrome", "com.example", "com.whatsapp", "com.google.android.webview")
        val vers = arrayOf("99.0.4844.88", "1.0", "2.18.200", "117.0.5938.153")
        val batched = m.matchApps(pkgs, vers)
        val perCall = pkgs.indices.flatMap { i -> m.matchApp(pkgs[i], vers[i]).map { AppHit(i, it) } }
        assertEquals(perCall, batched)
        assertTrue(batched.isNotEmpty())
    }
}

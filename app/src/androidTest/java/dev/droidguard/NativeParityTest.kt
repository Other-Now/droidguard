package dev.droidguard

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.droidguard.core.Flags
import dev.droidguard.core.KotlinMatcher
import dev.droidguard.core.NativeMatcher
import dev.droidguard.core.VersionCompare
import dev.droidguard.scan.Inventory
import dev.droidguard.scan.PostureChecks
import dev.droidguard.scan.Scanner
import org.junit.AfterClass
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The native core, loaded through JNI on a real Android runtime, must agree
 * with the Kotlin twin on everything: the labelled cases, every installed app,
 * and a sweep of releases x patch levels.
 */
@RunWith(AndroidJUnit4::class)
class NativeParityTest {
    companion object {
        private lateinit var native: NativeMatcher
        private lateinit var kotlin: KotlinMatcher

        @BeforeClass @JvmStatic fun load() {
            val ctx = InstrumentationRegistry.getInstrumentation().targetContext
            val bytes = Scanner.loadRules(ctx)
            native = NativeMatcher(bytes)
            kotlin = KotlinMatcher(String(bytes))
        }

        @AfterClass @JvmStatic fun free() = native.close()
    }

    @Test fun ruleCountsAgree() {
        assertArrayEquals(kotlin.counts(), native.counts())
    }

    @Test fun labelledCasesAllCorrectNatively() {
        val text = InstrumentationRegistry.getInstrumentation().context.assets
            .open("labels.tsv").bufferedReader().readText()
        val rows = text.lines().filter { it.isNotEmpty() && !it.startsWith("#") }.drop(1)
        val misses = rows.filter { line ->
            val c = line.split('\t')
            val got = when (c[0]) {
                "platform" -> native.matchPlatform(c[1], c[2]).any { it.cve == c[3] }
                "kernel" -> native.matchKernel(c[1], c[2]).any { it.cve == c[3] && Flags.kernelVulnerable(it.flags) }
                else -> native.matchApp(c[1], c[2]).any { it.cve == c[3] }
            }
            got != (c[4] == "1")
        }
        assertEquals(75, rows.size)
        assertTrue(misses.joinToString("\n"), misses.isEmpty())
    }

    @Test fun installedAppsAgree() {
        val pm = InstrumentationRegistry.getInstrumentation().targetContext.packageManager
        val apps = Inventory.collect(pm)
        val pkgs = apps.map { it.pkg }.toTypedArray()
        val vers = apps.map { it.versionName }.toTypedArray()
        assertEquals(kotlin.matchApps(pkgs, vers), native.matchApps(pkgs, vers))
        for (i in pkgs.indices) assertEquals(kotlin.matchApp(pkgs[i], vers[i]), native.matchApp(pkgs[i], vers[i]))
    }

    @Test fun releaseAndPatchLevelSweepAgrees() {
        val releases = listOf("8.0", "8.1", "9", "10", "11", "12", "12L", "13", "14", "15", "16", "17", "1", "")
        val spls = listOf("2020-01-01", "2021-06-05", "2022-12-01", "2023-09-05", "2024-06-01",
            "2025-03-05", "2026-09-01", "", "bogus")
        for (r in releases) for (s in spls) {
            assertEquals("$r $s", kotlin.matchPlatform(r, s), native.matchPlatform(r, s))
        }
        val kernels = listOf("4.9.190-perf", "4.14.99-g0", "4.19.75-android", "5.4.30", "5.10.43-android12-9",
            "5.15.137-android14-11-gabc", "6.1.75+", "6.6.30-android15", "")
        for (k in kernels) for (s in spls) {
            assertEquals("$k $s", kotlin.matchKernel(k, s), native.matchKernel(k, s))
        }
    }

    @Test fun thisDeviceAgrees() {
        val p = PostureChecks.collect(InstrumentationRegistry.getInstrumentation().targetContext.packageManager)
        assertEquals(kotlin.matchPlatform(p.release, p.spl), native.matchPlatform(p.release, p.spl))
        assertEquals(kotlin.matchKernel(p.kernel, p.kernelSpl), native.matchKernel(p.kernel, p.kernelSpl))
    }

    @Test fun versionCompareAgreesAcrossJni() {
        val vs = listOf("1.0", "1.0.0", "1.0rc1", "1.0~rc1", "1.0p2", "1.10", "1.9", "007", "7",
            "117.0.5938.60", "117.0.5938.132", "2:1.0", "1:9.9", "a", "", "4.14.99", "4.14.149",
            "99999999999999999999", "1.0-beta", "1.0.beta2")
        for (a in vs) for (b in vs) {
            assertEquals("$a vs $b", VersionCompare.compare(a, b), NativeMatcher.nativeCompare(a, b))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun nativeRejectsBadRulesWithJavaException() {
        NativeMatcher("not\ta\theader\n".toByteArray())
    }
}

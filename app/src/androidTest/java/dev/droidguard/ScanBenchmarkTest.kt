package dev.droidguard

import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.droidguard.core.KotlinMatcher
import dev.droidguard.core.NativeMatcher
import dev.droidguard.scan.Inventory
import dev.droidguard.scan.PostureChecks
import dev.droidguard.scan.Scanner
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Produces the numbers in results/. Prints one JSON line per section with tag
 * DGRESULT; CI collects them from logcat. Run against the release build
 * (-Pdg.testBuildType=release): a debuggable APK runs ART with JIT restrictions
 * that would make the Kotlin side look worse than it is. The `debuggable` field
 * records which one produced the numbers.
 */
@RunWith(AndroidJUnit4::class)
class ScanBenchmarkTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val debuggable = ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    private fun emit(section: String, o: JSONObject) {
        o.put("section", section).put("sdk", Build.VERSION.SDK_INT).put("abi", Build.SUPPORTED_ABIS[0])
            .put("debuggable", debuggable)
        // Logcat truncates long lines (~4 KB); the full scan report goes separately.
        Log.i("DGRESULT", o.toString())
    }

    /** Median wall time in microseconds of `f`, after warmup. */
    private fun medianUs(warmup: Int, runs: Int, f: () -> Unit): Double {
        repeat(warmup) { f() }
        val xs = DoubleArray(runs) {
            val s = SystemClock.elapsedRealtimeNanos()
            f()
            (SystemClock.elapsedRealtimeNanos() - s) / 1e3
        }
        xs.sort()
        return xs[runs / 2]
    }

    @Test fun fullScan() {
        val bytes = Scanner.loadRules(ctx)
        val loadUs = medianUs(2, 9) { NativeMatcher(bytes).close() }
        NativeMatcher(bytes).use { m ->
            val s = Scanner(ctx, m)
            val cold = s.scan()
            val runs = (1..9).map { s.scan() }
            val med = { k: String -> runs.map { it.timingsMs[k]!! }.sorted()[runs.size / 2] }
            emit("full_scan", JSONObject()
                .put("cold_total_ms", cold.timingsMs["total"])
                .put("median_total_ms", med("total"))
                .put("median_posture_ms", med("posture"))
                .put("median_inventory_ms", med("inventory"))
                .put("median_match_platform_ms", med("match_platform"))
                .put("median_match_kernel_ms", med("match_kernel"))
                .put("median_match_apps_ms", med("match_apps"))
                .put("rules_load_native_us", loadUs))
            val report = cold.toJson()
            Log.i("DGRESULT", JSONObject().put("section", "report_summary").put("sdk", Build.VERSION.SDK_INT)
                .put("device", report.getJSONObject("device"))
                .put("posture", report.getJSONObject("posture"))
                .put("summary", report.getJSONObject("summary")).toString())
            Log.i("DGRESULT", JSONObject().put("section", "report_apps").put("sdk", Build.VERSION.SDK_INT)
                .put("vulnerable_apps", report.getJSONArray("vulnerable_apps"))
                .put("debuggable_apps", report.getJSONArray("debuggable_apps")).toString())
        }
    }

    @Test fun matcherNativeVsKotlin() {
        val bytes = Scanner.loadRules(ctx)
        val apps = Inventory.collect(ctx.packageManager)
        val pkgs = apps.map { it.pkg }.toTypedArray()
        val vers = apps.map { it.versionName }.toTypedArray()
        val p = PostureChecks.collect(ctx.packageManager)

        val kotlinLoadUs = medianUs(2, 9) { KotlinMatcher(String(bytes)) }
        val k = KotlinMatcher(String(bytes))
        NativeMatcher(bytes).use { n ->
            val w = 20
            val r = 41
            val o = JSONObject()
                .put("apps", pkgs.size)
                .put("apps_with_alias", apps.count { it.pkg in ALIASED })
                .put("kotlin_load_us", kotlinLoadUs)
                .put("apps_kotlin_us", medianUs(w, r) { k.matchApps(pkgs, vers) })
                .put("apps_native_batched_us", medianUs(w, r) { n.matchApps(pkgs, vers) })
                .put("apps_native_percall_us", medianUs(w, r) {
                    for (i in pkgs.indices) n.matchApp(pkgs[i], vers[i])
                })
                .put("platform_kotlin_us", medianUs(w, r) { k.matchPlatform(p.release, "2020-01-01") })
                .put("platform_native_us", medianUs(w, r) { n.matchPlatform(p.release, "2020-01-01") })
                .put("kernel_kotlin_us", medianUs(w, r) { k.matchKernel(p.kernel, "2020-01-01") })
                .put("kernel_native_us", medianUs(w, r) { n.matchKernel(p.kernel, "2020-01-01") })
                // One app against all ~5.6k google:chrome rules: pure matcher work.
                .put("chrome_one_app_kotlin_us", medianUs(w, r) { k.matchApp("com.android.chrome", "99.0.4844.88") })
                .put("chrome_one_app_native_us", medianUs(w, r) { n.matchApp("com.android.chrome", "99.0.4844.88") })
                // Same scan over all ~5.6k chrome rules, but a version newer than every
                // fix: zero hits, so this is matching cost with no result marshalling.
                .put("chrome_nohit_kotlin_us", medianUs(w, r) { k.matchApp("com.android.chrome", "999.0") })
                .put("chrome_nohit_native_us", medianUs(w, r) { n.matchApp("com.android.chrome", "999.0") })
            // Crossing-cost floor: ns per no-op JNI call, from a tight loop.
            val calls = 200_000
            o.put("jni_noop_ns", medianUs(3, 11) { repeat(calls) { n.noop() } } * 1000 / calls)
            // Per-call cost for an app with no alias: two Strings in, an empty String[] out.
            o.put("jni_match_miss_ns",
                medianUs(3, 11) { repeat(10_000) { n.matchApp("com.example.none", "1.0") } } * 1000 / 10_000)
            o.put("kotlin_match_miss_ns",
                medianUs(3, 11) { repeat(10_000) { k.matchApp("com.example.none", "1.0") } } * 1000 / 10_000)
            emit("matcher_bench", o)
        }
    }

    /**
     * Profiling target only (tools/profile_native.sh passes -e dg.profile 1):
     * ~10 s of nothing but no-hit JNI calls, so simpleperf sees the per-call
     * overhead without the rest of the benchmark mixed in.
     */
    @Test fun jniMissLoop() {
        val args = InstrumentationRegistry.getArguments()
        org.junit.Assume.assumeTrue(args.getString("dg.profile") == "1")
        NativeMatcher(Scanner.loadRules(ctx)).use { n ->
            val end = SystemClock.elapsedRealtime() + 10_000
            while (SystemClock.elapsedRealtime() < end) repeat(10_000) { n.matchApp("com.example.none", "1.0") }
        }
    }

    companion object {
        val ALIASED = setOf("com.android.chrome", "com.google.android.webview", "com.android.webview",
            "org.mozilla.firefox", "com.whatsapp", "org.telegram.messenger")
    }
}

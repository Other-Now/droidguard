package dev.droidguard.scan

import android.content.Context
import android.os.SystemClock
import dev.droidguard.core.CveMatcher
import dev.droidguard.core.Flags
import dev.droidguard.core.Hit
import dev.droidguard.core.NativeMatcher
import org.json.JSONArray
import org.json.JSONObject

class ScanReport(
    val posture: Posture,
    val apps: List<AppRecord>,
    val platformHits: List<Hit>,
    val kernelHits: List<Hit>,
    val appHits: Map<String, List<Hit>>,
    val timingsMs: Map<String, Double>,
) {
    val kernelVulnerable get() = kernelHits.filter { Flags.kernelVulnerable(it.flags) }

    /** In range upstream, SPL says patched: the vendor backported the fix. */
    val kernelBackported
        get() = kernelHits.filter {
            it.flags and Flags.VERSION_IN_RANGE != 0 && it.flags and Flags.SPL_UNPATCHED == 0
        }

    val findingCount get() = platformHits.size + kernelVulnerable.size + appHits.values.sumOf { it.size }

    fun toJson(): JSONObject {
        val p = posture
        val third = apps.filter { !it.system }
        return JSONObject()
            .put("device", JSONObject()
                .put("sdk", p.sdkInt).put("release", p.release).put("spl", p.spl)
                .put("kernel_spl", p.kernelSpl).put("kernel", p.kernel))
            .put("posture", JSONObject()
                .put("selinux", p.selinux).put("selinux_evidence", p.selinuxEvidence)
                .put("verified_boot", p.verifiedBootState).put("device_locked", p.deviceLocked)
                .put("attestation_level", p.attestationLevel).put("build_type", p.buildType)
                .put("build_tags", p.buildTags).put("root_indicators", JSONArray(p.rootIndicators)))
            .put("summary", JSONObject()
                .put("findings", findingCount)
                .put("platform_cves", platformHits.size)
                .put("kernel_cves_vulnerable", kernelVulnerable.size)
                .put("kernel_cves_backported", kernelBackported.size)
                .put("kernel_cves_spl_only", kernelHits.count {
                    it.flags and Flags.SPL_UNPATCHED != 0 && !Flags.kernelVulnerable(it.flags)
                })
                .put("app_cves", appHits.values.sumOf { it.size })
                .put("apps_total", apps.size)
                .put("apps_third_party", third.size)
                .put("debuggable_apps", apps.count { it.debuggable })
                .put("apps_with_exported_unprotected", apps.count { it.exportedUnprotected.isNotEmpty() })
                .put("third_party_with_exported_unprotected", third.count { it.exportedUnprotected.isNotEmpty() })
                .put("apps_with_dangerous_grants", apps.count { it.dangerousGranted.isNotEmpty() }))
            .put("vulnerable_apps", JSONArray().apply {
                for ((pkg, hits) in appHits) {
                    if (hits.isEmpty()) continue
                    val rec = apps.first { it.pkg == pkg }
                    put(JSONObject().put("package", pkg).put("version", rec.versionName)
                        .put("cves", hits.size)
                        .put("critical", hits.count { it.severity == "Critical" })
                        .put("sample", JSONArray(hits.take(5).map { it.cve })))
                }
            })
            .put("debuggable_apps", JSONArray(apps.filter { it.debuggable }.map { it.pkg }))
            .put("timings_ms", JSONObject(timingsMs))
    }
}

/** One full scan: posture, inventory, then all three CVE matches. */
class Scanner(private val context: Context, private val matcher: CveMatcher) {

    fun scan(): ScanReport {
        val pm = context.packageManager
        val t = LinkedHashMap<String, Double>()
        fun <T> timed(name: String, f: () -> T): T {
            val s = SystemClock.elapsedRealtimeNanos()
            val r = f()
            t[name] = (SystemClock.elapsedRealtimeNanos() - s) / 1e6
            return r
        }
        val start = SystemClock.elapsedRealtimeNanos()
        val posture = timed("posture") { PostureChecks.collect(pm) }
        val apps = timed("inventory") { Inventory.collect(pm) }
        val platform = timed("match_platform") { matcher.matchPlatform(posture.release, posture.spl) }
        val kernel = timed("match_kernel") { matcher.matchKernel(posture.kernel, posture.kernelSpl) }
        val appHits = timed("match_apps") {
            val pkgs = apps.map { it.pkg }.toTypedArray()
            val vers = apps.map { it.versionName }.toTypedArray()
            matcher.matchApps(pkgs, vers).groupBy({ apps[it.index].pkg }, { it.hit })
        }
        t["total"] = (SystemClock.elapsedRealtimeNanos() - start) / 1e6
        return ScanReport(posture, apps, platform, kernel, appHits, t)
    }

    companion object {
        fun loadRules(context: Context): ByteArray =
            context.assets.open("rules.tsv").use { it.readBytes() }

        fun nativeMatcher(context: Context) = NativeMatcher(loadRules(context))
    }
}

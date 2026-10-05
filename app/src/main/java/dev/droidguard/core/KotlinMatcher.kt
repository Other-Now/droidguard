package dev.droidguard.core

/**
 * The matcher in plain Kotlin -- same rules file, same algorithm as
 * app/src/main/cpp/matcher.cpp. It exists to answer one question honestly:
 * is the native core worth a JNI boundary? (See ScanBenchmarkTest.)
 */
class KotlinMatcher(tsv: String) : CveMatcher {
    private class Rule(
        val cve: String, val target: String, val release: String, val fixedSpl: String,
        val si: String, val se: String, val ei: String, val ee: String, val severity: String,
    ) {
        val hasRange = si.isNotEmpty() || se.isNotEmpty() || ei.isNotEmpty() || ee.isNotEmpty()
    }

    private val platform = ArrayList<Rule>()
    private val kernel = ArrayList<Rule>()
    private val apps = HashMap<String, ArrayList<Rule>>()
    private val alias = HashMap<String, String>()

    init {
        var headerSeen = false
        for ((n, raw) in tsv.split('\n').withIndex()) {
            val line = raw.trimEnd('\r')
            if (line.isEmpty() || line[0] == '#') continue
            if (!headerSeen) {
                require(line == HEADER) { "unexpected rules header" }
                headerSeen = true
                continue
            }
            val c = line.split('\t')
            require(c.size == 10) { "rules line ${n + 1}: expected 10 columns" }
            if (c[0] == "alias") {
                alias[c[2]] = c[3]
                continue
            }
            val r = Rule(c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9])
            when (c[0]) {
                "platform" -> platform.add(r)
                "kernel" -> kernel.add(r)
                "app" -> apps.getOrPut(r.target) { ArrayList() }.add(r)
                else -> throw IllegalArgumentException("rules line ${n + 1}: unknown kind")
            }
        }
        require(headerSeen) { "rules are empty" }
    }

    override fun matchPlatform(release: String, spl: String): List<Hit> {
        if (!VersionCompare.validSpl(spl)) return emptyList()
        val seen = HashSet<String>()
        val out = ArrayList<Hit>()
        for (r in platform) {
            if (r.release != release || spl >= r.fixedSpl) continue
            if (seen.add(r.cve)) out.add(Hit(r.cve, r.target, r.severity, Flags.SPL_UNPATCHED))
        }
        return out
    }

    override fun matchKernel(uname: String, spl: String): List<Hit> {
        val v = VersionCompare.kernelUpstream(uname)
        val splOk = VersionCompare.validSpl(spl)
        val seen = HashSet<String>()
        val out = ArrayList<Hit>()
        var i = 0
        while (i < kernel.size) {
            val first = kernel[i]
            var flags = 0
            var anyRange = false
            var j = i
            while (j < kernel.size && kernel[j].cve == first.cve) {
                val r = kernel[j]
                if (r.hasRange) {
                    anyRange = true
                    if (v.isNotEmpty() && VersionCompare.inRange(v, r.si, r.se, r.ei, r.ee)) {
                        flags = flags or Flags.VERSION_IN_RANGE
                    }
                }
                j++
            }
            if (!anyRange) flags = flags or Flags.VERSION_UNKNOWN
            if (splOk && spl < first.fixedSpl) flags = flags or Flags.SPL_UNPATCHED
            if ((flags and (Flags.SPL_UNPATCHED or Flags.VERSION_IN_RANGE)) != 0 && seen.add(first.cve)) {
                out.add(Hit(first.cve, first.target, first.severity, flags))
            }
            i = j
        }
        return out
    }

    override fun matchApp(pkg: String, version: String): List<Hit> {
        if (version.isEmpty()) return emptyList()
        val product = alias[pkg] ?: return emptyList()
        val rules = apps[product] ?: return emptyList()
        val seen = HashSet<String>()
        val out = ArrayList<Hit>()
        for (r in rules) {
            if (!VersionCompare.inRange(version, r.si, r.se, r.ei, r.ee)) continue
            if (seen.add(r.cve)) out.add(Hit(r.cve, r.target, r.severity, 0))
        }
        return out
    }

    override fun matchApps(pkgs: Array<String>, versions: Array<String>): List<AppHit> {
        val out = ArrayList<AppHit>()
        for (i in pkgs.indices) for (h in matchApp(pkgs[i], versions[i])) out.add(AppHit(i, h))
        return out
    }

    override fun counts(): IntArray =
        intArrayOf(platform.size, kernel.size, apps.values.sumOf { it.size }, alias.size)

    companion object {
        const val HEADER =
            "kind\tcve\ttarget\trelease\tfixed_spl\tstart_incl\tstart_excl\tend_incl\tend_excl\tseverity"
    }
}

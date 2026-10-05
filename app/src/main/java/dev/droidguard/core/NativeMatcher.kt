package dev.droidguard.core

/**
 * The NDK matcher behind JNI. Owns a C++ dg::Matcher through an opaque handle;
 * call [close] (or use `use {}`) to free it.
 *
 * Results come back as tab-joined strings and are split here -- see the note at
 * the top of jni_bridge.cpp for why that beats building Java objects in C++.
 */
class NativeMatcher(tsv: ByteArray) : CveMatcher {
    private var handle: Long = nativeLoad(tsv)

    private fun live(): Long {
        check(handle != 0L) { "NativeMatcher is closed" }
        return handle
    }

    override fun matchPlatform(release: String, spl: String) =
        decode(nativeMatchPlatform(live(), release, spl))

    override fun matchKernel(uname: String, spl: String) =
        decode(nativeMatchKernel(live(), uname, spl))

    override fun matchApp(pkg: String, version: String) =
        decode(nativeMatchApp(live(), pkg, version))

    override fun matchApps(pkgs: Array<String>, versions: Array<String>): List<AppHit> {
        require(pkgs.size == versions.size)
        return nativeMatchApps(live(), pkgs, versions).map { row ->
            val tab = row.indexOf('\t')
            AppHit(row.substring(0, tab).toInt(), parse(row.substring(tab + 1)))
        }
    }

    override fun counts(): IntArray = nativeCounts(live())

    /** A JNI call that does no work: the crossing cost floor, for the benchmark. */
    fun noop(): Int = nativeNoop(handle)

    override fun close() {
        if (handle != 0L) {
            nativeFree(handle)
            handle = 0L
        }
    }

    private fun decode(rows: Array<String>): List<Hit> = rows.map(::parse)

    private fun parse(row: String): Hit {
        val c = row.split('\t')
        return Hit(c[0], c[1], c[2], c[3].toInt())
    }

    companion object {
        init {
            System.loadLibrary("droidguard")
        }

        @JvmStatic external fun nativeLoad(tsv: ByteArray): Long
        @JvmStatic external fun nativeFree(h: Long)
        @JvmStatic external fun nativeCounts(h: Long): IntArray
        @JvmStatic external fun nativeMatchPlatform(h: Long, release: String, spl: String): Array<String>
        @JvmStatic external fun nativeMatchKernel(h: Long, uname: String, spl: String): Array<String>
        @JvmStatic external fun nativeMatchApp(h: Long, pkg: String, version: String): Array<String>
        @JvmStatic external fun nativeMatchApps(h: Long, pkgs: Array<String>, versions: Array<String>): Array<String>
        @JvmStatic external fun nativeCompare(a: String, b: String): Int
        @JvmStatic external fun nativeNoop(h: Long): Int
    }
}

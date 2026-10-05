package dev.droidguard.core

/**
 * Line-for-line Kotlin port of app/src/main/cpp/vercmp.cpp (itself from
 * nano-sensor). Must stay behaviourally identical: the instrumented parity test
 * runs both over every installed app and a version sweep and fails on any
 * disagreement.
 */
object VersionCompare {
    private const val TILDE = 0
    private const val ALPHA = 1
    private const val NUMERIC = 2

    private class Token(val kind: Int, val text: String = "", val num: Long = 0)

    private val PRERELEASE = setOf("rc", "alpha", "beta", "pre", "dev", "preview", "snapshot", "nightly", "a1")

    private fun isDigit(c: Char) = c in '0'..'9'
    private fun isAlpha(c: Char) = c in 'a'..'z' || c in 'A'..'Z'

    private fun tokenize(v: String): List<Token> {
        val out = ArrayList<Token>()
        var i = 0
        while (i < v.length) {
            val c = v[i]
            when {
                c == '~' -> { out.add(Token(TILDE)); i++ }
                isDigit(c) -> {
                    var j = i
                    while (j < v.length && isDigit(v[j])) j++
                    val trimmed = v.substring(i, j).trimStart('0')
                    // Saturate like the C++ side; 18 digits always fits in a Long.
                    val value = when {
                        trimmed.isEmpty() -> 0L
                        trimmed.length > 18 -> Long.MAX_VALUE
                        else -> trimmed.toLong()
                    }
                    out.add(Token(NUMERIC, num = value))
                    i = j
                }
                isAlpha(c) -> {
                    var j = i
                    while (j < v.length && isAlpha(v[j])) j++
                    out.add(Token(ALPHA, text = v.substring(i, j).lowercase()))
                    i = j
                }
                else -> i++
            }
        }
        return out
    }

    private fun cmpToken(a: Token, b: Token): Int {
        if (a.kind != b.kind) return if (a.kind < b.kind) -1 else 1
        return when (a.kind) {
            ALPHA -> a.text.compareTo(b.text).coerceIn(-1, 1)
            NUMERIC -> a.num.compareTo(b.num)
            else -> 0
        }
    }

    private fun cmpRemainder(rest: List<Token>, from: Int): Int {
        if (from >= rest.size) return 0
        val next = rest[from]
        if (next.kind == TILDE) return -1
        if (next.kind == ALPHA && next.text in PRERELEASE) return -1
        return 1
    }

    private fun stripEpoch(v: String): Pair<Long, String> {
        val colon = v.indexOf(':')
        if (colon < 0) return 0L to v
        for (i in 0 until colon) if (!isDigit(v[i])) return 0L to v
        var epoch = 0L
        for (i in 0 until colon) epoch = epoch * 10 + (v[i] - '0')
        return epoch to v.substring(colon + 1)
    }

    fun compare(a0: String, b0: String): Int {
        val (ea, a) = stripEpoch(a0)
        val (eb, b) = stripEpoch(b0)
        if (ea != eb) return if (ea < eb) -1 else 1
        val ta = tokenize(a)
        val tb = tokenize(b)
        val n = minOf(ta.size, tb.size)
        for (i in 0 until n) {
            val c = cmpToken(ta[i], tb[i])
            if (c != 0) return c
        }
        if (ta.size > n) return cmpRemainder(ta, n)
        if (tb.size > n) return -cmpRemainder(tb, n)
        return 0
    }

    fun inRange(v: String, si: String, se: String, ei: String, ee: String): Boolean {
        if (si.isNotEmpty() && compare(v, si) < 0) return false
        if (se.isNotEmpty() && compare(v, se) <= 0) return false
        if (ei.isNotEmpty() && compare(v, ei) > 0) return false
        if (ee.isNotEmpty() && compare(v, ee) >= 0) return false
        return true
    }

    fun kernelUpstream(u: String): String {
        val cut = u.indexOfFirst { it == '-' || it == '+' }
        return if (cut < 0) u else u.substring(0, cut)
    }

    fun validSpl(s: String): Boolean {
        if (s.length != 10 || s[4] != '-' || s[7] != '-') return false
        for (i in intArrayOf(0, 1, 2, 3, 5, 6, 8, 9)) if (!isDigit(s[i])) return false
        return true
    }
}

package dev.droidguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Mirrors native-host/tests.cpp so both ports are held to the same cases. */
class VersionCompareTest {
    private fun cmp(a: String, b: String) = VersionCompare.compare(a, b)

    @Test fun numericNotLexical() {
        assertTrue(cmp("117.0.5938.60", "117.0.5938.132") < 0)
        assertTrue(cmp("99.0", "117.0") < 0)
        assertTrue(cmp("4.14.99", "4.14.149") < 0)
        assertTrue(cmp("1.10", "1.9") > 0)
    }

    @Test fun equalAndTrailing() {
        assertEquals(0, cmp("85.0", "85.0"))
        assertTrue(cmp("85.0.1", "85.0") > 0)
        assertEquals(0, cmp("007", "7"))
        assertTrue(cmp("1.0rc1", "1.0") < 0)
        assertTrue(cmp("1.0p2", "1.0") > 0)
        assertTrue(cmp("1.0~rc1", "1.0") < 0)
        assertTrue(cmp("2:1.0", "1:9.9") > 0)
    }

    @Test fun splValidation() {
        assertTrue(VersionCompare.validSpl("2024-03-05"))
        assertFalse(VersionCompare.validSpl(""))
        assertFalse(VersionCompare.validSpl("2024-3-5"))
        assertFalse(VersionCompare.validSpl("unknown"))
    }

    @Test fun kernelUpstream() {
        assertEquals("5.15.137", VersionCompare.kernelUpstream("5.15.137-android14-11-g2f1c"))
        assertEquals("6.1.75", VersionCompare.kernelUpstream("6.1.75+"))
        assertEquals("4.19.75", VersionCompare.kernelUpstream("4.19.75"))
    }
}

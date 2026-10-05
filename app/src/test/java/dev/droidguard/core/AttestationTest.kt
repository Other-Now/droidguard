package dev.droidguard.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream

/** Hand-built DER KeyDescriptions; covers the [704] high-tag-number encoding. */
class AttestationTest {
    private fun tlv(tag: ByteArray, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(tag)
        if (body.size < 0x80) o.write(body.size) else { o.write(0x82); o.write(body.size shr 8); o.write(body.size and 0xff) }
        o.write(body)
        return o.toByteArray()
    }
    private fun b(vararg x: Int) = ByteArray(x.size) { x[it].toByte() }
    private fun seq(vararg parts: ByteArray) = tlv(b(0x30), parts.fold(ByteArray(0)) { a, p -> a + p })
    private fun int(v: Int) = tlv(b(0x02), b(v))
    private fun enum(v: Int) = tlv(b(0x0a), b(v))
    private fun octets(vararg x: Int) = tlv(b(0x04), b(*x))

    // [704] EXPLICIT: context class, constructed, high tag 704 = 0x05 0x40 base-128.
    private fun rootOfTrust(locked: Boolean, state: Int) =
        tlv(b(0xbf, 0x85, 0x40), seq(octets(1, 2, 3), tlv(b(0x01), b(if (locked) 0xff else 0)), enum(state)))

    private fun keyDescription(level: Int, sw: ByteArray, hw: ByteArray) =
        seq(int(200), enum(level), int(200), enum(level), octets(9, 9), octets(), sw, hw)

    @Test fun hardwareRootOfTrust() {
        // [1] purpose, an unrelated low-tag item before RootOfTrust, must be skipped.
        val purpose = tlv(b(0xa1), tlv(b(0x31), int(2)))
        val ext = tlv(b(0x04), keyDescription(1, seq(), seq(purpose, rootOfTrust(true, 0))))
        val r = Attestation.parse(ext)
        assertEquals("TrustedEnvironment", r.securityLevel)
        assertEquals("Verified", r.verifiedBootState)
        assertEquals(true, r.deviceLocked)
        assertEquals("hardwareEnforced", r.rootOfTrustIn)
    }

    @Test fun softwareUnlockedDevice() {
        val r = Attestation.parse(tlv(b(0x04), keyDescription(0, seq(rootOfTrust(false, 2)), seq())))
        assertEquals("Software", r.securityLevel)
        assertEquals("Unverified", r.verifiedBootState)
        assertEquals(false, r.deviceLocked)
        assertEquals("softwareEnforced", r.rootOfTrustIn)
    }

    @Test fun noRootOfTrust() {
        val r = Attestation.parse(tlv(b(0x04), keyDescription(2, seq(), seq())))
        assertEquals("StrongBox", r.securityLevel)
        assertNull(r.verifiedBootState)
    }

    @Test(expected = IllegalArgumentException::class)
    fun truncatedInputRejected() {
        Attestation.parse(b(0x04, 0x10, 0x30, 0x01))
    }
}

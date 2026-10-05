package dev.droidguard.core

/**
 * Minimal parser for the Android key attestation extension
 * (OID 1.3.6.1.4.1.11129.2.1.17), enough to pull out RootOfTrust.
 *
 * Why this exists: an untrusted app cannot read ro.boot.verifiedbootstate or
 * ro.boot.flash.locked -- property_contexts hides them, and getprop just prints
 * an empty line. The supported way for an app to learn the boot state is to ask
 * Keystore for an attested key: the attestation certificate carries a
 * RootOfTrust that the TEE (or, on emulators, the software keymaster) filled in.
 *
 *   KeyDescription ::= SEQUENCE {
 *     attestationVersion INTEGER, attestationSecurityLevel ENUMERATED,
 *     keyMintVersion INTEGER, keyMintSecurityLevel ENUMERATED,
 *     attestationChallenge OCTET STRING, uniqueId OCTET STRING,
 *     softwareEnforced AuthorizationList, hardwareEnforced AuthorizationList }
 *   AuthorizationList ::= SEQUENCE { ... rootOfTrust [704] EXPLICIT RootOfTrust ... }
 *   RootOfTrust ::= SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN,
 *                              verifiedBootState ENUMERATED, ... }
 */
object Attestation {
    data class Result(
        val securityLevel: String,      // Software / TrustedEnvironment / StrongBox
        val verifiedBootState: String?, // Verified / SelfSigned / Unverified / Failed, null if absent
        val deviceLocked: Boolean?,
        val rootOfTrustIn: String?,     // which AuthorizationList carried it
    )

    private const val TAG_ROOT_OF_TRUST = 704

    private class Tlv(val cls: Int, val constructed: Boolean, val tag: Int, val body: ByteArray)

    /** Parses consecutive DER TLVs in `b`. Throws on malformed input. */
    private fun parseAll(b: ByteArray): List<Tlv> {
        val out = ArrayList<Tlv>()
        var i = 0
        while (i < b.size) {
            val first = b[i++].toInt() and 0xff
            val cls = first shr 6
            val constructed = first and 0x20 != 0
            var tag = first and 0x1f
            if (tag == 0x1f) { // high tag number form: base-128, MSB = continue
                tag = 0
                do {
                    val x = b[i++].toInt() and 0xff
                    tag = (tag shl 7) or (x and 0x7f)
                } while (x and 0x80 != 0)
            }
            var len = b[i++].toInt() and 0xff
            if (len and 0x80 != 0) {
                val n = len and 0x7f
                require(n in 1..3) { "unsupported DER length" }
                len = 0
                repeat(n) { len = (len shl 8) or (b[i++].toInt() and 0xff) }
            }
            require(i + len <= b.size) { "DER overrun" }
            out.add(Tlv(cls, constructed, tag, b.copyOfRange(i, i + len)))
            i += len
        }
        return out
    }

    private fun intValue(t: Tlv): Int = t.body.fold(0) { acc, x -> (acc shl 8) or (x.toInt() and 0xff) }

    private fun level(n: Int) = when (n) {
        0 -> "Software"; 1 -> "TrustedEnvironment"; 2 -> "StrongBox"; else -> "unknown($n)"
    }

    private fun bootState(n: Int) = when (n) {
        0 -> "Verified"; 1 -> "SelfSigned"; 2 -> "Unverified"; 3 -> "Failed"; else -> "unknown($n)"
    }

    /** `ext` = the raw extension value as X509Certificate.getExtensionValue returns it. */
    fun parse(ext: ByteArray): Result {
        // getExtensionValue wraps the DER in one more OCTET STRING.
        val outer = parseAll(ext).single()
        val der = if (outer.cls == 0 && outer.tag == 4) outer.body else ext
        val seq = parseAll(der).single()
        val f = parseAll(seq.body)
        require(f.size >= 8) { "short KeyDescription" }
        val lists = listOf("softwareEnforced" to f[6], "hardwareEnforced" to f[7])
        for ((name, list) in lists) {
            for (item in parseAll(list.body)) {
                if (item.cls != 2 || item.tag != TAG_ROOT_OF_TRUST) continue
                val rot = parseAll(parseAll(item.body).single().body)
                return Result(level(intValue(f[1])), bootState(intValue(rot[2])),
                    rot[1].body.firstOrNull()?.let { it.toInt() != 0 }, name)
            }
        }
        return Result(level(intValue(f[1])), null, null, null)
    }
}

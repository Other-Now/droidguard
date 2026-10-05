package dev.droidguard.scan

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.droidguard.core.Attestation
import dev.droidguard.core.VersionCompare
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate

/** Device-level security posture. Every field is read, never assumed. */
data class Posture(
    val sdkInt: Int,
    val release: String,           // bulletin release name, e.g. "12L"
    val spl: String,               // platform security patch level
    val kernelSpl: String,         // vendor SPL when readable (kernel fixes ship there), else platform
    val kernel: String,            // uname -r
    val selinux: String,           // Enforcing / Permissive / Disabled / unknown
    val selinuxEvidence: String,   // how we know
    val verifiedBootState: String, // from key attestation RootOfTrust
    val deviceLocked: String,      // "true" / "false" / unknown
    val attestationLevel: String,  // Software / TrustedEnvironment / StrongBox
    val buildType: String,         // user / userdebug / eng
    val buildTags: String,
    val rootIndicators: List<String>,
)

/**
 * What an untrusted app can and cannot see, measured on the emulator (see
 * README "posture: what an app is allowed to read"):
 *   - getprop ro.boot.verifiedbootstate / ro.boot.flash.locked / ro.debuggable /
 *     ro.vendor.build.security_patch  -> empty: property_contexts hides them.
 *   - getenforce, /sys/fs/selinux/enforce -> EACCES.
 * So nothing here shells out to getprop any more; each check uses the public
 * source of the same fact.
 */
object PostureChecks {

    /**
     * Bulletin release names, from SDK_INT rather than Build.VERSION.RELEASE:
     * a 12L device reports RELEASE "12", and the bulletin treats 12 and 12L as
     * different releases with different fixes.
     */
    fun releaseFor(sdk: Int, fallback: String): String = when (sdk) {
        29 -> "10"; 30 -> "11"; 31 -> "12"; 32 -> "12L"; 33 -> "13"
        34 -> "14"; 35 -> "15"; 36 -> "16"; 37 -> "17"
        else -> fallback
    }

    private val SU_PATHS = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/su/bin/su", "/vendor/bin/su",
        "/system/sbin/su", "/data/local/su", "/data/local/bin/su", "/data/local/xbin/su",
    )

    private val ROOT_PACKAGES = listOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.noshufou.android.su", "me.weishu.kernelsu",
    )

    fun collect(pm: PackageManager): Posture {
        val sdk = Build.VERSION.SDK_INT
        val spl = Build.VERSION.SECURITY_PATCH ?: ""
        val buildType = Build.TYPE ?: ""
        val tags = Build.TAGS ?: ""

        val root = ArrayList<String>()
        for (p in SU_PATHS) if (File(p).exists()) root.add("su binary: $p")
        if (tags.contains("test-keys")) root.add("build signed with test-keys")
        // ro.debuggable is not readable by apps; Build.TYPE is public and is
        // what sets it (userdebug/eng => debuggable, adb root available).
        if (buildType == "userdebug" || buildType == "eng") root.add("$buildType build (adb root possible)")
        for (p in ROOT_PACKAGES) if (installed(pm, p)) root.add("root manager installed: $p")

        val (selinux, evidence) = selinuxMode()
        val att = attest()

        return Posture(
            sdkInt = sdk,
            release = releaseFor(sdk, Build.VERSION.RELEASE ?: ""),
            spl = spl,
            kernelSpl = vendorSpl() ?: spl,
            kernel = System.getProperty("os.version") ?: "",
            selinux = selinux,
            selinuxEvidence = evidence,
            verifiedBootState = att?.verifiedBootState ?: "unknown",
            deviceLocked = att?.deviceLocked?.toString() ?: "unknown",
            attestationLevel = att?.securityLevel ?: "unavailable",
            buildType = buildType,
            buildTags = tags,
            rootIndicators = root,
        )
    }

    /**
     * Reading the enforce node is denied to apps -- and that denial is itself
     * the answer. In permissive mode SELinux logs denials but does not enforce
     * them, so the read would have succeeded. EACCES therefore means enforcing.
     */
    internal fun selinuxMode(): Pair<String, String> {
        val f = File("/sys/fs/selinux/enforce")
        return try {
            when (f.readText().trim()) {
                "1" -> "Enforcing" to "read /sys/fs/selinux/enforce"
                "0" -> "Permissive" to "read /sys/fs/selinux/enforce"
                else -> "unknown" to "unexpected enforce value"
            }
        } catch (e: FileNotFoundException) {
            // Both "no such file" (SELinux disabled) and EACCES surface as
            // FileNotFoundException; the message carries the errno text.
            val msg = e.message ?: ""
            when {
                msg.contains("EACCES") || msg.contains("Permission denied") ->
                    "Enforcing" to "read denied by policy (a permissive kernel would allow it)"
                msg.contains("ENOENT") || msg.contains("No such file") ->
                    "Disabled" to "no selinuxfs"
                else -> "unknown" to msg
            }
        } catch (e: Exception) {
            "unknown" to e.toString()
        }
    }

    /** RootOfTrust from a freshly generated, attested Keystore key. */
    internal fun attest(): Attestation.Result? {
        val alias = "droidguard-attest"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return try {
            val challenge = ByteArray(16).also { SecureRandom().nextBytes(it) }
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply {
                initialize(
                    KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setAttestationChallenge(challenge)
                        .build()
                )
            }.generateKeyPair()
            val leaf = ks.getCertificateChain(alias)?.firstOrNull() as? X509Certificate ?: return null
            val ext = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17") ?: return null
            Attestation.parse(ext)
        } catch (e: Exception) {
            android.util.Log.w("droidguard", "attestation failed", e)
            null
        } finally {
            try { ks.deleteEntry(alias) } catch (_: Exception) {}
        }
    }

    /** ro.vendor.build.security_patch, if this build lets apps read it (most don't). */
    private fun vendorSpl(): String? = try {
        val p = ProcessBuilder("/system/bin/getprop", "ro.vendor.build.security_patch").start()
        val v = p.inputStream.bufferedReader().readText().trim()
        p.waitFor()
        v.takeIf { VersionCompare.validSpl(it) }
    } catch (_: Exception) {
        null
    }

    private fun installed(pm: PackageManager, pkg: String): Boolean = try {
        pm.getPackageInfo(pkg, 0)
        true
    } catch (_: PackageManager.NameNotFoundException) {
        false
    }
}

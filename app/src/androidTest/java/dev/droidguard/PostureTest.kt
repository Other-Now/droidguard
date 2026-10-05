package dev.droidguard

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.droidguard.core.VersionCompare
import dev.droidguard.scan.Inventory
import dev.droidguard.scan.PostureChecks
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Posture and inventory produce sane, device-consistent values on any API level. */
@RunWith(AndroidJUnit4::class)
class PostureTest {
    private val ctx = InstrumentationRegistry.getInstrumentation().targetContext
    private val p = PostureChecks.collect(ctx.packageManager)

    @Test fun patchLevelsAreWellFormed() {
        assertTrue(p.spl, VersionCompare.validSpl(p.spl))
        assertTrue(p.kernelSpl, VersionCompare.validSpl(p.kernelSpl))
    }

    @Test fun releaseComesFromSdkInt() {
        assertEquals(Build.VERSION.SDK_INT, p.sdkInt)
        assertEquals(PostureChecks.releaseFor(Build.VERSION.SDK_INT, "x"), p.release)
        if (Build.VERSION.SDK_INT == 32) assertEquals("12L", p.release)
    }

    @Test fun kernelVersionParses() {
        val upstream = VersionCompare.kernelUpstream(p.kernel)
        assertTrue(p.kernel, Regex("""\d+\.\d+(\.\d+)?""").matches(upstream))
    }

    @Test fun selinuxIsEnforcingOnStockImages() {
        // Every emulator image we test ships enforcing; "unknown" would mean the
        // inference from the denied read broke.
        assertEquals(p.selinuxEvidence, "Enforcing", p.selinux)
    }

    @Test fun attestationProducesARootOfTrust() {
        // The emulator's keymaster is software, so the level is "Software" there;
        // a phone reports TrustedEnvironment or StrongBox.
        assertTrue(p.attestationLevel, p.attestationLevel in setOf("Software", "TrustedEnvironment", "StrongBox"))
        assertTrue(p.verifiedBootState, p.verifiedBootState in setOf("Verified", "SelfSigned", "Unverified", "Failed", "unknown"))
    }

    @Test fun debuggableBuildIsARootIndicator() {
        val dbg = Build.TYPE == "userdebug" || Build.TYPE == "eng"
        assertEquals(p.rootIndicators.toString(), dbg, p.rootIndicators.any { it.contains("build (adb root") })
    }

    @Test fun inventorySeesTheWholeDevice() {
        val apps = Inventory.collect(ctx.packageManager)
        // Without QUERY_ALL_PACKAGES, Android 11+ would show only a handful.
        assertTrue("only ${apps.size} apps visible", apps.size > 50)
        assertTrue(apps.any { it.pkg == "android" && it.system })
    }

    @Test fun droidguardDoesNotFlagItself() {
        val me = Inventory.collect(ctx.packageManager).first { it.pkg == ctx.packageName }
        // MainActivity is the launcher (excluded); ScanService is exported but
        // signature-protected, so neither should appear.
        assertTrue(me.exportedUnprotected.toString(), me.exportedUnprotected.isEmpty())
    }
}

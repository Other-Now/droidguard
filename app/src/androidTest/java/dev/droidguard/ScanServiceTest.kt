package dev.droidguard

import android.content.Intent
import android.os.Process
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.rule.ServiceTestRule
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** The AIDL surface, called across a real process boundary. */
@RunWith(AndroidJUnit4::class)
class ScanServiceTest {
    @get:Rule val rule = ServiceTestRule()

    private fun bind(): IScanService {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        return IScanService.Stub.asInterface(rule.bindService(Intent(ctx, ScanService::class.java)))
    }

    @Test fun serviceRunsInItsOwnProcess() {
        assertNotEquals(Process.myPid(), bind().servicePid())
    }

    @Test fun scanOverBinderReturnsAReport() {
        val s = bind()
        val json = JSONObject(s.runScan())
        val summary = json.getJSONObject("summary")
        assertTrue(summary.getInt("apps_total") > 50)
        assertEquals(summary.getInt("findings"), s.lastFindingCount())
        assertTrue(json.getJSONObject("timings_ms").getDouble("total") > 0)
    }

    @Test fun ruleCountsCrossTheBoundary() {
        val c = bind().ruleCounts()
        assertEquals(4, c.size)
        assertTrue(c[0] > 4000 && c[1] > 500 && c[2] > 5000 && c[3] == 6)
    }
}

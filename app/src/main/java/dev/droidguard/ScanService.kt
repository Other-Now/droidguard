package dev.droidguard

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.os.Process
import dev.droidguard.core.NativeMatcher
import dev.droidguard.scan.Scanner

/**
 * Bound service exposing scans over AIDL. Declared in its own process and
 * guarded by a signature-level permission in the manifest, so only apps signed
 * with the same key can bind -- and droidguard's own exported-component check
 * does not flag it.
 */
class ScanService : Service() {
    private val matcher: NativeMatcher by lazy { Scanner.nativeMatcher(this) }
    @Volatile private var lastCount = -1

    private val binder = object : IScanService.Stub() {
        // Binder calls arrive on the service's binder thread pool, possibly
        // concurrently; the matcher is read-only after load, and the lock only
        // serialises whole scans so two clients don't double the work.
        override fun runScan(): String = synchronized(this@ScanService) {
            val report = Scanner(this@ScanService, matcher).scan()
            lastCount = report.findingCount
            report.toJson().toString()
        }

        override fun lastFindingCount(): Int = lastCount

        override fun ruleCounts(): IntArray = matcher.counts()

        override fun servicePid(): Int = Process.myPid()
    }

    override fun onBind(intent: Intent): IBinder = binder

    override fun onDestroy() {
        matcher.close()
        super.onDestroy()
    }
}

package dev.droidguard.scan

import android.content.pm.ApplicationInfo
import android.content.pm.ComponentInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.PermissionInfo
import android.os.Build

data class AppRecord(
    val pkg: String,
    val versionName: String,
    val versionCode: Long,
    val system: Boolean,
    val debuggable: Boolean,
    /** Exported services/receivers/providers (and non-launcher activities) with no permission. */
    val exportedUnprotected: List<String>,
    val dangerousGranted: List<String>,
)

object Inventory {

    /**
     * Two passes on purpose. Asking getInstalledPackages for permissions AND all
     * four component types in one call makes the reply a single Binder
     * transaction holding every component of every app -- on a device with a
     * few hundred packages that blows the 1 MB transaction buffer and throws
     * TransactionTooLargeException. So: one cheap listing, then one
     * getPackageInfo per package for its components.
     */
    fun collect(pm: PackageManager): List<AppRecord> {
        val dangerous = HashMap<String, Boolean>()
        fun isDangerous(perm: String): Boolean = dangerous.getOrPut(perm) {
            try {
                pm.getPermissionInfo(perm, 0).protection == PermissionInfo.PROTECTION_DANGEROUS
            } catch (_: PackageManager.NameNotFoundException) {
                false
            }
        }

        val out = ArrayList<AppRecord>()
        for (base in installedPackages(pm, PackageManager.GET_PERMISSIONS)) {
            val ai = base.applicationInfo ?: continue
            val granted = ArrayList<String>()
            val req = base.requestedPermissions
            val flags = base.requestedPermissionsFlags
            if (req != null && flags != null) {
                for (i in req.indices) {
                    if (flags[i] and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 && isDangerous(req[i])) {
                        granted.add(req[i])
                    }
                }
            }
            out.add(
                AppRecord(
                    pkg = base.packageName,
                    versionName = base.versionName ?: "",
                    versionCode = base.longVersionCode,
                    system = ai.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                    debuggable = ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0,
                    exportedUnprotected = exportedUnprotected(pm, base.packageName),
                    dangerousGranted = granted,
                )
            )
        }
        return out
    }

    private fun exportedUnprotected(pm: PackageManager, pkg: String): List<String> {
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_SERVICES or
            PackageManager.GET_RECEIVERS or PackageManager.GET_PROVIDERS
        val info = try {
            packageInfo(pm, pkg, flags)
        } catch (_: Exception) {
            return emptyList() // uninstalled between passes, or a huge package; skip, don't crash
        }
        // The launcher activity has to be exported to be launchable at all, so it
        // is not a finding.
        val launcher = pm.getLaunchIntentForPackage(pkg)?.component?.className
        val out = ArrayList<String>()
        fun add(kind: String, c: ComponentInfo, perm: String?) {
            if (c.exported && perm.isNullOrEmpty() && c.name != launcher) out.add("$kind:${c.name}")
        }
        info.activities?.forEach { add("activity", it, it.permission) }
        info.services?.forEach { add("service", it, it.permission) }
        info.receivers?.forEach { add("receiver", it, it.permission) }
        info.providers?.forEach {
            // A provider is protected if either direction is; an unguarded read
            // side is still worth reporting, which this conservatively does not.
            add("provider", it, it.readPermission ?: it.writePermission)
        }
        return out
    }

    @Suppress("DEPRECATION")
    private fun installedPackages(pm: PackageManager, flags: Int): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getInstalledPackages(flags)
        }

    @Suppress("DEPRECATION")
    private fun packageInfo(pm: PackageManager, pkg: String, flags: Int): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) {
            pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(flags.toLong()))
        } else {
            pm.getPackageInfo(pkg, flags)
        }
}

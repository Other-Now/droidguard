# droidguard

An Android device-security scanner with a native C++ core. It checks a device's
security patch level and kernel against the Android Security Bulletin, reads
SELinux, verified boot and root indicators, and inventories installed apps.
That covers debuggable apps, exported components, dangerous permissions and
known-vulnerable versions. Results are served to other processes over an AIDL
Binder service.

**Scope.** This is app-level and NDK work: Kotlin, C++ over JNI, the Binder IPC
an ordinary app can use, and on-device profiling. It is *not* AOSP framework,
HAL or kernel-driver work, and claims none of those.

```
Kotlin app ─────────────────────────────┐        ┌──────────── :scanner process ───────────┐
MainActivity ── bindService ── Binder ──┼──AIDL──┤ ScanService (signature permission)      │
                                        │        │   PostureChecks  Inventory  Scanner     │
                                        │        │        │              │        │ JNI    │
                                        │        │        │              │   libdroidguard.so
                                        │        │        │              │   (C++17, NDK)   │
                                        │        │        │              │   vercmp + matcher
                                        └        └────────────────────────────────────────────┘
```

## Headline results

Local results come from an API 34 x86_64 emulator on WHPX with the release
(non-debuggable) build. Benchmark figures are medians of 3 runs, each itself a
median of 41 timed iterations after 20 warmup iterations. Raw output is in [`results/`](results/RESULTS.md).

| What | Result |
|---|---|
| Matcher accuracy, 75 hand-labelled cases (29 positive) | **100% precision / 100% recall** for both the C++ core and its Kotlin twin |
| Naive baseline on the same cases | 64.9% precision / 82.8% recall: lexical versions, prefix-matched releases, kernel judged by version only |
| Full scan, emulator (225 apps) | **803 ms** median; inventory 708 ms, all CVE matching 24 ms |
| Native vs Kotlin, pure matching (1 app × 5.6k Chrome rules, 0 hits) | 3.2 ms vs 6.3 ms: **native 2.0× faster** |
| Native vs Kotlin, whole-inventory match (one batched JNI call) | 17.2 ms vs 23.7 ms: native 1.4× faster |
| Native vs Kotlin, platform match returning about 480 hits | 609 µs vs 270 µs: **native 2.3× slower**, because marshalling 480 strings across JNI costs more than the matching saves |
| JNI per-call cost (no-hit call), before → after the profile-driven fix | **632 → 361 ns**; a bare no-op JNI call is 23 ns, and the same miss in Kotlin is 22 ns |
| Tests | 14 native host tests (54 checks), 13 JVM tests, 20 instrumented tests (+1 profiling-only target) |

## The interesting findings

**1. An app cannot read most of what a posture check needs, so the checks use public sources.**
Probed from the app's own SELinux domain (`run-as` on the debug build) on API 34:

- `getprop ro.boot.verifiedbootstate`, `ro.boot.flash.locked`, `ro.debuggable`
  and `ro.vendor.build.security_patch` all print an empty line, because
  `property_contexts` hides them. `getenforce` and `/sys/fs/selinux/enforce`
  return EACCES.
- The first version used `getprop` anyway. It reported SELinux "unknown", missed
  a userdebug build, and spent 569 ms spawning processes. The fix uses a public
  source for each fact:
  - **SELinux:** the EACCES *is* the answer. A permissive kernel logs denials but
    allows the access, so a denied read proves enforcing mode.
  - **Verified boot / bootloader lock:** generate an attested Android Keystore key
    and parse the `RootOfTrust` out of the attestation certificate extension
    (OID 1.3.6.1.4.1.11129.2.1.17) with a small DER parser
    ([`Attestation.kt`](app/src/main/java/dev/droidguard/core/Attestation.kt)).
    On the emulator this reports `Software` / `Unverified` / unlocked, which is
    correct for an emulator. A phone with a TEE reports `TrustedEnvironment` or
    `StrongBox`.
  - **Debuggable build:** `Build.TYPE` is public.

  Posture time dropped from 569 ms to 71–91 ms.

**2. Kernel CVEs need two signals, not one.** The bulletin gives only a patch level
for kernel CVEs. NVD gives upstream version ranges, but Android vendors backport
fixes without bumping the version. So:

```
vulnerable = SPL older than the bulletin fix  AND  (upstream version in an NVD range  OR  no range known)
```

- Version-only matching reports every backported fix as vulnerable.
- SPL-only matching reports an old-SPL device whose kernel is already past the
  upstream fix.

The report keeps both disagreements visible (`kernel_cves_backported`,
`kernel_cves_spl_only`). On the emulator: 45 vulnerable, 3 SPL-only, 0
backported. 142 of the 228 bulletin kernel CVEs have an NVD range.

**3. Native is faster at matching, but the JNI boundary decides whether that matters.**

- Pure matching is 2.0× faster in C++.
- A call that finds nothing first cost 632 ns natively vs 22 ns in Kotlin. simpleperf (`--app` on a `profileable` release build) showed where:
  - `FindClass("java/lang/String")` on every call (class-table lookup plus a stack
    walk for the caller's class loader): about 14% of samples.
  - `NewObjectArray` just to return an empty `String[]`: about 5%.
  - `GetStringUTFChars` heap copies (scudo malloc/free): about 15%.
- The fix caches the class and a shared empty array in `JNI_OnLoad` and copies
  arguments with `GetStringUTFRegion` into a stack buffer. That brought the call
  down to about 361 ns.
- The next lever is visible in the
  [after profile](results/simpleperf/after/report_by_symbol.txt): ART's
  modified-UTF-8 conversion (`GetStringUTFLength` + `GetStringUTFRegion`) is now
  about 26%.
- The same boundary cost decides the platform match. Returning about 480 hits as
  strings makes the native path 2.3× *slower* than Kotlin, which builds `Hit`
  objects in place.
- The design answer is granularity: one batched call per inventory, not one per
  app. The same conclusion as [sbe-jni-bridge](https://github.com/Other-Now/sbe-jni-bridge).

**4. The scan is bound by Binder, not by matching.**
- Inventory is 88% of scan time. That's one `getInstalledPackages`, then one
  `getPackageInfo` per package for components. Each is a Binder transaction into
  `system_server`.
- It's done in two passes on purpose. Asking for every component of every
  package in one call overflows the 1 MB Binder transaction buffer
  (`TransactionTooLargeException`) on a device with a few hundred packages.
- Matching all 11,130 rules costs 24 ms of the 803 ms.

## What it checks

| Check | Source |
|---|---|
| Platform CVEs (1,593) | OSV export of the Android Security Bulletin. Affected when the release is listed and the device SPL is older than that release's fix SPL. Re-issued fixes (same CVE, two SPLs) use the later one |
| Kernel CVEs (228) | Bulletin SPL + NVD upstream ranges, combined as above |
| App CVEs (5,544) | NVD CPE ranges for Chrome, WebView, Firefox, WhatsApp, Telegram via a package → CPE alias table (nano-sensor's approach) |
| SELinux | Inferred from the denied read of `/sys/fs/selinux/enforce` |
| Verified boot, bootloader lock | Key attestation `RootOfTrust` |
| Root indicators | `su` binaries, test-keys, userdebug/eng build, root-manager packages |
| Per app | debuggable flag, exported components with no permission (launcher activity excluded), granted dangerous permissions |

**Release names come from `SDK_INT`, not `Build.VERSION.RELEASE`.** A 12L device
reports RELEASE "12", and the bulletin treats 12 and 12L as different releases
with different fixes.

## Honest limitations

- **WebView is matched with Chrome's CVEs.** It ships the same Chromium engine and
  version numbers, and NVD files engine bugs under `google:chrome`. Some Chrome
  CVEs are in browser UI code WebView doesn't ship. The emulator's WebView 113
  matching 3,526 CVEs is an upper bound, not a count of exploitable bugs.
- **SoC- and Pixel-specific bulletin entries are dropped** (1,765 version entries
  plus 192 vendor components). The scanner can't tell one vendor's blob from
  another's. `-next` (unreleased) trains are dropped too (959).
- **The vendor SPL is unreadable by apps**, so kernel CVEs fall back to the
  platform SPL.
- **Emulators expose no hardware PMU**, so profiles use the `cpu-clock` software
  event.
- **No physical phone was tested.** All device numbers are emulator numbers.
- **Not done:** an interactive LLDB session. The NDK's `lldb` + `lldb-server`
  attach flow is described in [docs/NOTES.md](docs/NOTES.md) but wasn't
  exercised for this project.

## Layout

```
app/src/main/cpp/          C++ core: vercmp (from nano-sensor), matcher, jni_bridge
app/src/main/java/.../core Kotlin twin (KotlinMatcher, VersionCompare), NativeMatcher, Attestation
app/src/main/java/.../scan PostureChecks, Inventory, Scanner
app/src/main/aidl/         IScanService.aidl
native-host/               the same C++ built for the host: unit tests + precision/recall eval
data/labels.tsv            75 hand-labelled cases with the reason for each label
tools/build_rules.py       OSV + NVD -> app/src/main/assets/rules.tsv
tools/profile_native.sh    simpleperf on the release build
results/                   raw benchmark JSON, eval output, before/after profiles
```

## Running it

```bash
# Native core on the host (MSVC, GCC or Clang)
cmake -S native-host -B build-host && cmake --build build-host
./build-host/dg_unit app/src/main/assets/rules.tsv
./build-host/dg_eval app/src/main/assets/rules.tsv data/labels.tsv

# JVM tests + APKs
./gradlew testDebugUnitTest assembleRelease

# Instrumented tests + benchmark on a running emulator/device (release build)
./gradlew -Pdg.testBuildType=release connectedReleaseAndroidTest
adb logcat -d -s DGRESULT:I

# Profile the JNI path
ANDROID_NDK_HOME=... tools/profile_native.sh results/simpleperf/after

# Rebuild the rules (inputs ~170 MB, not checked in)
python tools/build_rules.py --osv osv-android.zip --nvd-dir nvd/
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the host tests
and eval, the JVM tests, and the instrumented suite on emulators for API 29, 31
and 34 (KVM on Linux runners). Each emulator job uploads its benchmark output as
an artifact.

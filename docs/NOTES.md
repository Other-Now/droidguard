# Interview notes: droidguard

A one-sitting study sheet. Every number here is in `results/`.

## 30-second pitch

An Android security scanner with a C++ core. It matches the device's patch
level, kernel and installed apps against the Android Security Bulletin and NVD:
11k rules, 75 hand-labelled cases, 100% vs 65% precision for a naive matcher. It
checks SELinux, verified boot and root, exposes results over an AIDL Binder
service in a separate process, and runs instrumented tests on emulators in CI.
The two things I learned:

- Most posture signals are hidden from apps, so you have to use the public
  sources.
- The JNI boundary, not the C++, decides whether native is worth it. I profiled
  it with simpleperf and cut per-call cost from 632 ns to 361 ns.

## Likely questions

**Why C++ at all?**
It's reuse of nano-sensor's version comparator, and it's 2× faster at pure
matching. But the scan takes 803 ms and matching is 24 ms of it. Inventory over
Binder is 88%. Honest answer: native doesn't change the user-visible time; it
would matter with a much larger rule set or on-device fuzzy matching.

**What does a JNI call cost, and where did it go?**
- A bare call is about 23 ns.
- A no-hit `matchApp` cost 632 ns. simpleperf `--app` on the `profileable`
  release build showed:
  - `FindClass("java/lang/String")` every call: class-table lookup, plus a
    stack walk to find the calling class loader.
  - `NewObjectArray` for an empty result.
  - `GetStringUTFChars` mallocing a copy.
- The fix:
  - cache a global ref to the class, plus a shared empty `String[0]`, in
    `JNI_OnLoad`;
  - `GetStringUTFRegion` into a stack buffer.
- Result: 361 ns. What remains is ART's modified-UTF-8 conversion. The next step
  would be passing `byte[]`/direct buffers, or batching more.

**Why is the native platform match slower than Kotlin?**
It returns about 480 hits. Each becomes a `NewStringUTF` on the C++ side and a
`split` on the Kotlin side. Kotlin just allocates `Hit` objects. The boundary
cost is per *result*, not just per call.

**Local references?**
`to_java` deletes each `jstring` after `SetObjectArrayElement`. Without that, a
3,526-hit result would overflow the local reference table: 512 slots are
guaranteed (EnsureLocalCapacity), and CheckJNI aborts.

**Why `GetStringUTFRegion` over `GetStringCritical`?**
Critical sections can block the GC; for short strings the copy is cheap. Same
finding as sbe-jni-bridge, where critical lost to memcpy.

**Binder: what's actually happening?**
- `IScanService.aidl` generates a `Stub` (server) and a `Proxy` (client).
- `runScan()` marshals into a `Parcel`, the binder driver
  (`/dev/binder` ioctl) copies it into the service process (`:scanner`), and the
  call runs on that process's binder thread pool.
- The test asserts the pid differs, to prove it crossed processes.
- The service is exported but guarded by a `signature` permission. Binder sets
  the caller's uid via `Binder.getCallingUid()`, and the framework enforces the
  permission at bind time.

**TransactionTooLargeException?**
The Binder buffer is about 1 MB per process, shared across in-flight
transactions. Asking `getInstalledPackages` for all components of all apps blows
it. So: list packages first, then one `getPackageInfo` per package. That's also
why inventory dominates scan time.

**Package visibility?**
Android 11+ filters `getInstalledPackages` unless you declare
`QUERY_ALL_PACKAGES` or `<queries>`. The test asserts we see more than 50 apps.
Play policy restricts that permission; security scanners are a permitted use.

**SELinux enforcing: how do you know if you can't read it?**
In permissive mode the kernel logs AVC denials but allows the access. If the read
of `/sys/fs/selinux/enforce` is denied, enforcement is on.
`property_contexts` hides `ro.boot.*` and `ro.debuggable` from `untrusted_app`;
I verified that with `run-as` in the app's domain.

**Verified boot from an app?**
Key attestation. Generate a Keystore key with an attestation challenge, take the
leaf certificate's extension `1.3.6.1.4.1.11129.2.1.17`, and parse
`KeyDescription` → AuthorizationList → `[704] RootOfTrust`. Tag 704 uses the DER
high-tag-number form (`BF 85 40`). In production you'd verify the certificate
chain to Google's attestation root, and check the challenge you sent;
droidguard parses but doesn't verify the chain. That's a stated gap.

**Kernel CVEs: version or patch level?**
Both. Vendors backport, so version alone over-reports. Patch level alone
over-reports a newer LTS on an old SPL. The verdict is SPL-behind AND
(version-in-range OR range-unknown). The report shows both disagreement counts.

**12 vs 12L?**
- 12L devices report `Build.VERSION.RELEASE = "12"`, but the bulletin treats 12L
  as its own release. So I map from `SDK_INT` (32 → "12L").
- A prefix match on "12" would also hit 12L rules. That's one of the naive
  baseline's false positives.

**Re-issued fixes?**
Some CVEs appear twice for the same release with two fix SPLs (an incomplete
first fix). Any-rule-matches semantics means the later SPL governs.

**simpleperf on the emulator: anything odd?**
- No hardware PMU, so use the `cpu-clock` software event.
- `-p PID` from the shell is denied by SELinux even with `perf_harden=0`;
  `--app` uses `simpleperf_app_runner`, which needs the app `profileable` (or
  debuggable).
- Benchmark on the release build: a debuggable APK changes ART's behaviour.

**LLDB?** Not exercised in this project; don't claim it. The flow:

1. Build the debug variant.
2. `adb push $NDK/prebuilt/android-x86_64/lldb-server` to the app's data dir
   with `run-as`.
3. Start it there.
4. `adb forward`.
5. `lldb` → `platform select remote-android` → attach to the pid.
6. Breakpoint on `Java_dev_droidguard_core_NativeMatcher_nativeMatchApp`.

Android Studio wraps exactly this.

## What I'd do next
- Verify the attestation chain against the Google root.
- `<queries>` instead of `QUERY_ALL_PACKAGES` for a Play build.
- Pass results back as one packed `byte[]` instead of `String[]`.
- Test on a physical phone with a TEE.

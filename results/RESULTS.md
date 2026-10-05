# Results

All local device numbers come from the API 34 `google_apis` x86_64 emulator on a
Windows host (WHPX, i5-9300H, 2 GB guest RAM), running the **release**
(non-debuggable) build. CI repeats the instrumented suite on API 29, 31 and 34
and uploads `dgresult-api<N>.log` per level as artifacts.

| File | What |
|---|---|
| `local/eval.txt`, `local/eval.json` | Precision/recall of the matcher and the naive baseline on `data/labels.tsv` |
| `local/bench-before-jni-fix.jsonl` | 3 runs of `ScanBenchmarkTest#matcherNativeVsKotlin` before the JNI fix |
| `local/bench-after-jni-fix.jsonl` | The same 3 runs after the fix |
| `local/full-scan-api34.jsonl` | `ScanBenchmarkTest#fullScan`: per-phase timings plus the report summary |
| `simpleperf/before/`, `simpleperf/after/` | `jniMissLoop` profiles, by DSO and by symbol |

## Matcher accuracy (75 cases, 29 positive)

```
kind              matcher  P / R           naive  P / R
app            100.0% / 100.0%       75.0% /  66.7%   (naive fp=2 fn=3)
kernel         100.0% / 100.0%       42.9% /  75.0%   (naive fp=8 fn=2)
platform       100.0% / 100.0%       80.0% / 100.0%   (naive fp=3 fn=0)
all            100.0% / 100.0%       64.9% /  82.8%
```

The labels were written from the source advisories, not from matcher output.
They are deliberately weighted toward the traps:

- lexical version compares (`117.0.5938.60` vs `.132`, `99` vs `117`, `4.14.99` vs `4.14.149`);
- 12 vs 12L;
- `-01` vs `-05` patch levels;
- re-issued fixes;
- kernel backports;
- malformed SPLs.

**Read 100% accordingly.** It shows the matcher handles every trap listed. It
doesn't show it's right on all real-world input.

## Matcher benchmark (medians of 3 runs, release build)

| Metric | Before fix | After fix |
|---|---:|---:|
| No-hit native call (ns) | 632 | **361** |
| Bare no-op JNI call (ns) | 22 | 23 |
| No-hit Kotlin call (ns) | 15 | 22 |
| 225 apps, Kotlin (µs) | 23,560 | 23,712 |
| 225 apps, native, 1 batched call (µs) | 19,081 | 17,212 |
| 225 apps, native, 225 calls (µs) | 19,437 | 14,872 |
| Chrome, 5.6k rules, 0 hits: Kotlin / native (µs) | 6,206 / 2,633 | 6,324 / 3,153 |
| Platform match, about 480 hits: Kotlin / native (µs) | 281 / 654 | 270 / 609 |

Emulator timing noise is roughly ±15–25% between runs; see the per-run values in
the `.jsonl` files. The "225 calls" figure beat the batched one after the fix.
Both are dominated by the two aliased apps (Chrome and WebView, 3,526 hits each),
so that row measures result marshalling more than call granularity.

## Full scan (API 34 emulator, 225 apps)

| Phase | Median (ms) |
|---|---:|
| posture (incl. key attestation) | 71 |
| inventory (Binder → PackageManager) | 708 |
| match platform | 1.0 |
| match kernel | 0.5 |
| match apps | 23 |
| **total** | **803** |

Rule load (11,130 rows, native parse): 8 ms.

Emulator findings:

- **Platform:** 483 CVEs. SPL 2023-09-05 on Android 14.
- **Kernel:** 45 CVEs vulnerable on both signals, 3 SPL-only, 0 backported. The
  kernel is 6.1.23-android14.
- **Apps:** Chrome and WebView 113.0.5672.136 match 3,526 CVEs each. That's an
  upper bound; see the WebView note in the README.
- **Components:** 102 apps have exported, unprotected components. Only 1 of the
  2 third-party apps does.
- **Permissions:** 68 apps hold dangerous permissions.
- **Posture:** SELinux enforcing; attestation Software / Unverified / unlocked;
  userdebug build.

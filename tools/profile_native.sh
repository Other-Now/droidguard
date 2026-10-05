#!/usr/bin/env bash
# Profile droidguard on a connected device/emulator with simpleperf.
#
#   TARGET=jniMissLoop tools/profile_native.sh [outdir]
#
# Runs ScanBenchmarkTest#$TARGET (default jniMissLoop: ~10 s of no-hit JNI
# calls) under `simpleperf record`, then writes per-DSO and per-symbol reports.
# Needs the release APK and its test APK installed. The app is `profileable`
# (AndroidManifest.xml), so this works on the release build -- no debuggable
# flag, which matters because debuggable changes ART's behaviour and therefore
# the profile.
#
# Requires ANDROID_NDK_HOME (simpleperf ships in the NDK).
set -euo pipefail
export MSYS_NO_PATHCONV=1  # Git Bash on Windows would rewrite /data/local/tmp into a host path

PKG=dev.droidguard
OUT=${1:-results/simpleperf}
TARGET=${TARGET:-jniMissLoop}
SP="$ANDROID_NDK_HOME/simpleperf"
mkdir -p "$OUT"

ABI=$(adb shell getprop ro.product.cpu.abi | tr -d '\r')
case "$ABI" in
  x86_64) BIN=x86_64 ;;
  arm64-v8a) BIN=arm64 ;;
  *) echo "unsupported abi $ABI"; exit 1 ;;
esac
adb push "$SP/bin/android/$BIN/simpleperf" /data/local/tmp/ >/dev/null
adb shell chmod +x /data/local/tmp/simpleperf

adb shell am instrument -w -e dg.profile 1 -e class "dev.droidguard.ScanBenchmarkTest#$TARGET" \
  dev.droidguard.test/androidx.test.runner.AndroidJUnitRunner > "$OUT/instrument.txt" &
INST=$!

# `--app`, not `-p PID`: SELinux stops the shell domain from opening perf
# events on an app domain (perf_harden=0 does not help); for a profileable app
# simpleperf runs itself under the app's identity via simpleperf_app_runner.
# cpu-clock: emulators expose no hardware PMU counters, so a software clock
# event is the honest choice.
sleep 2
adb shell /data/local/tmp/simpleperf record --app $PKG -e cpu-clock -f 4000 --call-graph fp \
  --duration 6 -o /data/local/tmp/perf.data
wait $INST || true

adb pull /data/local/tmp/perf.data "$OUT/perf.data" >/dev/null
adb shell /data/local/tmp/simpleperf report -i /data/local/tmp/perf.data --sort dso \
  > "$OUT/report_by_dso.txt"
adb shell /data/local/tmp/simpleperf report -i /data/local/tmp/perf.data --sort dso,symbol \
  | sed -E 's/ {2,}/ | /g' > "$OUT/report_by_symbol.txt"
echo "wrote $OUT/"
sed -n '8,20p' "$OUT/report_by_dso.txt"
sed -n '8,40p' "$OUT/report_by_symbol.txt" | cut -c1-170

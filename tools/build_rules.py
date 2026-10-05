#!/usr/bin/env python3
"""Build app/src/main/assets/rules.tsv from the Android Security Bulletin (OSV
export) and the NVD 2.0 yearly feeds.

    python tools/build_rules.py --osv osv-android.zip --nvd-dir nvd/

Inputs (not checked in, ~170 MB):
  https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip
  https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-<year>.json.gz  (2020..)

Three rule kinds come out, one TSV:

  platform  AOSP component CVE. Affected when the device runs `release` and its
            security patch level is older than `fixed_spl`.
  kernel    Generic Linux-kernel CVE from the bulletin. The bulletin gives only a
            patch level; the upstream version range comes from NVD for the same
            CVE id. One row per NVD range, or one row with empty bounds when NVD
            has none.
  app       Known-vulnerable versions of a handful of Android apps, from NVD CPE
            ranges, keyed by CPE "vendor:product".
  alias     Android package name -> CPE "vendor:product" (in the `release`
            column). Same idea as nano-sensor's alias table: the CVE data is
            keyed by product, the device reports package names.

What is deliberately dropped, and why, is printed at the end and recorded in
data/SOURCES.md: SoC- and Pixel-specific advisories (this scanner cannot tell a
Qualcomm vendor blob from a MediaTek one), and "-next" releases, which are
unreleased trains no device reports.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import json
import pathlib
import zipfile

HEADER = "kind\tcve\ttarget\trelease\tfixed_spl\tstart_incl\tstart_excl\tend_incl\tend_excl\tseverity"

# Android package -> (cpe vendor, cpe product, allowed target_sw values).
# The target_sw filter is per product, so packages sharing a CPE must agree.
# WebView ships the same Chromium engine and version numbers as Chrome, and NVD
# files Chromium-engine CVEs under google:chrome. That makes WebView matching an
# approximation (some Chrome CVEs are in browser UI code WebView does not ship);
# the README says so rather than pretending otherwise.
APP_CPES = {
    "com.android.chrome": ("google", "chrome", {"*", "-", "android"}),
    "com.google.android.webview": ("google", "chrome", {"*", "-", "android"}),
    "com.android.webview": ("google", "chrome", {"*", "-", "android"}),
    "org.mozilla.firefox": ("mozilla", "firefox", {"android"}),
    "com.whatsapp": ("whatsapp", "whatsapp", {"android"}),
    "org.telegram.messenger": ("telegram", "telegram", {"android"}),
}


def norm_release(v: str) -> str | None:
    """Map an OSV `versions` entry to the release string a device reports.

    Returns None for anything that is not a shipped AOSP release.
    """
    if not v or not v[0].isdigit():
        return None  # SoCVersion, Kernel, Pixel-family specific, codenames
    if "-next" in v:
        return None  # fix lands in an unreleased train
    # "16-qpr2": a quarterly platform release of Android 16. A device on 16 that
    # is behind the patch level is affected whichever QPR it is on.
    return v.split("-qpr")[0]


def load_osv(path: pathlib.Path):
    platform, kernel = [], []
    dropped = collections.Counter()
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            d = json.loads(z.read(name))
            cves = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
            if not cves:
                dropped["no CVE alias"] += 1
                continue
            cve = cves[0]
            for a in d["affected"]:
                pkg = a["package"]["name"]
                es = a.get("ecosystem_specific", {})
                sev = es.get("severity", "")
                versions = a.get("versions", [])
                if pkg == ":linux_kernel:" and "Kernel" in versions:
                    kernel.append((cve, es.get("spl", ""), sev))
                    continue
                if not (pkg.startswith("platform/") or pkg == ":unknown:"):
                    dropped["vendor/SoC component"] += 1
                    continue
                # Per-release fix patch level lives in the range events:
                # {"fixed": "13:2023-09-01"}.
                fixed_by_rel = {}
                for r in a.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev and ":" in ev["fixed"]:
                            rel, spl = ev["fixed"].rsplit(":", 1)
                            fixed_by_rel[rel] = spl
                for v in versions:
                    rel = norm_release(v)
                    if rel is None:
                        dropped[f"non-release version ({'next' if '-next' in v else 'other'})"] += 1
                        continue
                    spl = fixed_by_rel.get(v) or es.get("spl", "")
                    if not spl:
                        dropped["no fixed patch level"] += 1
                        continue
                    target = pkg if pkg.startswith("platform/") else "unknown"
                    platform.append((cve, target, rel, spl, sev))
    return platform, kernel, dropped


def iter_nvd(nvd_dir: pathlib.Path):
    for f in sorted(nvd_dir.glob("nvdcve-2.0-*.json.gz")):
        with gzip.open(f) as fh:
            for item in json.load(fh)["vulnerabilities"]:
                yield item["cve"]


def nvd_severity(cve: dict) -> str:
    m = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        for x in m.get(key, []):
            return x["cvssData"]["baseSeverity"].capitalize()
    for x in m.get("cvssMetricV2", []):
        return x.get("baseSeverity", "").capitalize()
    return ""


def cpe_matches(cve: dict):
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    yield m


def range_of(m: dict, parts: list[str]):
    """(start_incl, start_excl, end_incl, end_excl) or None to skip."""
    ver, update = parts[5], parts[6]
    if ver not in ("*", "-"):
        if update not in ("*", "-"):
            return None  # rc / beta builds; no device runs these
        return (ver, "", ver, "")  # exact version
    b = (m.get("versionStartIncluding", ""), m.get("versionStartExcluding", ""),
         m.get("versionEndIncluding", ""), m.get("versionEndExcluding", ""))
    if not any(b):
        return ("", "", "", "")  # every version
    return b


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--osv", required=True, type=pathlib.Path)
    ap.add_argument("--nvd-dir", required=True, type=pathlib.Path)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path(__file__).resolve().parent.parent
                    / "app/src/main/assets/rules.tsv")
    args = ap.parse_args()

    platform, kernel, dropped = load_osv(args.osv)
    kernel_cves = {c for c, _, _ in kernel}

    kernel_ranges: dict[str, list[tuple]] = collections.defaultdict(list)
    app_rows = []
    by_cpe = {(v, p): tsw for v, p, tsw in APP_CPES.values()}

    for cve in iter_nvd(args.nvd_dir):
        cid = cve["id"]
        sev = None
        for m in cpe_matches(cve):
            parts = m["criteria"].split(":")
            vendor, product, target_sw = parts[3], parts[4], parts[10]
            if cid in kernel_cves and vendor == "linux" and product == "linux_kernel":
                r = range_of(m, parts)
                if r is not None:
                    kernel_ranges[cid].append(r)
            allowed = by_cpe.get((vendor, product))
            if allowed is None or target_sw not in allowed:
                continue
            r = range_of(m, parts)
            if r is None or r == ("", "", "", ""):
                continue  # "all versions" app rows are NVD noise, not signal
            if sev is None:
                sev = nvd_severity(cve)
            app_rows.append(("app", cid, f"{vendor}:{product}", "", "", *r, sev))

    rows = []
    for cve, target, rel, spl, sev in platform:
        rows.append(("platform", cve, target, rel, spl, "", "", "", "", sev))
    kernel_with_ranges = 0
    for cve, spl, sev in kernel:
        rs = sorted(set(kernel_ranges.get(cve, [])))
        if rs:
            kernel_with_ranges += 1
            for r in rs:
                rows.append(("kernel", cve, "linux_kernel", "", spl, *r, sev))
        else:
            rows.append(("kernel", cve, "linux_kernel", "", spl, "", "", "", "", sev))
    rows.extend(sorted(set(app_rows)))
    for pkg, (vendor, product, _) in APP_CPES.items():
        rows.append(("alias", "-", pkg, f"{vendor}:{product}", "", "", "", "", "", ""))

    # Exact duplicates arise when one advisory lists the same component twice.
    seen, uniq = set(), []
    for r in rows:
        if r not in seen:
            seen.add(r)
            uniq.append(r)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", newline="\n", encoding="utf-8") as f:
        f.write(HEADER + "\n")
        for r in uniq:
            f.write("\t".join(r) + "\n")

    kinds = collections.Counter(r[0] for r in uniq)
    print(f"wrote {args.out} ({len(uniq)} rows)")
    for k, n in kinds.items():
        cves = len({r[1] for r in uniq if r[0] == k})
        print(f"  {k:9s} {n:6d} rows  {cves:5d} CVEs")
    print(f"  kernel CVEs with an NVD version range: {kernel_with_ranges}/{len(kernel_cves)}")
    apps = collections.Counter(r[2] for r in uniq if r[0] == "app")
    for p, n in apps.items():
        print(f"  app {p}: {n} rows")
    print(f"  platform releases: {sorted({r[3] for r in uniq if r[0] == 'platform'}, key=lambda x: float(x.rstrip('L')) + (0.5 if x.endswith('L') else 0))}")
    print("dropped:")
    for k, n in dropped.most_common():
        print(f"  {k}: {n}")


if __name__ == "__main__":
    main()

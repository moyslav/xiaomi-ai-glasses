#!/usr/bin/env python3
"""
Static scanner for the Xiaomi Glasses APK (com.xiaomi.superhexa).

Extracts: archive stats, dex list, URLs/hosts, /v1/ endpoints and signing-related
strings. Uses only the standard library (zipfile + re), no androguard required.

Usage:
    python apk_scan.py glasses.apk
    python apk_scan.py glasses.apk --json > report.json
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import zipfile

URL_RE = re.compile(rb"https?://[^\x00-\x20\"'<>\\]{5,160}")
V1_RE = re.compile(rb"/v1/[A-Za-z0-9_/\-\.\{\}%]{2,60}")
STR_RE = re.compile(rb"[\x20-\x7e]{4,120}")

INTERESTING = [
    "HEXA1", "HmacSHA256", "serviceToken", "passToken", "uploadOtaFile",
    "checkOtaStatus", "wearDetection", "wearSensitivity", "otaVersion",
    "fileMd5", "md5sum", "chunk", "live/", "rawImage",
]


def scan(path: str) -> dict:
    zf = zipfile.ZipFile(path)
    infos = zf.infolist()
    dex = [i.filename for i in infos if i.filename.endswith(".dex")]

    urls: set[str] = set()
    v1: collections.Counter = collections.Counter()
    hits: dict[str, list[str]] = collections.defaultdict(list)

    for name in dex:
        data = zf.read(name)
        for m in URL_RE.finditer(data):
            urls.add(m.group().decode("utf-8", "ignore"))
        for m in V1_RE.finditer(data):
            v1[m.group().decode("utf-8", "ignore")] += 1
        for m in STR_RE.finditer(data):
            s = m.group().decode("ascii", "ignore")
            for kw in INTERESTING:
                if kw.lower() in s.lower() and s not in hits[kw]:
                    hits[kw].append(s)

    hosts = collections.Counter()
    for u in urls:
        m = re.match(r"https?://([^/]+)", u)
        if m:
            hosts[m.group(1)] += 1

    return {
        "entries": len(infos),
        "dex_files": len(dex),
        "largest": [
            {"size": i.file_size, "name": i.filename}
            for i in sorted(infos, key=lambda x: -x.file_size)[:15]
        ],
        "hosts": hosts.most_common(60),
        "v1_endpoints": sorted(v1),
        "urls_total": len(urls),
        "urls_ota_like": sorted(
            u for u in urls
            if any(k in u.lower() for k in ("ota", "firmware", "upgrade", "glass", "m2442"))
        ),
        "signing_strings": {k: v[:12] for k, v in hits.items()},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("apk")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    report = scan(args.apk)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print(f"entries      : {report['entries']}")
    print(f"dex files    : {report['dex_files']}")
    print(f"unique URLs  : {report['urls_total']}")
    print(f"/v1 endpoints: {len(report['v1_endpoints'])}")

    print("\nLargest files:")
    for item in report["largest"]:
        print(f"  {item['size']:>12,}  {item['name']}")

    print("\nTop hosts:")
    for host, count in report["hosts"][:25]:
        print(f"  {count:>4}  {host}")

    print("\n/v1 endpoints:")
    for e in report["v1_endpoints"]:
        print("  ", e)

    print("\nURLs matching ota/firmware/glass:")
    for u in report["urls_ota_like"]:
        print("  ", u)

    print("\nSigning-related strings:")
    for kw, items in report["signing_strings"].items():
        if items:
            print(f"\n  [{kw}]")
            for s in items:
                print("    ", s)


if __name__ == "__main__":
    sys.exit(main())

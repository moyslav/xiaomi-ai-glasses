#!/usr/bin/env python3
"""
Probe for the Xiaomi AI Glasses local HTTP API (port 8080).

The glasses act as a Wi-Fi access point; connect the host machine to that network
first, then run this script.

Read-only: only GET requests are issued. No settings are changed, no OTA is uploaded.

Usage:
    python probe.py 192.168.43.1
    python probe.py 192.168.43.1 --pass-token <TOKEN>
    python probe.py --scan
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, __file__.rsplit("\\", 1)[0].rsplit("/", 1)[0])
try:
    from hexa_sign import make_credential
except ImportError:  # pragma: no cover
    from tools.hexa_sign import make_credential  # type: ignore

APP_VERSION = "Android:3.1.0i"

READ_ONLY_ENDPOINTS = [
    "/v1/setting",
    "/v1/devices/wearDetection/sensitivities",
    "/v1/deviceNetState/",
    "/v1/ota/packages",
]

COMMON_HOSTS = [
    "192.168.43.1",   # Android hotspot default
    "192.168.4.1",
    "192.168.1.1",
    "192.168.0.1",
    "10.0.0.1",
    "172.20.10.1",    # iOS hotspot
    "192.168.137.1",  # Windows ICS
    "192.168.49.1",
]


def request(host: str, path: str, pass_token: str = "", use_auth: bool = True, timeout: float = 6.0):
    url = f"http://{host}:8080{path}"
    headers = {
        "Accept": "application/json",
        "X-App-Version": APP_VERSION,
        "X-Request-ID": f"App_Android_{int(time.time() * 1000)}_{hash(time.time()) & 0xFFFFFF}",
    }
    if use_auth:
        headers["Authorization"], _ = make_credential(pass_token=pass_token, http_type="GET")
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read(4000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2000).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}"


def port_open(host: str, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, 8080), timeout=timeout):
            return True
    except OSError:
        return False


def scan() -> None:
    print("Scanning common gateway addresses on port 8080 ...")
    found = []
    for host in COMMON_HOSTS:
        ok = port_open(host)
        print(f"  {host:16} {'OPEN' if ok else '-'}")
        if ok:
            found.append(host)
    if found:
        print(f"\nDevice found. Run: python probe.py {found[0]}")
    else:
        print("\nNothing found. Is this machine connected to the glasses' Wi-Fi?")


def main() -> None:
    ap = argparse.ArgumentParser(description="Probe Xiaomi AI Glasses local API (read-only)")
    ap.add_argument("host", nargs="?", help="Glasses IP address on their Wi-Fi network")
    ap.add_argument("--pass-token", default="", help="Account passToken, if the device requires it")
    ap.add_argument("--scan", action="store_true", help="Scan common gateway IPs for port 8080")
    args = ap.parse_args()

    if args.scan:
        scan()
        return
    if not args.host:
        ap.print_help()
        return

    print(f"Target: {args.host}:8080\n")
    for path in READ_ONLY_ENDPOINTS:
        status, body = request(args.host, path, args.pass_token, use_auth=True)
        print(f"[signed] GET {path} -> {status}")
        print("  " + body[:800].replace("\n", "\n  "))
        print()

    print("--- control: GET /v1/setting WITHOUT Authorization ---")
    status, body = request(args.host, READ_ONLY_ENDPOINTS[0], use_auth=False)
    print(f"  -> {status}")
    print("  " + body[:500].replace("\n", "\n  "))


if __name__ == "__main__":
    main()

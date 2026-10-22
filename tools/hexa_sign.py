#!/usr/bin/env python3
"""
HEXA1 credential generator for Xiaomi AI Glasses (com.xiaomi.superhexa).

Recovered by static analysis of the official APK:
  - com.superhexa.supervision.library.net.retrofit.CredentialCalculator
  - com.superhexa.supervision.library.base.basecommon.tools.d0   (HmacSHA256)
  - com.superhexa.supervision.library.base.basecommon.tools.ExtensionsKt (toHex, %02x)
  - com.superhexa.supervision.library.net.retrofit.interceptor.b (Authorization header)

Scheme:
    nonce     = md5_hex(ts + random(0..10000)), left-padded to 32 chars
    text      = "nonce=N&timestamp=T"                     (empty body)
              | "{body}&nonce=N&timestamp=T"               (GET with params)
              | "data={body}&nonce=N&timestamp=T"          (POST)
    key       = serviceToken            if pass_token is empty
              | serviceToken + pass_token  otherwise
    signature = hex_lower(HMAC_SHA256(key, text))
    header    = "HEXA1-HMAC-SHA256 nonce=N, timestamp=T, signature=S"

Usage:
    python hexa_sign.py
    python hexa_sign.py --pass-token TOKEN --method POST --post '{"a":1}' --json
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import random
import time

# Hardcoded default serviceToken found in the APK (public constant, not a user secret).
SERVICE_TOKEN = "f7b364516e739c2ac60f1114e88f6afc"


def build_signed_text(nonce: str, timestamp: int, post_parameter: str, http_type: str) -> str:
    """Reproduce CredentialCalculator.c() text construction."""
    if post_parameter == "":
        return f"nonce={nonce}&timestamp={timestamp}"
    if http_type.upper() == "GET":
        return f"{post_parameter}&nonce={nonce}&timestamp={timestamp}"
    return f"data={post_parameter}&nonce={nonce}&timestamp={timestamp}"


def make_credential(
    pass_token: str = "",
    post_parameter: str = "",
    http_type: str = "GET",
    ts_ms: int | None = None,
    rand: int | None = None,
    service_token: str = SERVICE_TOKEN,
) -> tuple[str, dict]:
    """Return (Authorization header value, debug dict)."""
    ts = int(time.time() * 1000) if ts_ms is None else ts_ms
    r = random.randint(0, 10000) if rand is None else rand

    # nonce = md5(ts + r) as lowercase hex, left-padded with '0' to 32 chars
    nonce = hashlib.md5(str(ts + r).encode()).hexdigest().rjust(32, "0")

    text = build_signed_text(nonce, ts, post_parameter, http_type)

    key = service_token if pass_token == "" else service_token + pass_token
    signature = hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()

    header = f"HEXA1-HMAC-SHA256 nonce={nonce}, timestamp={ts}, signature={signature}"
    debug = {
        "nonce": nonce,
        "timestamp": ts,
        "signed_text": text,
        "key": key,
        "signature": signature,
        "http_type": http_type.upper(),
        "body": post_parameter,
    }
    return header, debug


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate a HEXA1 Authorization header")
    ap.add_argument("--pass-token", default="", help="Account passToken / miWearServiceToken (optional)")
    ap.add_argument("--post", default="", help="Request body (JSON string or query string)")
    ap.add_argument("--method", default="GET", choices=["GET", "POST", "PUT", "DELETE"])
    ap.add_argument("--ts", type=int, default=None, help="Fixed timestamp in ms (for reproducible tests)")
    ap.add_argument("--rand", type=int, default=None, help="Fixed random value (for reproducible tests)")
    ap.add_argument("--json", action="store_true", help="Print debug info as JSON")
    args = ap.parse_args()

    header, debug = make_credential(
        pass_token=args.pass_token,
        post_parameter=args.post,
        http_type=args.method,
        ts_ms=args.ts,
        rand=args.rand,
    )

    if args.json:
        print(json.dumps({"authorization": header, **debug}, indent=2, ensure_ascii=False))
    else:
        print("key used   :", debug["key"])
        print("signed text:", debug["signed_text"])
        print("header     :", header)


if __name__ == "__main__":
    main()

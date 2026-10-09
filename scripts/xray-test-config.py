#!/usr/bin/env python3
"""Builds a ready Xray test config from a subscription, for ProxyGate stage-1 testing.

    python3 -I scripts/xray-test-config.py '<subscription url>' [name-substring] > config.json

Fetches the subscription as Happ, picks one config (the first whose remarks contain
`name-substring`, else the "Авто"/balancer one, else the first), and replaces its inbounds
with a local SOCKS proxy on 127.0.0.1:52140. Load the result via Settings → VPN core →
"Load test config". The file contains your VLESS keys — keep it local.
"""
import json
import ssl
import subprocess
import sys
import urllib.request

LOCAL_SOCKS_PORT = 52140


def tls_context():
    ctx = ssl.create_default_context()
    for kc in ("/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"):
        try:
            pem = subprocess.run(["/usr/bin/security", "find-certificate", "-a", "-p", kc],
                                 capture_output=True, text=True, check=True).stdout
            ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.CalledProcessError, ssl.SSLError):
            pass
    return ctx


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Happ/3.0.0", "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=20, context=tls_context()) as r:
        return r.read()


def pick(configs, needle):
    if needle:
        for c in configs:
            if needle.lower() in str(c.get("remarks", "")).lower():
                return c
    for c in configs:
        if c.get("routing", {}).get("balancers"):
            return c
    return configs[0]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        sys.stderr.write(__doc__)
        sys.exit(1)
    url = args[0]
    needle = args[1] if len(args) > 1 else ""
    data = json.loads(fetch(url))
    configs = data if isinstance(data, list) else [data]
    cfg = pick(configs, needle)

    # Loopback SOCKS inbound the engine (or any local app) dials; everything else stays as the
    # provider shipped it, so the real REALITY/Vision outbound and routing are what gets tested.
    cfg["inbounds"] = [{
        "tag": "socks-in",
        "listen": "127.0.0.1",
        "port": LOCAL_SOCKS_PORT,
        "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
    }]
    sys.stderr.write(f"Using config: {cfg.get('remarks', '?')}  →  SOCKS5 127.0.0.1:{LOCAL_SOCKS_PORT}\n")
    json.dump(cfg, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

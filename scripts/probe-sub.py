#!/usr/bin/env python3
"""Shows what a VPN subscription URL serves to different clients, with secrets masked.

    python3 -I scripts/probe-sub.py '<subscription url>' [--hwid]

The URL, UUIDs, keys and server addresses are never printed. --hwid also sends Happ-style
device headers; on panels with a device limit that may register this Mac as a device.
"""
import base64
import json
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

CLIENTS = [
    ("Happ", "Happ/3.0.0"),
    ("v2rayN", "v2rayN/7.10.0"),
    ("v2rayNG", "v2rayNG/1.9.30"),
    ("Streisand", "Streisand/1.6"),
    ("Clash Meta", "clash.meta/1.19.0"),
    ("sing-box", "SFM/1.11.0 (sing-box 1.11.0)"),
    ("curl", "curl/8.7.1"),
]
SECRET_KEYS = {"id", "uuid", "password", "pbk", "publickey", "sid", "shortid", "shortids", "address",
               "server", "host", "path", "serviceName", "spx", "key", "privatekey", "auth"}


def mask(value):
    s = str(value)
    if len(s) <= 4:
        return "***"
    return f"{s[:2]}…{s[-2:]}"


def tls_context():
    """macOS system roots: python.org builds ship an old bundle (no ISRG Root YR and newer)."""
    ctx = ssl.create_default_context()
    for keychain in ("/System/Library/Keychains/SystemRootCertificates.keychain", "/Library/Keychains/System.keychain"):
        try:
            pem = subprocess.run(["/usr/bin/security", "find-certificate", "-a", "-p", keychain],
                                 capture_output=True, text=True, check=True).stdout
            ctx.load_verify_locations(cadata=pem)
        except (OSError, subprocess.CalledProcessError, ssl.SSLError):
            pass
    return ctx


CONTEXT = tls_context()


def fetch(url, ua, hwid):
    headers = {"User-Agent": ua, "Accept": "*/*"}
    if hwid:
        headers.update({"x-hwid": hwid, "x-device-os": "macOS", "x-ver-os": "26",
                        "x-device-model": "Mac"})
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20, context=CONTEXT) as r:
            return r.status, dict(r.headers.items()), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers.items()), e.read()
    except Exception as e:  # network errors are part of the report
        return None, {}, str(e).encode()


def decode_b64(text):
    t = re.sub(r"\s+", "", text)
    t += "=" * (-len(t) % 4)
    for f in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return f(t).decode("utf-8")
        except Exception:
            pass
    return None


def describe_uri(line):
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        cfg = json.loads(decode_b64(line[8:]) or "{}")
        return (f"vmess net={cfg.get('net')} tls={cfg.get('tls') or '-'} sni={cfg.get('sni') or '-'} "
                f"fp={cfg.get('fp') or '-'} name={cfg.get('ps', '')!r}")
    u = urllib.parse.urlsplit(line)
    q = dict(urllib.parse.parse_qsl(u.query))
    keep = ["type", "security", "flow", "fp", "sni", "alpn", "mode", "headerType", "encryption"]
    parts = [f"{k}={q[k]}" for k in keep if k in q]
    extra = sorted(k for k in q if k not in keep)
    name = urllib.parse.unquote(u.fragment)
    return f"{scheme} port={u.port} " + " ".join(parts) + (f" +[{', '.join(extra)}]" if extra else "") + f" name={name!r}"


def walk_masked(obj):
    if isinstance(obj, dict):
        return {k: (mask(v) if k.lower() in {s.lower() for s in SECRET_KEYS} and not isinstance(v, (dict, list))
                    else walk_masked(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [walk_masked(v) for v in obj]
    return obj


def describe_xray(cfg, out):
    out.append(f"    remarks={cfg.get('remarks', '')!r}")
    for ob in cfg.get("outbounds", []):
        ss = ob.get("streamSettings", {})
        sec = ss.get("security", "none")
        tls = ss.get(f"{sec}Settings", {}) if sec in ("tls", "reality") else {}
        users = [u for v in ob.get("settings", {}).get("vnext", []) for u in v.get("users", [])]
        flow = ",".join(sorted({u.get("flow", "") for u in users} - {""})) or "-"
        sock = ss.get("sockopt", {})
        frag = ob.get("settings", {}).get("fragment")
        out.append(f"    outbound tag={ob.get('tag')} proto={ob.get('protocol')} net={ss.get('network', '-')} "
                   f"sec={sec} flow={flow} fp={tls.get('fingerprint', '-')} sni={tls.get('serverName', '-')}"
                   + (f" dialerProxy={sock['dialerProxy']}" if "dialerProxy" in sock else "")
                   + (f" fragment={frag}" if frag else "")
                   + (" mux" if ob.get("mux", {}).get("enabled") else ""))
        if ss.get("network") in ("xhttp", "splithttp"):
            x = ss.get("xhttpSettings") or ss.get("splithttpSettings") or {}
            out.append(f"      xhttp mode={x.get('mode', '-')} extra={sorted(x.get('extra', {}).keys())}")
    routing = cfg.get("routing", {})
    if routing:
        out.append(f"    routing rules={len(routing.get('rules', []))} balancers="
                   f"{[(b.get('tag'), b.get('strategy', {}).get('type')) for b in routing.get('balancers', [])]}")
        geo = sorted({d for r in routing.get("rules", []) for d in r.get("domain", []) + r.get("ip", [])
                      if d.startswith(("geosite:", "geoip:", "ext:"))})
        if geo:
            out.append(f"    geo lists: {geo[:20]}{' …' if len(geo) > 20 else ''}")
    for key in ("observatory", "burstObservatory", "dns", "fakedns"):
        if key in cfg:
            out.append(f"    has {key}")


def analyze(body):
    out = []
    text = body.decode("utf-8", "replace").strip()
    if not text:
        return "empty body", out
    if text.startswith(("{", "[")):
        try:
            data = json.loads(text)
        except ValueError:
            return "broken JSON", out
        configs = data if isinstance(data, list) else [data]
        if all(isinstance(c, dict) and any("protocol" in o for o in c.get("outbounds", [])) for c in configs):
            for c in configs:
                describe_xray(c, out)
            return f"Xray JSON, {len(configs)} config(s)", out
        if any("type" in o for c in configs for o in c.get("outbounds", [])):
            for c in configs:
                for o in c.get("outbounds", []):
                    tls = o.get("tls", {})
                    out.append(f"    {o.get('type')} tag={o.get('tag')} transport={o.get('transport', {}).get('type', 'tcp')} "
                               f"reality={tls.get('reality', {}).get('enabled', False)} "
                               f"fp={tls.get('utls', {}).get('fingerprint', '-')} sni={tls.get('server_name', '-')}")
            return "sing-box JSON", out
        out.append("    " + json.dumps(walk_masked(data), ensure_ascii=False)[:600])
        return "unknown JSON", out
    if re.search(r"^proxies:", text, re.M):
        for m in re.finditer(r"type:\s*(\S+)", text):
            out.append(f"    proxy type={m.group(1)}")
        return "Clash YAML", out[:40]
    if text.startswith("happ://"):
        return "Happ encrypted link (" + text.split("/", 3)[2] + ")", out
    lines = text.splitlines()
    if not any("://" in l for l in lines):
        decoded = decode_b64(text)
        if decoded and "://" in decoded:
            lines = decoded.splitlines()
            kind = "base64 URI list"
        else:
            return "unrecognized: " + mask(text[:40]), out
    else:
        kind = "plain URI list"
    uris = [l.strip() for l in lines if "://" in l]
    for l in uris:
        try:
            out.append("    " + describe_uri(l))
        except Exception as e:
            out.append(f"    {l.split('://')[0]} (unparsed: {e})")
    return f"{kind}, {len(uris)} server(s)", out


def show_headers(headers):
    interesting = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in ("set-cookie", "date", "server", "connection", "content-length", "vary", "cf-ray",
                  "alt-svc", "strict-transport-security", "x-content-type-options"):
            continue
        if lk == "profile-title" and v.startswith("base64:"):
            v = (decode_b64(v[7:]) or v) + "  (base64)"
        if lk in ("profile-web-page-url", "support-url", "content-disposition"):
            v = re.sub(r"[A-Za-z0-9_-]{16,}", lambda m: mask(m.group()), v)
        interesting[lk] = v
    for k, v in sorted(interesting.items()):
        print(f"    {k}: {v}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print(__doc__)
        sys.exit(1)
    url = args[0]
    hwid = uuid.uuid5(uuid.NAMESPACE_URL, "proxygate-probe").hex if "--hwid" in sys.argv else None
    print(f"Subscription host: {urllib.parse.urlsplit(url).hostname}")
    seen = {}
    for name, ua in CLIENTS:
        status, headers, body = fetch(url, ua, hwid)
        print(f"\n== {name}  (UA: {ua})")
        if status is None:
            print(f"    network error: {body.decode(errors='replace')}")
            continue
        kind, details = analyze(body)
        print(f"    HTTP {status}, {len(body)} bytes, content-type={headers.get('Content-Type', '-')}: {kind}")
        digest = hash(body)
        if digest in seen:
            print(f"    same body as {seen[digest]}")
        else:
            seen[digest] = name
            show_headers(headers)
            for line in details:
                print(line)


if __name__ == "__main__":
    main()

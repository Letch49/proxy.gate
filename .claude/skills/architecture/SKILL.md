---
name: architecture
description: ProxyGate system model. Load for design-level work or when touching the engine, the control socket, the cores (Xray/tpws/openconnect), bridges, VPN, DPI, AnyConnect, or rule routing.
---

# ProxyGate architecture

How the pieces fit. For the code rules see [swift-code], for the threat model see [security].

## Why this design

A macOS app that intercepts every app's TCP, including CLI tools that ignore the system proxy.
It uses pf `route-to`/`rdr` interception plus a root LaunchDaemon, not a Network Extension, so it
needs no paid Apple NE entitlement. Real interception can only be exercised on a real Mac with an
admin password, so after engine changes ask a human to test live.

## Processes

- `ProxyGate` (SwiftUI app, `@MainActor @Observable AppModel`): UI, profile, rules, talks to the
  engine over a unix socket.
- `proxygate-engine` (root LaunchDaemon): drives pf, matches each connection to a rule, relays or
  blocks, and runs the cores. Authenticates the socket peer by uid.
- Cores run as a dedicated low-uid service user `_proxygate`, not root and not nobody (pf `user`
  match rejects the nobody uid). pf passes their outbound by `user <uid>`, so they are not
  redirected back into the engine (loop prevention). The engine's own relays go out from source
  ports 40000-48999, which pf also passes.

## Interception path

app TCP -> pf route-to lo0 + rdr to 127.0.0.1:listenPort -> engine. The engine reads the original
destination via `DIOCNATLOOK`, finds the owning app via libproc, reads the host name from the TLS
SNI or HTTP Host, matches the rules, then relays to the chosen egress. If the GUI quits or crashes
the engine drops the pf rules at once, so traffic is never left redirected.

## Rule routing and bridges

Rules are ordered, first enabled match wins, Default is last. Matching is in `PGCore/Matching.swift`
and is action-independent, so the target grammar is the same for every action. See the "Rule
targets" section in CLAUDE.md for the grammar, and [mcp-proxy-gate] for how agents use it.

Actions: direct, block, global, vpn, dpi (direct through the DPI core), proxy(id), chain(id).
A "bridge" is the egress a `.global` rule resolves to right now: direct, vpn or a proxy. The app
picks the active bridge from interface state (a wired adapter wins) and pushes it to the engine;
`.vpn` resolves to the VPN when its core is up, else to block so a "VPN only" rule never leaks.

## Cores

- VPN = Xray-core, run as a managed child process. The provider's subscription JSON is used as-is,
  with the inbound swapped for a local SOCKS inbound on a loopback port. Fetched with a Happ-style
  User-Agent over the system trust store. Geo routing (geosite/geoip) can run inside Xray or in our
  own rules (see GeoDB below). Typical configs are VLESS + REALITY.
- DPI bypass = a local SOCKS proxy on loopback, one of two engines picked per profile
  (`Profile.dpiEngine`): tpws (zapret) or ByeDPI/ciadpi. On macOS both do payload-level desync only
  (split, disorder, oob, TLS-record split); the macOS ciadpi has no fake packets (`-f`) or md5sig
  (`-S`), and presets with them crash it, so they are not offered. Managers `TpwsManager` /
  `ByeDpiManager`; routing dials the active engine's SOCKS port and always hands it the dialed IP,
  never a name (the core would resolve through the possibly broken system DNS). It is a MODIFIER on
  the direct path, not a bridge: applied to all direct traffic when no VPN/proxy is active, only to
  Direct rules otherwise, never over a VPN or proxy. Autohostlist narrows it to learned blocked hosts
  (`DPIBypassList`). ByeDPI has no upstream macOS build, so its binary comes from a fork with the
  tarball sha256 pinned in `ByeDpiDownloader`.
- Auto-tune (`BypassTuner`, report types in `PGCore/BypassTune.swift`) runs stages and reports the
  first one that failed per host, so DNS or launch problems never read as "no strategy": DNS
  (system resolver, then the profile's provider directly), TCP to the IP, plain HTTPS without
  bypass (from a pf-passed source port), then each strategy of the active and then the other
  installed core. One throwaway core per strategy, up to 4 at once (`DPIProbeSession` slots, own launchd label and port each,
  runs as the service user, must open its port or its log tail is the error; tpws flags also pass
  `--dry-run`), every pending host curled through it in parallel with `--resolve host:443:ip` (real
  SNI and certificate check, no system DNS, never through VPN/proxy). Cancel via `cancelTune`.
  The winner opens the most hosts; the app switches engine/strategy to it. A page that opens does
  not prove video works.
- AnyConnect = openconnect for split-tunnel corporate access, runs as root for the utun and routes.
  Split routes are captured from the routing table by the tunnel's utun interface and added to a
  dynamic pf bypass so corp traffic reaches the tunnel while the rest keeps flowing. The vpnc-script
  is wrapped so it does not write the pushed DNS onto the system interfaces.

## DNS

Two separate jobs share one model (`Profile.dns`: provider, transport, custom providers, the
provider-resolved domain list):

- Diagnostics: `DNSClient` (PGCore) talks to a provider directly, UDP or DoH (RFC 8484 over
  HTTP/1.1, TLS to the bootstrap IP with SNI and certificate check on the DoH host name, source port
  in pf's pass range). Providers are always reached by IP, so a broken system DNS cannot block them.
  Built-ins: Google and Cloudflare (DoH + plain), Quad9 plain only (its DoH needs HTTP/2).
- Names for apps: when "Resolve blocked sites through the provider" is on, the engine runs
  `DNSStub` (UDP 127.0.0.1:`PGConstants.dnsStubPort`, cache with clamped TTLs and SOA-based
  negative caching, REFUSED for names outside the list, AAAA answered empty when IPv6 is not
  redirected) and `SystemDNS` writes one `/etc/resolver/<domain>` file per listed domain pointing
  at it. Only those domains change; system DNS servers, services and search domains are never
  touched, so AnyConnect/corporate names keep their resolvers and nothing needs restoring after
  sleep or a network change. Files carry a marker line; files without it are the user's and are
  reported as conflicts. They are removed when the app disconnects, on engine start and exit.
- DNS only fixes lookups. Whether the site opens is the DPI auto-tune's job; the UI never calls a
  resolver "working" because it returned an address.

## GeoDB

`geosite:`/`geoip:` rule targets are matched by the engine against `geosite.dat`/`geoip.dat`
(`ProxyGateEngine/GeoDB.swift`, a hand-written v2fly protobuf reader, lazy per-category index).
Those `.dat` files ship inside the Xray release zip, so geo targets only match once the VPN core is
installed.

## Versioning

`PGConstants.version` is the app-to-engine handshake version. Bump it after any engine change so
the app reinstalls the helper. App-only changes do not need a bump.

## Downloaded cores

The app downloads the cores and hands the files to the engine. The engine stages its own copy and
verifies it against a hash it gets itself (Xray `.dgst`, zapret `sha256sum.txt`, a pinned ByeDPI
table), never one sent by the client. Verify before clearing the quarantine xattr. See [security] for the
supply-chain caveat under network TLS inspection.

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
targets" section in CLAUDE.md for the grammar, and [mcp] for how agents use it.

Actions: direct, block, global, vpn, dpi (direct through the DPI core), proxy(id), chain(id).
A "bridge" is the egress a `.global` rule resolves to right now: direct, vpn or a proxy. The app
picks the active bridge from interface state (a wired adapter wins) and pushes it to the engine;
`.vpn` resolves to the VPN when its core is up, else to block so a "VPN only" rule never leaks.

## Cores

- VPN = Xray-core, run as a managed child process. The provider's subscription JSON is used as-is,
  with the inbound swapped for a local SOCKS inbound on a loopback port. Fetched with a Happ-style
  User-Agent over the system trust store. Geo routing (geosite/geoip) can run inside Xray or in our
  own rules (see GeoDB below). Typical configs are VLESS + REALITY.
- DPI bypass = tpws (zapret), run as a local SOCKS proxy. It is a MODIFIER on the direct path, not
  a bridge: applied to all direct traffic when no VPN/proxy is active, only to Direct rules
  otherwise, and never over a VPN or proxy (the tunnel already hides the SNI). Auto-tune probes the
  strategies against known-blocked hosts and picks the first that works.
- AnyConnect = openconnect for split-tunnel corporate access, runs as root for the utun and routes.
  Split routes are captured from the routing table by the tunnel's utun interface and added to a
  dynamic pf bypass so corp traffic reaches the tunnel while the rest keeps flowing. The vpnc-script
  is wrapped so it does not write the pushed DNS onto the system interfaces.

## GeoDB

`geosite:`/`geoip:` rule targets are matched by the engine against `geosite.dat`/`geoip.dat`
(`ProxyGateEngine/GeoDB.swift`, a hand-written v2fly protobuf reader, lazy per-category index).
Those `.dat` files ship inside the Xray release zip, so geo targets only match once the VPN core is
installed.

## Versioning

`PGConstants.version` is the app-to-engine handshake version. Bump it after any engine change so
the app reinstalls the helper. App-only changes do not need a bump.

## Downloaded cores

Xray and tpws are downloaded by the app, SHA256-verified, then handed to the engine, which
re-verifies before install. Verify before clearing the quarantine xattr. See [security] for the
supply-chain caveat under network TLS inspection.

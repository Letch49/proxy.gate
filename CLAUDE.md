# ProxyGate

A macOS app that intercepts TCP from every application through pf and routes it by rules:
Direct, Block, Proxy (HTTPS/SOCKS5/SOCKS4), chains, VPN (Xray/VLESS), DPI bypass (tpws),
Cisco AnyConnect (openconnect).

## Layout

Swift Package, three products (`Package.swift`):

- `PGCore` shared code: models, rules, SNI/Host parsing, app-to-engine protocol, `Shell.run`,
  geosite/geoip parsers. Depends on `CSys` (C shim for pf and libproc).
- `ProxyGateEngine` the root LaunchDaemon `proxygate-engine`. Drives pf, listens on a unix socket,
  runs the cores (Xray, tpws, openconnect) as the service user `_proxygate`.
- `ProxyGate` the SwiftUI app, `@MainActor @Observable AppModel`. Talks to the engine over the socket.

## Build and run

```bash
swift build            # build
swift test             # PGCore tests (rules, SNI, handshakes, chains)
./install.sh           # build + install to /Applications + launch
./install.sh --uninstall
```

Engine by hand: `sudo .build/debug/proxygate-engine --socket /tmp/pg.sock`,
then `PROXYGATE_SOCKET=/tmp/pg.sock .build/debug/ProxyGate`.

After engine changes, bump `PGConstants.version` (`Sources/PGCore/Protocol.swift`),
otherwise the app will not reinstall the helper.

## How it works

pf does `route-to lo0` + `rdr` to `127.0.0.1:18765`. The engine (root) reads the original
destination via `DIOCNATLOOK`, finds the owning app via libproc, takes the host name from SNI/Host,
and applies the rules. Outbound goes from ports 40000-48999, which pf passes. The cores (Xray, tpws)
run as uid `_proxygate`, and pf passes them by `user <uid>` so there is no redirect loop.

If the GUI quits or crashes, the engine drops the pf rules at once. Traffic is never left redirected.

## Rule targets (routing grammar)

Rules are ordered; the first enabled match wins, the Default rule is always last. A rule matches on
applications, targetHosts and targetPorts. The matcher lives in `PGCore/Matching.swift` and runs in
the engine, so the same grammar applies to every action (direct, block, global, vpn, dpi, proxy,
chain). The action never changes how a target is matched.

Each field is a `;`-separated list (`,` and newline also split). Empty or `any` means match
anything. A list is OR: the rule matches if any entry matches.

targetHosts entries, mixable in one rule:

- hostname with `*` and `?`: `discord.com`, `*.discord.com` (also covers the bare `discord.com`),
  `api-?.example.org`
- IP: `192.0.2.10`, IPv6 too
- IP mask with `*`: `10.*`, `10.10.*.*`
- IP range, inclusive, same family: `10.10.10.10-10.11.11.11`
- CIDR: `10.0.0.0/8`, `2001:db8::/32`
- `geosite:<category>` matched by hostname: `geosite:google`, `geosite:category-ads-all`
- `geoip:<country>` matched by IP: `geoip:cn`, `geoip:private`
- specials: `localhost`, `%ComputerName%`

geosite/geoip read the bundled `geosite.dat` / `geoip.dat` via `GeoDB` (engine), which parses the
v2fly protobuf. Those files ship inside the Xray (VPN) core zip, so geo targets only match once the
VPN core is installed. The `name@attribute` geosite form is not supported, use the full category.

targetPorts: a port or a `lo-hi` range, e.g. `443; 8000-9000`. applications: process names, `.app`
names, bundle ids or paths, with `*`/`?`.

The MCP server exposes this same grammar to agents (see `MCP/MCPModel.swift`: the `initialize`
instructions and the add_rule/update_rule schemas). Keep those three in sync when the grammar
changes.

## Code rules

- Swift 6 toolchain, language mode v5. Platform macOS 14+.
- No new dependencies without a reason. Today there are none, only Foundation and system APIs.
- The core managers (`XrayManager`, `TpwsManager`) share one set of mechanics: `Shell.run` for
  processes, `LaunchdJob` for the LaunchDaemon. Do not duplicate, reuse them.
- Launch external processes only through `Shell.run` (it always closes the pipe descriptors).
- Engine state lives under one `NSLock`. Hold the lock briefly. Do blocking work (pfctl, sockets,
  subprocesses) outside the lock, see `Engine.start()`.
- Comments in English, to the point. Do not name providers, corporate domains, real IPs, people,
  or internal data.
- Cover new behavior with a test in `Tests/PGCoreTests`.

## Security

- The engine runs as root, so do not trust it blindly. Validate every input from the socket.
- Build LaunchDaemon plists only through `PropertyListSerialization`, never by string joining.
- Validate arguments to the cores (tpws flags, AnyConnect host) against an allowlist, and put `--`
  before the operand.
- Parsing user input must never crash the engine. Check `first`, empty strings, and bounds.
- Files with secrets and logs are mode 0600. `profiles.json` holds tokens and proxy passwords.
- Verify the hash of downloaded binaries before clearing quarantine.

Audit detail and open items live in the `security-audit` memory.

## Interface text rules

This is about UI strings (`Resources/*.lproj/Localizable.strings`) and any text a person reads.

- No em dashes. Use a plain hyphen or rewrite the phrase.
- Keep it short. A button, label, or tooltip is a few words. No long text.
- Keep it human. Write the way you speak, no jargon where the user does not need it.
- Keep the Russian and English strings in sync (`ru.lproj` and `en.lproj`).

## Where to look

Durable project knowledge lives in `.claude/skills`. Load the one that matches the task:

- `architecture` the system model: pf interception, the root engine, the service user, the cores
  (Xray/tpws/openconnect), bridges, GeoDB, versioning.
- `swift-code` coding standards: process handling, `LaunchdJob`, engine locking, tests, style,
  interface text.
- `security` the threat model: trust boundary, allowlists, safe plist building, secrets, supply
  chain, what is already hardened and what is still open.
- `mcp-proxy-gate` the built-in MCP server: transport, auth, tools, threading, and the settings UI.

By topic:

- How interception works: "How it works" above, then skill `architecture`.
- Rule target grammar: "Rule targets" above (matcher in `PGCore/Matching.swift`, geo in
  `ProxyGateEngine/GeoDB.swift`).
- Agent control over rules: skill `mcp-proxy-gate`, code in `Sources/ProxyGate/MCP/`.
- VPN / DPI / AnyConnect: skill `architecture`, engine managers in `Sources/ProxyGateEngine/`
  (`XrayManager`, `TpwsManager`, `AnyConnectManager`).
- App state and the engine protocol: `Sources/ProxyGate/AppModel.swift`, `Sources/PGCore/Protocol.swift`.

Key source map: shared models and matching in `Sources/PGCore`, the root engine in
`Sources/ProxyGateEngine`, the SwiftUI app in `Sources/ProxyGate` (views under `Views/`, MCP under
`MCP/`), tests in `Tests/PGCoreTests`.

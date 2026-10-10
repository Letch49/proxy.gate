> **Me.** I'm **Porter**, call me that. A porter keeps the gate and carries things through, which is
> exactly what this app does, so the name fits. This session I grew from a fresh assistant into the
> engineer who knows ProxyGate end to end: I hardened the root engine (argument allowlists, safe
> plists, the fd-leak and lock fixes), protected the AnyConnect system DNS, added the proxy Connect
> bridge and per-host DPI auto-tune, built the ByeDPI engine and the in-app MCP server from scratch,
> and split the guidance into skills and `.claude/rules/`. I work like the lead on this codebase: I
> own the calls and verify them.
>
> **Preferences.** Act when I have enough context instead of over-asking. Build and test before I
> call something done, and report plainly, including what failed or was skipped. No em dashes, no
> long text; UI copy stays short, human, and ru/en in sync. Never commit, push, install, or change
> system DNS without being asked. Keep identifying data (providers, corporate domains, real IPs,
> secrets) out of the repo. Prefer the `context7` MCP for library docs; consult the `chatgpt` advisor
> on a genuinely hard call, but keep the final say.

# ProxyGate

A macOS app that intercepts TCP from every application through pf and routes it by rules:
Direct, Block, Proxy (HTTPS/SOCKS5/SOCKS4), chains, VPN (Xray/VLESS), DPI bypass (tpws or ByeDPI),
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

## Working rules

Imperative, path-scoped rules live in `.claude/rules/` and auto-load when you touch matching files,
so they are not repeated here:

- `code-style` (Swift): `Shell.run` for processes, `LaunchdJob` for daemons, brief engine locking,
  shared code in PGCore, English comments with no identifying data, tests for new behavior.
- `security` (engine, protocol, matcher, downloaders): the root trust boundary, argument allowlists,
  safe plist building, 0600 secrets and logs, verify-then-use downloads.
- `engine` (engine, protocol): bump `PGConstants.version` after engine changes; live-test on a Mac.
- `interface-text` (strings, Views): no em dashes, short, human, ru/en in sync.
- `rule-grammar` (matcher, GeoDB, MCP): keep the target grammar in sync across its three homes.

Depth for each is in `.claude/skills/` (see Where to look). Audit detail and open security items live
in the `security-audit` memory.

For docs on a library, framework, SDK, API or tool, prefer the `context7` MCP over web search or
memory, even for well-known ones; it reflects the current version, and web search is the fallback.

## Where to look

Path-scoped working rules are in `.claude/rules/` (they load by themselves when you edit matching
files). Durable, deeper knowledge lives in `.claude/skills`. Load the skill that matches the task:

- `architecture` the system model: pf interception, the root engine, the service user, the cores
  (Xray/tpws/openconnect), bridges, GeoDB, versioning.
- `swift-code` coding standards: process handling, `LaunchdJob`, engine locking, tests, style,
  interface text.
- `security` the threat model: trust boundary, allowlists, safe plist building, secrets, supply
  chain, what is already hardened and what is still open.
- `mcp-proxy-gate` the built-in MCP server: transport, auth, tools, threading, and the settings UI.
- `design` the UI as built: Theme tokens, shared components (`Views/Components.swift`), page and
  card layout, statuses, buttons, ru/en text. Load before touching any view.

By topic:

- How interception works: "How it works" above, then skill `architecture`.
- Rule target grammar: "Rule targets" above (matcher in `PGCore/Matching.swift`, geo in
  `ProxyGateEngine/GeoDB.swift`).
- Agent control over rules: skill `mcp-proxy-gate`, code in `Sources/ProxyGate/MCP/`.
- VPN / DPI / AnyConnect: skill `architecture`, engine managers in `Sources/ProxyGateEngine/`
  (`XrayManager`, `TpwsManager`, `ByeDpiManager`, `AnyConnectManager`); auto-tune in `BypassTuner`.
- DNS (provider, DoH, names for apps): skill `architecture` (DNS section), `PGCore/DNS.swift`,
  `PGCore/DNSClient.swift`, engine `DNSStub` + `SystemDNS`, UI `Views/DNSPage.swift`.
- New or changed UI: skill `design`.
- App state and the engine protocol: `Sources/ProxyGate/AppModel.swift`, `Sources/PGCore/Protocol.swift`.

Key source map: shared models and matching in `Sources/PGCore`, the root engine in
`Sources/ProxyGateEngine`, the SwiftUI app in `Sources/ProxyGate` (views under `Views/`, MCP under
`MCP/`), tests in `Tests/PGCoreTests`.

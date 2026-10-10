---
name: mcp-proxy-gate
description: ProxyGate's built-in MCP server. Load when touching MCP/MCPServer.swift, MCP/MCPModel.swift, the tool surface, the rule-target grammar exposed to agents, or the MCP settings UI.
---

# ProxyGate MCP server

A local, token-authenticated MCP endpoint in the app, so an AI agent can manage rules and read the
journal and stats.

## Files

- `Sources/ProxyGate/MCP/MCPServer.swift`: a tiny HTTP server on `NWListener`, bound to 127.0.0.1
  only. Speaks the MCP Streamable HTTP transport (JSON-RPC over HTTP POST, a single
  `application/json` reply per request, no SSE).
- `Sources/ProxyGate/MCP/MCPModel.swift`: an `AppModel` extension with the token handling, the tool
  catalogue and the dispatch that reads and edits rules.

## Transport and auth

- One endpoint, POST only (GET returns 405, we offer no server-initiated SSE).
- Bearer token required on every request, compared in constant time. Missing or wrong -> 401.
- Origin is checked (localhost only) as a DNS-rebinding guard; native agents send no Origin.
- Methods: `initialize` (returns `instructions` that teach the agent the capabilities, the actions
  and the full target grammar), `ping`, `tools/list`, `tools/call`. Notifications -> 202.

## Tools

Read: `list_rules`, `list_targets` (proxies, chains, symbolic actions, and the `vpnAvailable` /
`dpiAvailable` / `geoAvailable` flags), `get_log`, `get_stats`, `get_status`.
Write: `add_rule`, `update_rule`, `delete_rule`, `move_rule`.

Scope is deliberate: read plus rules CRUD only. An agent cannot start redirection or change
VPN/DPI/AnyConnect. Default, locked and dynamic rules are protected from edit, delete and move.

## State and threading

- Settings live in `UserDefaults` (`mcpEnabled`, `mcpPort`, default `MCPServer.defaultPort` =
  18766), the token in the Keychain, `mcpLastSeen` drives the "Active" status. `applyMCP()` starts,
  stops or rebinds the server.
- The server runs on a background queue; every model access hops to the main actor via `onMain`
  (`DispatchQueue.main.sync` + `MainActor.assumeIsolated`), because `AppModel` is `@MainActor`.

## UI

Its own sidebar page (`AppSection.mcp`, `Views/MCPPage.swift`), placed above the profile widget,
with a green dot when the server is running. Holds the toggle, status, address, port, token
(show/copy/regenerate) and a "Copy setup prompt" button (client-agnostic, user scope). Connect with
`claude mcp add --transport http ... --header "Authorization: Bearer <token>"`.

## Keeping the grammar in sync

The rule-target grammar lives in three places that must agree: the matcher
(`PGCore/Matching.swift` + `ProxyGateEngine/GeoDB.swift`), the "Rule targets" section of CLAUDE.md,
and this server (the `initialize` instructions plus the `add_rule`/`update_rule` schemas). Change
one, change all three. See [architecture].

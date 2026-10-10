---
paths:
  - "Sources/PGCore/Matching.swift"
  - "Sources/ProxyGateEngine/GeoDB.swift"
  - "Sources/ProxyGate/MCP/**/*.swift"
---

# Rule-target grammar and MCP

- The target grammar lives in three places that must agree: the matcher (`PGCore/Matching.swift` plus `ProxyGateEngine/GeoDB.swift`), the "Rule targets" section of CLAUDE.md, and the MCP server (the `initialize` instructions plus the `add_rule`/`update_rule` schemas in `MCP/MCPModel.swift`). Change one, change all three.
- Matching is action-independent: the same target grammar works for direct, block, global, vpn, dpi, proxy and chain.
- The MCP server runs off the main actor. Reach `AppModel` state only through `onMain`, because `AppModel` is `@MainActor`.
- MCP scope is read plus rules CRUD only; it cannot start redirection or change VPN/DPI/AnyConnect. Keep that boundary.

Depth: skill `mcp-proxy-gate`.

---
paths:
  - "Sources/ProxyGateEngine/**/*.swift"
  - "Sources/PGCore/Protocol.swift"
---

# Engine changes

- After any engine change, bump `PGConstants.version` (`Sources/PGCore/Protocol.swift`) so the app reinstalls the helper. App-only changes do not need a bump.
- The engine runs as a root LaunchDaemon; cores run as the `_proxygate` service user, and pf passes their outbound by `user <uid>` (loop prevention). Keep that model.
- Real interception, VPN, DPI and AnyConnect can only be exercised on a real Mac with an admin password. After engine changes, ask the user to test live, and tell them to Reinstall Helper.

Depth: skill `architecture`.

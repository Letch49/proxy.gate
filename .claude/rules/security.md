---
paths:
  - "Sources/ProxyGateEngine/**/*.swift"
  - "Sources/PGCore/Protocol.swift"
  - "Sources/PGCore/Matching.swift"
  - "Sources/ProxyGate/*Downloader.swift"
---

# Security (the engine runs as root)

- Everything from the control socket is untrusted (the peer is checked by uid and the pinned app cdhash, but still validate). Validate every field before acting; never pass socket data into a shell, a path, or a plist.
- Build LaunchDaemon plists only through `PropertyListSerialization`, never by string interpolation (interpolating untrusted args into XML is a root RCE).
- Allowlist core arguments before they reach a command line: tpws `TpwsManager.validStrategy`, ByeDPI `ByeDpiStrategies.valid`, AnyConnect `isSafeServer` / `isSafeUser` (reject a leading `-`). Put `--` before any operand that could look like a flag.
- Parsing must never crash the root engine: guard `first`, empty strings, and bounds; cover with a test.
- Secret-bearing files and logs are mode 0600. The AnyConnect password lives in the Keychain, not on disk. Never log or comment a token, password, real host, or real IP.
- Verify a downloaded binary's SHA256 before clearing the quarantine xattr; under TLS inspection prefer a hash pinned in code (see `ByeDpiDownloader`).

Depth: skill `security`.

---
name: security
description: ProxyGate security rules. Load when touching the root engine, the control socket, launchd plists, external cores (Xray, tpws, openconnect), downloads and hashes, secrets, or user input parsing.
---

# ProxyGate security

The engine runs as root. A fault here is a root exploit, so hold this line.

## Trust boundary

- Everything from the control socket is untrusted. The peer could be any local process.
- The socket checks the peer's uid and, in an installed helper, the app's pinned cdhash (audit
  token). Still validate every field before acting; a manual dev run checks the uid only.
- Validate input, then act. Never pass socket data straight into a shell, a path, or a plist.

## Processes and arguments

- Launch external tools only through `Shell.run`. It closes pipe descriptors, so no fd leak.
- Validate arguments to the cores against an allowlist before they reach a command line:
  - tpws flags: `TpwsManager.validStrategy` (option-name allowlist of desync options plus a value
    regex; no bind, user, hostlist, ipset or debug options).
  - ByeDPI flags: `ByeDpiStrategies.valid` (desync letters only, no `-i/-p/-l/-H`, no `-f/-S`).
  - AnyConnect host and user: `isSafeServer` / `isSafeUser`, reject a leading `-`.
- Put `--` before any operand that could look like a flag.

## LaunchDaemon plists

- Build plists from a dictionary with `PropertyListSerialization`, never by string interpolation.
  Interpolating untrusted args into XML is a root RCE.
- Write them root owned, mode 644, through `LaunchdJob.writePlist`.

## Parsing must not crash

- The engine must survive junk input. A crash is a denial of service on root.
- Guard `first`, empty strings, and bounds in rule, network, and port parsing. Example paths:
  `PFRules.validNetworks`, `Matching.parsePorts`, `RuleShadow`. Cover each with a test.

## Secrets and logs

- `profiles.json` holds proxy passwords and subscription tokens. Mode 0600.
- Logs can hold connection targets. Create them mode 0600, owned by the service user.
- The AnyConnect password lives in the Keychain, not on disk.
- Never log or comment a token, a password, a real host, or a real IP.

## Downloads and supply chain

- Verify the SHA256 of a downloaded binary before use.
- Verify before clearing the quarantine xattr, not after.
- The corporate network does TLS inspection, so a plain TLS fetch of a hash is not a strong anchor.
  Prefer a hash pinned in code or a signature check. Flag this when you touch the download path.

## Open items

These are known and not yet fixed. Do not regress them, and prefer fixing over working around:

- Binary hashes come over TLS with no pinning under corporate MITM.
- A raw Xray config string can open a non loopback inbound. Force inbound to 127.0.0.1 server side.
- The helper install script lands in a user writable temp dir (TOCTOU). Prefer SMAppService.

## Already hardened (do not regress)

A security pass fixed these; keep them in place:

- LaunchDaemon plists are built via `PropertyListSerialization`, never string interpolation.
- Control socket auth: besides the uid, the peer must be the app build whose cdhash the helper pins
  (`--client-cdhash`, checked via the `LOCAL_PEERTOKEN` audit token and `SecCodeCheckValidity`).
  Uid-only fallback is only for manual dev runs without a pin.
- tpws flags and the AnyConnect host/user are allowlisted before they reach a command line.
- Core installs take no hash from the client: the engine copies the named file with `O_NOFOLLOW`
  (regular file, size-capped) into a root-only staging dir, hashes that copy, and checks it against
  a hash it gets itself (ByeDPI pinned in `CoreReleases`; Xray `.dgst` and zapret `sha256sum.txt`
  fetched from a URL built from a validated tag). Unzip/tar/move run only on the staged copy.
- Every external process goes through `Shell.run`, which closes pipe descriptors (no fd leak).
- Rule, network and port parsing guards `first`/empty/bounds, so junk input cannot crash the engine.
- Secret-bearing files and logs are mode 0600.
- `Engine.start()` does the blocking pf/listen/subprocess work outside the lock.
- DPI cores listen on 127.0.0.1 only (tpws gets `--bind-addr=127.0.0.1`; without it tpws is an
  open SOCKS proxy on every interface).
- `/etc/resolver` files: domain names pass `DNSDomainList.isAllowed` (no `/`, `..`, wildcards,
  `local`, `arpa`), are written only by `SystemDNS`, never follow a symlink, and only files with our
  marker are replaced or removed. DNS providers from the socket are re-checked (`DNSProvider.isValid`).
- The DNS stub answers only the listed domains (REFUSED otherwise) and ignores replies whose id or
  question do not match.

## Before you finish

Re-read your diff for: an unvalidated socket field, a string built into a plist or shell, a parse
that can crash, a secret in a log or comment. `swift test` green.

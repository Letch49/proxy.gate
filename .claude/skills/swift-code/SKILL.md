---
name: swift-code
description: ProxyGate code standards. Load when writing or editing Swift in this project: core managers, process handling, engine locking, tests, comment style, and interface text.
---

# ProxyGate code

How to write and edit Swift in this project.

## Layout

Three targets in `Package.swift`:

- `PGCore` shared code, depends on `CSys`.
- `ProxyGateEngine` the root engine.
- `ProxyGate` the SwiftUI app.

Put shared code in `PGCore`, do not copy between targets. Keep engine logic out of the app.

## Processes and cores

- Launch any external process through `Shell.run` (`PGCore/Shell.swift`). It is the one place that
  closes the pipe descriptors, so the leak cannot return. Do not build `Process` by hand.
- Drive LaunchDaemons (Xray, tpws) through `LaunchdJob`: `writePlist`, `prepareLog`, `bootstrap`,
  `bootout`, `running`. Do not repeat these steps in the managers.
- Build plists from a dictionary with `PropertyListSerialization`, never by joining strings.

## Locking in the engine

- Engine state lives under one `NSLock`, reached through `withLock`.
- Hold the lock briefly, only to read or write fields.
- Do blocking work (pfctl, bind, subprocesses, resolve) outside the lock. See `Engine.start()`:
  under the lock it claims the slot and copies the settings, the heavy work runs without the lock,
  and a short final section writes the state with a rollback if a `stop()` slipped in.

## Style

- Swift 6 toolchain, language mode v5, macOS 14+.
- Do not add dependencies. Today it is only Foundation and system APIs.
- Clear names, no shortening for its own sake. Code reads like the code next to it.
- Comments in English and to the point: say why, not what. A short comment beats a long one.
  Do not name providers, corporate domains, real IPs, people, or internal data in comments.

## Tests

- Cover new behavior with a test in `Tests/PGCoreTests`. Run `swift test` before you hand off.
- Test rule parsing, SNI and Host, proxy handshakes, chains, and resistance to junk input.

## Interface text

Strings in `Resources/*.lproj/Localizable.strings` and any text a person reads:

- No em dashes. Use a plain hyphen or rewrite the phrase.
- Short and human.
- The Russian and English strings go as a pair.

## Before you finish

`swift build` and `swift test` green. After engine changes bump `PGConstants.version` in
`Protocol.swift`. Commit and push only when the user asks.

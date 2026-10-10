---
paths:
  - "Sources/**/*.swift"
  - "Tests/**/*.swift"
---

# Code style

- Swift 6 toolchain, language mode v5, macOS 14+. No new dependencies (only Foundation and system APIs).
- Launch external processes only through `Shell.run` (`PGCore/Shell.swift`); never build `Process` by hand.
- Drive LaunchDaemons through `LaunchdJob` (`writePlist`/`prepareLog`/`bootstrap`/`bootout`/`running`); do not repeat these steps in the managers.
- Build plists from a dictionary with `PropertyListSerialization`, never by joining strings.
- Engine state lives under one `NSLock`; hold it briefly, and do blocking work (pfctl, bind, subprocess, resolve) outside it (see `Engine.start()`).
- Put shared code in `PGCore`, do not copy between targets; keep engine logic out of the app.
- Comments in English and to the point (say why, not what). Never name providers, corporate domains, real IPs, people, or internal data.
- Cover new behavior with a test in `Tests/PGCoreTests`; run `swift build` and `swift test` before handing off.

Depth: skill `swift-code`.

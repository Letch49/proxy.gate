---
paths:
  - "Resources/**/*.strings"
  - "Sources/ProxyGate/Views/**/*.swift"
---

# Interface text

For UI strings (`Resources/*.lproj/Localizable.strings`) and any text a person reads:

- No em dashes. Use a plain hyphen or rewrite the phrase.
- Keep it short. A button, label, or tooltip is a few words. No long text.
- Keep it human. Write the way you speak, no jargon where the user does not need it.
- Keep the Russian and English strings in sync (`ru.lproj` and `en.lproj`). A new English literal needs a matching `ru.lproj` entry.

Depth: skill `design` (components, tokens, localization), skill `swift-code`.

---
name: design
description: ProxyGate UI design system as it exists in the code. Load before adding or changing any SwiftUI view, page, card, row, status, button or interface string, so new UI matches Theme, the shared components and the ru/en rules.
---

# ProxyGate UI

What the app already uses. Reuse it; do not invent new colors, sizes or components for one screen.
Code rules are in [swift-code], text rules in `.claude/rules/interface-text.md`.

## Where things live

- Tokens and base pieces: `Sources/ProxyGate/Views/Theme.swift` (`Theme`, `Pill`, `.card()`,
  `AccentButtonStyle`, `GhostButtonStyle`, `PageHeader`, `FlowLayout`).
- Shared building blocks: `Sources/ProxyGate/Views/Components.swift` (`StatusTone`, `StatusPill`,
  `ToggleCard`, `NoticeBanner`, `SectionHeader`, `ChoiceRow`, `DiagnosticRow`, `RowDivider`).
- Pages: one file per sidebar page in `Views/` (`DPIPage`, `DNSPage`, `VPNPage`, `MCPPage`,
  `AnyConnectPage`, `SettingsPages`, `RulesPage`, `ProxiesPage`). Sidebar entries and icons:
  `AppSection` in `AppModel.swift`. Window shell: `MainView.swift` (sidebar 224 pt, `Theme.sidebar`).
- Page-private views stay `private struct` in the page file (`DNSProviderRow`, `TuneReportCard`).
  Move a view to `Components.swift` once a second page needs it.

## Tokens (Theme.swift)

- Grounds: `window`, `sidebar`, `header`, `card` (card fill), `surface` (rows inside cards),
  `raised` (pressed, icon tiles). Lines: `border`, `borderStrong` (warning banners).
- Text: `text` (primary), `text2` (notes under titles, row details), `text3` (captions, hints).
- Accent (teal): `accent` (radio mark, primary button), `accentBg`, `accentFg`, `accentBorder`
  (border of a card whose feature is on or selected).
- State pairs, always with a text label, never color alone: `onBg/onFg` (ok, running),
  `warnBg/warnFg` (attention, starting, warnings), `offBg/offFg` (failed, destructive),
  `neutralBg/neutralFg` (counts, "Installed"). Use them through `StatusTone`.
- Chips: `hostChipBg/Fg` (hosts, also the mono subject in `DiagnosticRow`), `appChip*`, `portChip*`.
- Font: `Theme.mono` (12 pt monospaced) for hosts, IPs, flags, URLs, tokens. No other custom font.

## Type scale in use

| Use | Font |
| --- | --- |
| Page title (`PageHeader`) | 22 semibold, subtitle default size in `text2` |
| Section title (`SectionHeader`) | 15 semibold |
| Card title (`ToggleCard`, engine cards) | 13-13.5 semibold |
| Row title (`ChoiceRow`) | 13.5 |
| Note under a title | 11-11.5 in `text2` |
| Row detail | 12 in `text2` |
| Caption / hint under a block | `.caption` in `text3` |
| Error or warning line | `.caption` in `warnFg`, `.textSelection(.enabled)` for engine errors |

## Layout

- Card pages (DPI, DNS, VPN, MCP, AnyConnect): `ScrollView { VStack(alignment: .leading, spacing: 18) }`
  with `.padding(.horizontal, 24).padding(.vertical, 18)`. `PageHeader` first, actions in its
  trailing slot.
- Form pages (Settings, editors): `Form { Section }` with `.formStyle(.grouped)` and
  `.scrollContentBackground(.hidden)`; `PageHeader` above it padded 24/18. Use a Form only for long
  lists of plain settings; feature pages with status use cards.
- Cards: `.card(radius: 12)`; padding 14 (status cards, lists) or 16 (forms inside a card).
  Border `Theme.accentBorder` while the feature is on or the item is selected.
- Rows inside lists: `ChoiceRow` (padding 12/10, radius 9, `surface` fill, accent when selected),
  stacked in `VStack(spacing: 8)`.
- Result tables: `VStack(spacing: 0)` of `DiagnosticRow`s with `RowDivider()` between, wrapped in
  `.card(radius: 12)` (see `DNSCheckCard`, `TuneReportCard`).

## Components and when to use them

- `PageHeader(title:subtitle:) { actions }`: every page. Subtitle is one short line.
- `ToggleCard(isOn:title:note:disabled:) { trailing }`: the main switch of a feature (DPI bypass,
  DNS for apps, MCP). Trailing is a `StatusPill` (Running / Starting… / Active / Error).
- `NoticeBanner(text:) { action }`: "not installed" or blocking problems on top of a page. Action is
  a `GhostButtonStyle` button ("Open Settings").
- `SectionHeader(title:) { actions }`: a titled block with buttons on the right (Strategy +
  Auto-tune/Stop, Provider + transport picker + Add).
- `ChoiceRow(title:detail:selected:onTap:) { trailing }`: single choice from a list (DPI strategy,
  DNS provider). `detail` is mono (flags, IP). Trailing holds pills and a trash button.
- `DiagnosticRow(subject:detail:status:tone:)`: one checked thing and its verdict (DNS resolver,
  auto-tune host). Subject mono, detail localized, status in a pill.
- `StatusPill(text:tone:)`: any state badge. Map: ok -> `.ok`, in progress/attention -> `.warn`,
  failed -> `.fail`, informational -> `.neutral`, highlighted choice -> `.accent`.
- Buttons: `AccentButtonStyle` for the one primary action of a block (Auto-tune, Check, Connect,
  Add in a form). `GhostButtonStyle` for secondary ones; `GhostButtonStyle(destructive: true)` for
  Stop, Disconnect, delete.
- Busy state: `ProgressView().controlSize(.small)` next to the action, plus a short `.caption` text
  in `text3`; offer Stop when the work is long (auto-tune).
- Switches: `.toggleStyle(.switch).controlSize(.mini).labelsHidden()` inside cards; plain
  `Toggle("label")` inside a card form block (DNS hostname detection) or a Form.
- Chips that can be removed: see the autohostlist in `DPIPage` (`FlowLayout`, `hostChip*`, xmark).

## Composition rules

- Plain SwiftUI: small `View` structs with `let` parameters and `@Binding`, `@ViewBuilder` slots
  for content, `ViewModifier` (`CardBackground`) for shared decoration. Read the model with
  `@Environment(AppModel.self)`; edit with `@Bindable var model = model`.
- One data model per concept. DNS settings live in `Profile.dns` and are shown on the DNS page; the
  DPI page reads the same provider (`model.profile.dns.upstream`), it never keeps its own copy.
- No UI dependencies, no form builders, no framework layers.

## Text and localization

- English strings are the keys (`Resources/en.lproj` has no entries); every new literal needs a
  `Resources/ru.lproj/Localizable.strings` entry. Interpolations become `%@` (String) or `%lld` (Int).
- Literals in `Text("...")`, `Button("...")`, `LocalizedStringKey` parameters localize on their own.
  Computed text uses `String(localized: "...")`. Brand names, flags, hosts, example values:
  `Text(verbatim:)` or a plain `String`.
- Engine messages that the UI shows as-is are fixed English sentences with a ru entry, looked up via
  `LocalizedStringKey(message)` (see `AnyConnectPage`).
- Short and human: a button is 1-3 words, a note one line, a caption one or two sentences. No em
  dashes. Say what the user can do, not how it works inside.
- Never claim more than was checked ("Found" for a DNS answer, not "works"; a page that opens is not
  video that plays).

## Checking new UI

1. Same structure as the neighbour page: `PageHeader`, 18 pt rhythm, cards 12 pt radius.
2. Only `Theme` colors and `StatusTone`; no hex in views (Theme.swift is the one place).
3. Every state has a label; errors are selectable text in `warnFg`.
4. Run the RU check: each new English literal has a ru entry, `plutil -lint` passes.
5. `swift build`; then look at the page in the running app in both languages if you can launch it
   without taking the engine away from a running copy (one app per engine socket).

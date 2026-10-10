import SwiftUI

// Reusable pieces of the card-style pages (DPI, DNS, MCP, VPN, AnyConnect). Colors and fonts come
// from Theme; see the `design` skill for when to use which.

/// Meaning of a status, mapped to the Theme state colors. Always shown with a text label.
enum StatusTone {
    case ok, warn, fail, neutral, accent

    var colors: (bg: Color, fg: Color) {
        switch self {
        case .ok: return (Theme.onBg, Theme.onFg)
        case .warn: return (Theme.warnBg, Theme.warnFg)
        case .fail: return (Theme.offBg, Theme.offFg)
        case .neutral: return (Theme.neutralBg, Theme.neutralFg)
        case .accent: return (Theme.accentBg, Theme.accentFg)
        }
    }
}

struct StatusPill: View {
    let text: String
    var tone: StatusTone = .neutral

    var body: some View {
        Pill(text: text, bg: tone.colors.bg, fg: tone.colors.fg)
    }
}

/// The main on/off switch of a feature: mini switch, bold title, one-line note, status on the right.
/// The card border turns accent while it is on.
struct ToggleCard<Trailing: View>: View {
    @Binding var isOn: Bool
    let title: LocalizedStringKey
    let note: String
    var disabled = false
    @ViewBuilder var trailing: Trailing

    var body: some View {
        HStack(spacing: 14) {
            Toggle("", isOn: $isOn)
                .toggleStyle(.switch).controlSize(.mini).labelsHidden()
                .disabled(disabled)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .semibold))
                Text(note).font(.system(size: 11)).foregroundStyle(Theme.text2).lineLimit(2)
            }
            Spacer()
            trailing
        }
        .padding(.horizontal, 14).padding(.vertical, 11)
        .card(radius: 12, border: isOn ? Theme.accentBorder : Theme.border)
    }
}

/// A warning strip on top of a page ("not installed", "needs attention"), with an optional action.
struct NoticeBanner<Action: View>: View {
    let text: String
    @ViewBuilder var action: Action

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warnFg)
            Text(text).fixedSize(horizontal: false, vertical: true)
            Spacer()
            action
        }
        .padding(14).card(radius: 12, border: Theme.borderStrong)
    }
}

extension NoticeBanner where Action == EmptyView {
    init(text: String) {
        self.init(text: text) { EmptyView() }
    }
}

/// A section title inside a page, with actions on the right (like the DPI "Strategy" row).
struct SectionHeader<Actions: View>: View {
    let title: LocalizedStringKey
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(spacing: 8) {
            Text(title).font(.system(size: 15, weight: .semibold))
            Spacer()
            actions
        }
    }
}

extension SectionHeader where Actions == EmptyView {
    init(_ title: LocalizedStringKey) {
        self.init(title: title) { EmptyView() }
    }
}

/// One choice of a single-select list: radio mark, title, a mono detail on the right, extra
/// trailing content (pills, a delete button).
struct ChoiceRow<Trailing: View>: View {
    let title: String
    var detail: String?
    let selected: Bool
    let onTap: () -> Void
    @ViewBuilder var trailing: Trailing

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Theme.accent : Theme.text3)
                Text(title).font(.system(size: 13.5))
                Spacer()
                if let detail {
                    Text(detail).font(Theme.mono).foregroundStyle(Theme.text3).lineLimit(1).truncationMode(.middle)
                }
                trailing
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .background(selected ? Theme.accentBg.opacity(0.5) : Theme.surface, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(selected ? Theme.accentBorder : Theme.border))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

extension ChoiceRow where Trailing == EmptyView {
    init(title: String, detail: String? = nil, selected: Bool, onTap: @escaping () -> Void) {
        self.init(title: title, detail: detail, selected: selected, onTap: onTap) { EmptyView() }
    }
}

/// A result line of a check: subject in mono, a short explanation, the status pill.
struct DiagnosticRow: View {
    let subject: String
    let detail: String
    let status: String
    var tone: StatusTone = .neutral

    var body: some View {
        HStack(spacing: 12) {
            Text(subject).font(Theme.mono).foregroundStyle(Theme.hostChipFg)
                .frame(width: 190, alignment: .leading).lineLimit(1).truncationMode(.middle)
            Text(detail).font(.system(size: 12)).foregroundStyle(Theme.text2)
                .frame(maxWidth: .infinity, alignment: .leading).lineLimit(2)
                .textSelection(.enabled)
            StatusPill(text: status, tone: tone)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

/// Hairline between rows of a result card (`VStack(spacing: 0)` + `.card(radius: 12)`).
struct RowDivider: View {
    var body: some View {
        Rectangle().fill(Theme.border).frame(height: 1)
    }
}

import AppKit
import PGCore
import SwiftUI

/// Colors of the approved redesign: graphite ground, teal accent; state colors always come
/// with a text label, never hue alone.
enum Theme {
    static let window = Color(hex: 0x121417)
    static let sidebar = Color(hex: 0x16191D)
    static let header = Color(hex: 0x15181B)
    static let card = Color(hex: 0x1A1D22)
    static let surface = Color(hex: 0x1C2025)
    static let raised = Color(hex: 0x23282E)
    static let border = Color(hex: 0x262B31)
    static let borderStrong = Color(hex: 0x353C44)

    static let text = Color(hex: 0xECEFF2)
    static let text2 = Color(hex: 0xA3ACB6)
    static let text3 = Color(hex: 0x8D97A2)

    static let accent = Color(hex: 0x2EC4B0)
    static let accentInk = Color(hex: 0x06201C)
    static let accentBg = Color(hex: 0x173230)
    static let accentFg = Color(hex: 0x7FE3D3)
    static let accentBorder = Color(hex: 0x2F5F59)

    static let on = Color(hex: 0x3DDC84)
    static let onBg = Color(hex: 0x17301F)
    static let onFg = Color(hex: 0x6FE9A4)
    static let offBg = Color(hex: 0x3A1F1D)
    static let offFg = Color(hex: 0xFFB3AB)
    static let warnBg = Color(hex: 0x3A2A12)
    static let warnFg = Color(hex: 0xF5B85A)

    static let neutralBg = Color(hex: 0x262B31)
    static let neutralFg = Color(hex: 0xC9D0D7)
    static let appChipBg = Color(hex: 0x262033)
    static let appChipFg = Color(hex: 0xCBB8FF)
    static let hostChipBg = Color(hex: 0x1D2A3A)
    static let hostChipFg = Color(hex: 0x9CC4FF)
    static let portChipBg = Color(hex: 0x2C2617)
    static let portChipFg = Color(hex: 0xF3C97A)

    static let mono = Font.system(size: 12, design: .monospaced)

    /// Pill colors for a route kind.
    static func route(_ kind: RouteKind?) -> (bg: Color, fg: Color) {
        switch kind {
        case .proxy, .chain: return (accentBg, accentFg)
        case .block: return (offBg, offFg)
        case .direct, .none: return (neutralBg, neutralFg)
        }
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255)
    }
}

struct Pill: View {
    let text: String
    var bg: Color = Theme.neutralBg
    var fg: Color = Theme.neutralFg
    var mono = false

    var body: some View {
        Text(text)
            .font(mono ? Theme.mono : .system(size: 12))
            .lineLimit(1)
            .truncationMode(.middle)
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .foregroundStyle(fg)
            .background(bg, in: Capsule())
    }
}

struct CardBackground: ViewModifier {
    var radius: CGFloat = 10
    var border: Color = Theme.border

    func body(content: Content) -> some View {
        content
            .background(Theme.card, in: RoundedRectangle(cornerRadius: radius))
            .overlay(RoundedRectangle(cornerRadius: radius).stroke(border))
    }
}

extension View {
    func card(radius: CGFloat = 10, border: Color = Theme.border) -> some View {
        modifier(CardBackground(radius: radius, border: border))
    }
}

struct AccentButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .foregroundStyle(Theme.accentInk)
            .background(Theme.accent.opacity(configuration.isPressed ? 0.8 : 1), in: RoundedRectangle(cornerRadius: 8))
    }
}

struct GhostButtonStyle: ButtonStyle {
    var destructive = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 12.5))
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .foregroundStyle(destructive ? Theme.offFg : Color(hex: 0xD5DBE1))
            .background((configuration.isPressed ? Theme.raised : Theme.surface), in: RoundedRectangle(cornerRadius: 7))
            .overlay(RoundedRectangle(cornerRadius: 7).stroke(destructive ? Color(hex: 0x4A2B28) : Color(hex: 0x2A3037)))
    }
}

/// Title + subtitle on top of a page, actions on the right.
struct PageHeader<Actions: View>: View {
    let title: LocalizedStringKey
    let subtitle: LocalizedStringKey
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(alignment: .center, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(.system(size: 22, weight: .semibold))
                Text(subtitle).foregroundStyle(Theme.text2)
            }
            Spacer()
            actions
        }
    }
}

/// Wrapping row of chips.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(width: proposal.width ?? .infinity, subviews: subviews)
        let height = rows.last.map { $0.y + $0.height } ?? 0
        let width = rows.map(\.width).max() ?? 0
        return CGSize(width: proposal.width ?? width, height: height)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        for row in arrange(width: bounds.width, subviews: subviews) {
            var x = bounds.minX
            for index in row.items {
                let size = subviews[index].sizeThatFits(.unspecified)
                subviews[index].place(at: CGPoint(x: x, y: bounds.minY + row.y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
        }
    }

    private struct Row {
        var items: [Int] = []
        var y: CGFloat = 0
        var width: CGFloat = 0
        var height: CGFloat = 0
    }

    private func arrange(width: CGFloat, subviews: Subviews) -> [Row] {
        var rows: [Row] = [Row()]
        for (index, view) in subviews.enumerated() {
            let size = view.sizeThatFits(.unspecified)
            if !rows[rows.count - 1].items.isEmpty && rows[rows.count - 1].width + spacing + size.width > width {
                let last = rows[rows.count - 1]
                rows.append(Row(y: last.y + last.height + spacing))
            }
            var row = rows[rows.count - 1]
            row.width += (row.items.isEmpty ? 0 : spacing) + size.width
            row.height = max(row.height, size.height)
            row.items.append(index)
            rows[rows.count - 1] = row
        }
        return rows
    }
}

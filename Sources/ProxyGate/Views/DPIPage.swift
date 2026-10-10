import PGCore
import SwiftUI

struct DPIPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "DPI bypass", subtitle: "Defeats ISP DPI on direct routes (zapret/tpws). It never touches VPN or proxy traffic.") {
                    if model.tpwsBusy {
                        ProgressView().controlSize(.small)
                        if let m = model.tpwsMessage { Text(m).font(.caption).foregroundStyle(Theme.text3) }
                    }
                    Button(model.tpwsVersion == nil ? "Install Core" : "Update Core") { model.installTpws() }
                        .buttonStyle(GhostButtonStyle())
                        .disabled(model.tpwsBusy || !model.engineConnected)
                }

                if model.tpwsVersion == nil {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warnFg)
                        Text("The DPI-bypass core (tpws) is not installed yet.")
                        Spacer()
                    }
                    .padding(14).card(radius: 12, border: Theme.borderStrong)
                }

                // Main switch
                HStack(spacing: 14) {
                    Toggle("", isOn: Binding(get: { model.bypassEnabled }, set: { model.setBypass($0) }))
                        .toggleStyle(.switch).controlSize(.mini).labelsHidden()
                        .disabled(model.tpwsVersion == nil)
                    VStack(alignment: .leading, spacing: 3) {
                        Text("DPI bypass").font(.system(size: 13, weight: .semibold))
                        Text(modeNote).font(.system(size: 11)).foregroundStyle(Theme.text2).lineLimit(1)
                    }
                    Spacer()
                    if model.bypassEnabled {
                        Pill(text: model.tpwsRunning ? "Running" : "Starting…",
                             bg: model.tpwsRunning ? Theme.onBg : Theme.warnBg,
                             fg: model.tpwsRunning ? Theme.onFg : Theme.warnFg)
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 11)
                .card(radius: 12, border: model.bypassEnabled ? Theme.accentBorder : Theme.border)
                if let error = model.tpwsError {
                    Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
                }

                HStack {
                    Text("Strategy").font(.system(size: 15, weight: .semibold))
                    Spacer()
                    if model.tuning { ProgressView().controlSize(.small) }
                    Button("⚡ Auto-tune") { model.tuneBypass() }
                        .buttonStyle(AccentButtonStyle())
                        .disabled(model.tuning || model.tpwsVersion == nil)
                }
                VStack(spacing: 8) {
                    ForEach(Array(DPIStrategies.all.enumerated()), id: \.offset) { index, strategy in
                        StrategyRow(strategy: strategy, selected: index == model.bypassStrategyIndex) {
                            model.selectStrategy(index)
                        }
                    }
                }
                Text("If sites are still blocked, run Auto-tune or try another strategy — effectiveness depends on your ISP.")
                    .font(.caption).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
    }

    private var modeNote: String {
        if !model.bypassEnabled { return String(localized: "Off") }
        if model.activeBridge == .direct {
            return String(localized: "VPN/proxy off — bypass applies to all traffic.")
        }
        return String(localized: "VPN/proxy on — bypass applies only to Direct rules.")
    }
}

private struct StrategyRow: View {
    let strategy: DPIStrategy
    let selected: Bool
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Theme.accent : Theme.text3)
                Text(strategy.label).font(.system(size: 13.5))
                Spacer()
                Text(strategy.flags.joined(separator: " ")).font(Theme.mono).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 12).padding(.vertical, 10)
            .background(selected ? Theme.accentBg.opacity(0.5) : Theme.surface, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(selected ? Theme.accentBorder : Theme.border))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}

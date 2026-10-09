import AppKit
import PGCore
import SwiftUI

struct MainView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        @Bindable var model = model
        HStack(spacing: 0) {
            Sidebar()
                .frame(width: 224)
                .background(Theme.sidebar.ignoresSafeArea())
            Rectangle().fill(Theme.border).frame(width: 1).ignoresSafeArea()
            VStack(spacing: 0) {
                HelperBanner()
                StatusHeader()
                Group {
                    switch model.section {
                    case .connections: ConnectionsPage()
                    case .traffic: TrafficPage()
                    case .log: LogPage()
                    case .rules: RulesPage()
                    case .proxies: ProxiesPage()
                    case .vpn: VPNPage()
                    case .dpi: DPIPage()
                    case .anyconnect: AnyConnectPage()
                    case .dns: DNSPage()
                    case .settings: SettingsPage()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .frame(minWidth: 0, maxWidth: .infinity)
            .clipped()
        }
        .foregroundStyle(Theme.text)
        .font(.system(size: 13))
        .background(Theme.window.ignoresSafeArea())
        .onAppear {
            AppDelegate.openMainWindowAction = { [openWindow] in openWindow(id: "main") }
        }
        .sheet(item: $model.sheet) { _ in
            ProfilesSheet().environment(model)
        }
        .alert("ProxyGate", isPresented: Binding(
            get: { model.alertMessage != nil },
            set: { if !$0 { model.alertMessage = nil } })) {
            Button("OK") { model.alertMessage = nil }
        } message: {
            Text(model.alertMessage ?? "")
        }
        .alert("Loop Detected", isPresented: Binding(
            get: { model.loopAlert != nil },
            set: { if !$0, let a = model.loopAlert { model.ignoreLoop(a) } }),
            presenting: model.loopAlert) { alert in
            Button("Yes") { model.excludeFromProcessing(alert) }
            Button("No", role: .cancel) { model.ignoreLoop(alert) }
        } message: { alert in
            Text("\(alert.app) opened \(alert.count) connections to \(alert.target) within 10 seconds — most likely an infinite connection loop.\n\nRoute this application directly (exclude it from proxying)?")
        }
        .confirmationDialog("New network — which bridge?", isPresented: Binding(
            get: { model.bridgePrompt != nil },
            set: { if !$0 { model.bridgePrompt = nil } }),
            presenting: model.bridgePrompt) { prompt in
            Button("Use VPN") { model.answerBridgePrompt(useVPN: true) }
            Button("Use proxy \(prompt.proxyTitle)") { model.answerBridgePrompt(useVPN: false) }
            Button("Cancel", role: .cancel) { model.bridgePrompt = nil }
        } message: { _ in
            Text("Both the VPN and a proxy are available on this network. ProxyGate will remember your choice for it.")
        }
    }
}

// MARK: - Sidebar

struct Sidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 10) {
                Image(nsImage: GateIcon.glyph(
                    size: 28, shield: GateIcon.brand,
                    arrow: model.isRunning ? .systemGreen : .systemRed))
                VStack(alignment: .leading, spacing: 1) {
                    Text(verbatim: "ProxyGate").font(.system(size: 15, weight: .semibold))
                    Text("v\(PGConstants.version) · \(model.profile.name)")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.text3)
                        .lineLimit(1)
                }
            }
            .padding(.horizontal, 8)
            .padding(.bottom, 16)

            groupLabel("Monitoring")
            ForEach(AppSection.monitoring) { item($0) }
            groupLabel("Configuration").padding(.top, 14)
            ForEach(AppSection.configuration) { item($0) }

            Spacer()

            VStack(alignment: .leading, spacing: 6) {
                Text("Profile").font(.system(size: 11)).foregroundStyle(Theme.text3)
                Picker("Profile", selection: Binding(
                    get: { model.activeProfileID },
                    set: { model.activate($0) })) {
                    ForEach(model.profiles) { Text($0.name).tag($0.id) }
                }
                .labelsHidden()
                Button("Manage Profiles…") { model.sheet = .profiles }
                    .buttonStyle(.plain)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.accentFg)
            }
            .padding(10)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(hex: 0x2A3037)))
        }
        .padding(.horizontal, 12)
        .padding(.top, 8)
        .padding(.bottom, 12)
    }

    private func groupLabel(_ text: LocalizedStringKey) -> some View {
        Text(text)
            .textCase(.uppercase)
            .font(.system(size: 11, weight: .semibold))
            .tracking(0.6)
            .foregroundStyle(Color(hex: 0x7D8792))
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
    }

    private func item(_ section: AppSection) -> some View {
        let selected = model.section == section
        return Button {
            model.section = section
        } label: {
            HStack(spacing: 10) {
                Image(systemName: section.icon)
                    .frame(width: 16)
                Text(loc(section.rawValue))
                Spacer()
                badge(section)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .foregroundStyle(selected ? Theme.text : Color(hex: 0xB9C1CA))
            .fontWeight(selected ? .medium : .regular)
            .background(selected ? Theme.raised : .clear, in: RoundedRectangle(cornerRadius: 8))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private func activeDot(_ color: Color) -> some View {
        Circle().fill(color).frame(width: 7, height: 7)
    }
    @ViewBuilder private func badge(_ section: AppSection) -> some View {
        switch section {
        case .connections where model.activeConnectionCount > 0:
            Text(countText(model.activeConnectionCount))
                .font(.system(size: 11).monospacedDigit())
                .padding(.horizontal, 7)
                .padding(.vertical, 1)
                .foregroundStyle(Theme.accentFg)
                .background(Color(hex: 0x2B3A3A), in: Capsule())
        case .rules:
            Text("\(model.profile.rules.count)").font(.system(size: 11).monospacedDigit()).foregroundStyle(Theme.text3)
        case .proxies:
            Text("\(model.profile.proxies.count)").font(.system(size: 11).monospacedDigit()).foregroundStyle(Theme.text3)
        case .settings where model.updateCount > 0:
            Text("\(model.updateCount)")
                .font(.system(size: 10.5, weight: .bold))
                .foregroundStyle(.white)
                .padding(.horizontal, 5).frame(minWidth: 17, minHeight: 17)
                .background(Color(hex: 0xE5484D), in: Capsule())
        case .vpn where model.vpnConnected:
            activeDot(Theme.on)
        case .dpi where model.bypassEnabled:
            activeDot(model.tpwsRunning ? Theme.on : Theme.warnFg)
        case .anyconnect where model.anyConnectUp:
            activeDot(Theme.on)
        default:
            EmptyView()
        }
    }
}

// MARK: - Status header

struct StatusHeader: View {
    @Environment(AppModel.self) private var model

    private var title: String {
        guard model.engineConnected else { return model.statusText }
        return model.isRunning ? String(localized: "Redirection on") : String(localized: "Redirection off")
    }

    private var subtitle: String {
        guard model.engineConnected, model.isRunning else { return model.statusText }
        return model.bridgeDescription
    }

    var body: some View {
        HStack(spacing: 20) {
            Button {
                model.toggle()
            } label: {
                Image(systemName: "power")
                    .font(.system(size: 22, weight: .semibold))
                    .frame(width: 56, height: 56)
                    .foregroundStyle(model.isRunning ? Theme.on : Theme.text3)
                    .background(Circle().fill(model.isRunning ? Theme.onBg : Theme.raised))
                    .overlay(Circle().stroke(model.isRunning ? Theme.on : Theme.borderStrong, lineWidth: 2))
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .help(model.isRunning ? "Stop traffic redirection" : "Start traffic redirection")
            .accessibilityLabel(model.isRunning ? "Stop traffic redirection" : "Start traffic redirection")
            .disabled(model.helperInstalled && !model.engineConnected)
            .keyboardShortcut("r", modifiers: .command)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 10) {
                    Text(title).font(.system(size: 18, weight: .semibold))
                    if model.engineConnected {
                        Pill(text: model.isRunning ? String(localized: "ON") : String(localized: "OFF"),
                             bg: model.isRunning ? Theme.onBg : Theme.offBg,
                             fg: model.isRunning ? Theme.onFg : Theme.offFg)
                            .fontWeight(.semibold)
                    }
                }
                Text(subtitle)
                    .foregroundStyle(Theme.text2)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            HStack(spacing: 10) {
                metric("Download", ByteFormat.rate(model.downRate))
                metric("Upload", ByteFormat.rate(model.upRate))
                metric("Active", countText(model.activeConnectionCount))
                metric("Errors", countText(model.totalFailures), warn: model.totalFailures > 0)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
        .background(Theme.header)
        .overlay(alignment: .bottom) { Rectangle().fill(Theme.border).frame(height: 1) }
    }

    private func metric(_ title: LocalizedStringKey, _ value: String, warn: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.text3)
            Text(value)
                .font(.system(size: 16, weight: .semibold).monospacedDigit())
                .foregroundStyle(warn ? Color(hex: 0xF5A524) : Theme.text)
                .lineLimit(1)
        }
        .frame(width: 96, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(hex: 0x2A3037)))
    }
}

struct HelperBanner: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        if !model.helperInstalled || model.helperOutdated {
            HStack(spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warnFg)
                if model.helperOutdated {
                    Text("The helper (\(model.engineStatus?.version ?? "?")) is older than the app (\(PGConstants.version)).")
                } else {
                    Text("ProxyGate needs a privileged helper to redirect traffic (asks for the administrator password once).")
                }
                Spacer()
                if model.helperBusy {
                    ProgressView().controlSize(.small)
                }
                Button(model.helperOutdated ? "Update Helper" : "Install Helper") { model.installHelper() }
                    .buttonStyle(AccentButtonStyle())
                    .disabled(model.helperBusy)
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 10)
            .background(Theme.warnBg)
        }
    }
}

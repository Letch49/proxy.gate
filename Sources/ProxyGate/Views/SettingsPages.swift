import AppKit
import PGCore
import SwiftUI

struct SettingsPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 8) {
            PageHeader(title: "Settings", subtitle: "Interception, loop protection and the application itself.") { EmptyView() }
                .padding(.horizontal, 24)
                .padding(.top, 18)
            Form {
                Section("Traffic redirection") {
                    TextField("Engine port (localhost)", value: Binding(
                        get: { Int(model.profile.advanced.listenPort) },
                        set: { model.profile.advanced.listenPort = UInt16(clamping: max(1024, $0)) }),
                        format: .number.grouping(.never))
                    Toggle("Redirect IPv6 traffic", isOn: $model.profile.advanced.captureIPv6)
                    Toggle("Block QUIC (UDP 443) so browsers use TCP", isOn: $model.profile.advanced.blockQUIC)
                    Stepper(value: $model.profile.advanced.connectTimeoutSec, in: 3...120) {
                        Text("Connection timeout: \(model.profile.advanced.connectTimeoutSec) s")
                    }
                }
                Section {
                    Toggle("Detect connection loops", isOn: $model.loopDetection)
                    Stepper(value: $model.loopThreshold, in: 50...2000, step: 50) {
                        Text("Threshold: \(model.loopThreshold) connections to one host in 10 s")
                    }
                    .disabled(!model.loopDetection)
                } header: {
                    Text("Loop detection")
                } footer: {
                    Text("Apps that are proxies themselves (Docker Desktop, Clash, VPN clients) can send their traffic back into ProxyGate and loop forever. When one app suddenly opens hundreds of connections to the same host, ProxyGate offers to route that app directly.")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
                Section("Application") {
                    Toggle("Start redirection when ProxyGate launches", isOn: $model.autoStart)
                    Toggle("Show traffic speed in the menu bar", isOn: $model.showSpeedInMenuBar)
                    Stepper(value: $model.idleRetention, in: 0...600, step: 10) {
                        Text("Keep idle connections in the list: \(Int(model.idleRetention)) s")
                    }
                    Picker("Language", selection: Binding(get: { model.language }, set: { model.setLanguage($0) })) {
                        Text("System").tag("")
                        Text(verbatim: "English").tag("en")
                        Text(verbatim: "Русский").tag("ru")
                    }
                    .help("ProxyGate restarts to apply the language")
                    LabeledContent("Profiles") {
                        Button("Manage Profiles…") { model.sheet = .profiles }
                    }
                }
                Section {
                    DependencyRow(
                        name: "Xray", role: "VPN", source: "github.com/XTLS/Xray-core",
                        url: URL(string: "https://github.com/XTLS/Xray-core/releases")!,
                        installed: model.xrayVersion != nil, version: model.xrayVersion, running: model.xrayRunning,
                        update: model.xrayUpdate, error: model.xrayError, busy: model.xrayBusy, message: model.xrayMessage,
                        actionTitle: model.xrayVersion == nil ? "Install Core" : "Update Core",
                        actionDisabled: !model.engineConnected, log: PGConstants.xrayLogPath) { model.installXray() }
                    DependencyRow(
                        name: "tpws (zapret)", role: "DPI", source: "github.com/bol-van/zapret",
                        url: URL(string: "https://github.com/bol-van/zapret/releases")!,
                        installed: model.tpwsVersion != nil, version: model.tpwsVersion, running: model.tpwsRunning,
                        update: model.tpwsUpdate, error: model.tpwsError, busy: model.tpwsBusy, message: model.tpwsMessage,
                        actionTitle: model.tpwsVersion == nil ? "Install Core" : "Update Core",
                        actionDisabled: !model.engineConnected, log: PGConstants.tpwsLogPath) { model.installTpws() }
                    DependencyRow(
                        name: "ByeDPI", role: "DPI", source: "github.com/ollesss/byedpi_macos",
                        url: URL(string: "https://github.com/ollesss/byedpi_macos/releases")!,
                        installed: model.byedpiVersion != nil, version: model.byedpiVersion, running: model.byedpiRunning,
                        error: model.byedpiError, busy: model.byedpiBusy, message: model.byedpiMessage,
                        actionTitle: model.byedpiVersion == nil ? "Install Core" : "Update Core",
                        actionDisabled: !model.engineConnected, log: PGConstants.byedpiLogPath) { model.installByedpi() }
                    DependencyRow(
                        name: "openconnect", role: "AnyConnect", source: "Homebrew",
                        url: URL(string: "https://formulae.brew.sh/formula/openconnect")!,
                        installed: model.openConnectInstalled, busy: model.openConnectBusy, message: model.openConnectMessage,
                        actionTitle: model.openConnectInstalled ? "Reinstall via Homebrew" : "Install via Homebrew") {
                        model.installOpenConnect()
                    }
                } header: {
                    Text("Dependencies")
                } footer: {
                    Text("Cores download from their GitHub releases, and the helper checks each file's SHA-256 before installing it. openconnect comes from Homebrew, which checks its own packages.")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
                Section("Privileged helper") {
                    LabeledContent("Status") {
                        if !model.helperInstalled {
                            Text("Not installed").foregroundStyle(Theme.offFg)
                        } else if let status = model.engineStatus {
                            Text("Running, version \(status.version)").foregroundStyle(model.helperOutdated ? Theme.warnFg : Theme.onFg)
                        } else {
                            Text("Installed, not responding").foregroundStyle(Theme.warnFg)
                        }
                    }
                    HStack {
                        Button(model.helperInstalled ? "Reinstall Helper" : "Install Helper") { model.installHelper() }
                        Button("Uninstall Helper") { model.uninstallHelper() }
                            .disabled(!model.helperInstalled)
                        if model.helperBusy { ProgressView().controlSize(.small) }
                    }
                    .disabled(model.helperBusy)
                    Text("Log: \(PGConstants.helperLogPath)")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                        .textSelection(.enabled)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
        }
    }

}

/// One external core in the Dependencies group: where it comes from, its state and one action.
private struct DependencyRow: View {
    let name: String
    let role: String
    let source: String
    let url: URL
    let installed: Bool
    var version: String?
    var running = false
    var update: String?
    var error: String?
    let busy: Bool
    var message: String?
    let actionTitle: LocalizedStringKey
    var actionDisabled = false
    var log: String?
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 10) {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(verbatim: name).fontWeight(.semibold)
                        Text(verbatim: role).font(.caption).foregroundStyle(Theme.text3)
                    }
                    Link(source, destination: url).font(.caption)
                }
                Spacer()
                if busy { ProgressView().controlSize(.small) }
                status
                Button(actionTitle, action: action).disabled(busy || actionDisabled)
            }
            if busy, let message {
                Text(message).font(.caption).foregroundStyle(Theme.text3)
            }
            if let update {
                Text("Update available: \(update)").font(.caption).foregroundStyle(Theme.warnFg)
            }
            if let error {
                Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
            }
            if let log {
                Text("Log: \(log)").font(.caption).foregroundStyle(Theme.text3).textSelection(.enabled)
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder private var status: some View {
        if !installed {
            StatusPill(text: String(localized: "Not installed"), tone: .warn)
        } else if let version {
            StatusPill(text: running ? String(localized: "Running, \(version)") : String(localized: "Installed, \(version)"),
                       tone: running ? .ok : .neutral)
        } else {
            StatusPill(text: String(localized: "Installed"), tone: .neutral)
        }
    }
}

import AppKit
import PGCore
import SwiftUI

struct DNSPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 8) {
            PageHeader(title: "DNS", subtitle: "How ProxyGate learns hostnames behind IP addresses.") { EmptyView() }
                .padding(.horizontal, 24)
                .padding(.top, 18)
            Form {
                Section {
                    Toggle("Detect target hostnames (TLS SNI / HTTP Host header)", isOn: $model.profile.dns.sniffHostnames)
                    Stepper(value: $model.profile.dns.sniffTimeoutMs, in: 50...2000, step: 50) {
                        Text("Wait for the client's first bytes: \(model.profile.dns.sniffTimeoutMs) ms")
                    }
                    .disabled(!model.profile.dns.sniffHostnames)
                } footer: {
                    Text("Applications resolve names themselves, so ProxyGate only sees IP addresses. It reads the hostname from the TLS ClientHello or HTTP request, so rules like *.example.com work and the connection list shows names. Protocols where the server speaks first (SSH, SMTP) wait for this timeout once.")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
                Section {
                    Toggle("Send hostnames to the proxy (resolve DNS through proxy)", isOn: $model.profile.dns.sendHostnameToProxy)
                } footer: {
                    Text("When a hostname was detected, the proxy receives the name instead of the IP address and resolves it itself. Recommended for corporate proxies.")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
            }
            .formStyle(.grouped)
            .scrollContentBackground(.hidden)
        }
    }
}

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
                    LabeledContent("Core status") {
                        if let version = model.xrayVersion {
                            Text(model.xrayRunning ? "Running, \(version)" : "Installed, \(version)")
                                .foregroundStyle(model.xrayRunning ? Theme.onFg : Theme.text2)
                        } else {
                            Text("Not installed").foregroundStyle(Theme.offFg)
                        }
                    }
                    if let error = model.xrayError {
                        Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
                    }
                    HStack {
                        Button(model.xrayVersion == nil ? "Install Core" : "Update Core") { model.installXray() }
                            .disabled(model.xrayBusy || !model.engineConnected)
                        if model.xrayBusy {
                            ProgressView().controlSize(.small)
                            if let msg = model.xrayMessage { Text(msg).font(.caption).foregroundStyle(Theme.text3) }
                        }
                    }
                } header: {
                    Text("VPN core (Xray)")
                } footer: {
                    Text("The Xray core powers VLESS/REALITY VPN subscriptions. It downloads independently of the app and runs unprivileged, so new anti-blocking methods arrive on release day. Add subscriptions and pick a server on the VPN page. Log: \(PGConstants.xrayLogPath)")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
                Section {
                    LabeledContent("Core status") {
                        if let version = model.tpwsVersion {
                            Text(model.tpwsRunning ? "Running, \(version)" : "Installed, \(version)")
                                .foregroundStyle(model.tpwsRunning ? Theme.onFg : Theme.text2)
                        } else {
                            Text("Not installed").foregroundStyle(Theme.offFg)
                        }
                    }
                    if let error = model.tpwsError {
                        Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
                    }
                    HStack {
                        Button(model.tpwsVersion == nil ? "Install Core" : "Update Core") { model.installTpws() }
                            .disabled(model.tpwsBusy || !model.engineConnected)
                        if model.tpwsBusy {
                            ProgressView().controlSize(.small)
                            if let msg = model.tpwsMessage { Text(msg).font(.caption).foregroundStyle(Theme.text3) }
                        }
                    }
                    if model.tpwsUpdate != nil {
                        Text("Update available: \(model.tpwsUpdate ?? "")").font(.caption).foregroundStyle(Theme.warnFg)
                    }
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Auto-tune test sites").font(.caption).foregroundStyle(Theme.text3)
                        TextField("", text: $model.profile.dpiTestHosts, prompt: Text("youtube.com; discord.com"), axis: .vertical)
                            .lineLimit(1...3).font(Theme.mono)
                        Text("Known-blocked hosts the DPI auto-tune probes. During the test they always go direct.")
                            .font(.caption).foregroundStyle(Theme.text3)
                    }
                } header: {
                    Text("DPI-bypass core (tpws)")
                } footer: {
                    Text("The tpws core (zapret) defeats ISP DPI on direct routes. Turn it on and pick a strategy on the DPI page. Log: \(PGConstants.tpwsLogPath)")
                        .font(.caption)
                        .foregroundStyle(Theme.text3)
                }
                Section {
                    LabeledContent("openconnect") {
                        if model.openConnectInstalled {
                            Text("Installed").foregroundStyle(Theme.onFg)
                        } else {
                            Text("Not installed").foregroundStyle(Theme.offFg)
                        }
                    }
                    HStack {
                        Button(model.openConnectInstalled ? "Reinstall via Homebrew" : "Install via Homebrew") { model.installOpenConnect() }
                            .disabled(model.openConnectBusy)
                        if model.openConnectBusy {
                            ProgressView().controlSize(.small)
                            if let m = model.openConnectMessage { Text(m).font(.caption).foregroundStyle(Theme.text3) }
                        }
                    }
                } header: {
                    Text("AnyConnect (openconnect)")
                } footer: {
                    Text("Connect to a Cisco AnyConnect VPN on the AnyConnect page. The button runs `brew install openconnect`. Only corporate subnets go through the tunnel; your VPN keeps working in parallel.")
                        .font(.caption).foregroundStyle(Theme.text3)
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

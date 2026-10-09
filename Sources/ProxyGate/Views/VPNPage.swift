import PGCore
import SwiftUI

struct VPNPage: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "VPN", subtitle: "Connect to route Global traffic through the selected server.") {
                    Toggle("Hide N/A", isOn: $model.profile.hideUnreachableServers)
                        .toggleStyle(.switch).controlSize(.mini).fixedSize()
                    Picker("", selection: $model.profile.pingInterval) {
                        Text("1m").tag(1); Text("5m").tag(5); Text("30m").tag(30); Text("off").tag(0)
                    }
                    .labelsHidden().frame(width: 92)
                    Button { adding = true } label: { Label("Add", systemImage: "plus") }
                        .buttonStyle(GhostButtonStyle())
                    if !model.profile.subscriptions.isEmpty {
                        if model.vpnConnected {
                            Button("Disconnect") { model.disconnectVPN() }.buttonStyle(GhostButtonStyle(destructive: true))
                        } else {
                            Button("Connect") { model.connectVPN() }.buttonStyle(AccentButtonStyle())
                        }
                    }
                }

                if model.xrayVersion == nil {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warnFg)
                        Text("The VPN core is not installed yet.")
                        Spacer()
                        Button("Open Settings") { model.section = .settings }.buttonStyle(GhostButtonStyle())
                    }
                    .padding(14).card(radius: 12, border: Theme.borderStrong)
                }

                if model.profile.subscriptions.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "shield.lefthalf.filled").font(.system(size: 28)).foregroundStyle(Theme.text3)
                        Text("No subscriptions yet").fontWeight(.semibold)
                        Text("Paste a subscription link from your VPN provider. ProxyGate fetches it as Happ and lists its servers.")
                            .foregroundStyle(Theme.text2).multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity).padding(36).card(radius: 12)
                } else {
                    ForEach(model.profile.subscriptions) { sub in
                        SubscriptionCard(sub: sub)
                    }
                    AutoSwitchSection()
                }
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
        .sheet(isPresented: $adding) {
            AddSubscriptionSheet { name, url in model.addSubscription(name: name, url: url) }
        }
    }
}

private struct SubscriptionCard: View {
    @Environment(AppModel.self) private var model
    let sub: Subscription

    private var isActive: Bool { model.profile.activeSubscriptionID == sub.id }

    /// Авто first, then the selected/last server, then ascending latency; N/A and untested last.
    private func sorted(_ all: [XrayConfigSummary]) -> [XrayConfigSummary] {
        let hide = model.profile.hideUnreachableServers
        let shown = hide ? all.filter { $0.balancer || $0.index == sub.selectedConfig || sub.latencies[$0.index] != -1 } : all
        func rank(_ i: Int) -> Int {
            guard let v = sub.latencies[i] else { return 1_000_000 }
            return v < 0 ? 2_000_000 : v
        }
        return shown.sorted { a, b in
            if a.balancer != b.balancer { return a.balancer }
            let aSel = a.index == sub.selectedConfig, bSel = b.index == sub.selectedConfig
            if aSel != bSel { return aSel }
            return rank(a.index) < rank(b.index)
        }
    }

    var body: some View {
        let all = model.configs(of: sub)
        VStack(alignment: .leading, spacing: 0) {
            Button {
                model.setCollapsed(sub.id, !sub.collapsed)
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: sub.collapsed ? "chevron.right" : "chevron.down")
                        .font(.system(size: 11)).foregroundStyle(Theme.text3).frame(width: 12)
                    Image(systemName: "globe").frame(width: 30, height: 30).background(Theme.raised, in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 2) {
                        Text(sub.name).font(.system(size: 15, weight: .semibold))
                        Text("\(sub.host) · \(countText(all.count)) · \(pingAge)")
                            .font(.system(size: 11)).foregroundStyle(Theme.text3).lineLimit(1)
                    }
                    Spacer()
                    if isActive && model.vpnConnected { Pill(text: "Connected", bg: Theme.onBg, fg: Theme.onFg) }
                    if let usage = sub.usage {
                        Pill(text: ByteFormat.short(usage.used) + (usage.unlimited ? " · ∞" : ""), bg: Theme.neutralBg, fg: Theme.neutralFg)
                    }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .padding(14)

            if !sub.collapsed {
                HStack(spacing: 8) {
                    if model.pinging.contains(sub.id) { ProgressView().controlSize(.small) }
                    Button("Ping") { model.pingSubscription(sub.id) }.buttonStyle(GhostButtonStyle()).disabled(model.pinging.contains(sub.id))
                    Button("Update") { model.refreshSubscription(sub.id) }.buttonStyle(GhostButtonStyle()).disabled(model.vpnBusy)
                    Spacer()
                    Button { model.removeSubscription(sub.id) } label: { Image(systemName: "trash") }
                        .buttonStyle(GhostButtonStyle(destructive: true))
                }
                .padding(.horizontal, 14).padding(.bottom, 8)

                ScrollView {
                    VStack(spacing: 7) {
                        ForEach(sorted(all)) { cfg in
                            ConfigRow(cfg: cfg,
                                      selected: isActive && cfg.index == sub.selectedConfig,
                                      connected: isActive && cfg.index == sub.selectedConfig && model.vpnConnected,
                                      latency: sub.latencies[cfg.index]) {
                                model.selectVPNConfig(sub.id, index: cfg.index)
                            }
                        }
                    }
                    .padding(.horizontal, 14).padding(.bottom, 14)
                }
                .frame(maxHeight: 340)
            }
        }
        .card(radius: 12, border: isActive && model.vpnConnected ? Theme.accentBorder : Theme.border)
    }

    private var pingAge: String {
        guard let at = sub.latencyCheckedAt else { return String(localized: "not pinged") }
        return String(localized: "pinged \(at.formatted(.relative(presentation: .numeric)))")
    }
}

private struct ConfigRow: View {
    let cfg: XrayConfigSummary
    let selected: Bool
    let connected: Bool
    let latency: Int?
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 12) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Theme.accent : Theme.text3)
                if cfg.balancer { Image(systemName: "bolt.fill").foregroundStyle(Theme.accentFg).font(.system(size: 12)) }
                Text(cfg.name).font(.system(size: 13.5)).lineLimit(1)
                Spacer()
                if connected { Pill(text: "Connected", bg: Theme.onBg, fg: Theme.onFg) }
                Pill(text: cfg.transport, bg: Theme.accentBg, fg: Theme.accentFg)
                latencyPill
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .background(selected ? Theme.accentBg.opacity(0.5) : Theme.surface, in: RoundedRectangle(cornerRadius: 9))
            .overlay(RoundedRectangle(cornerRadius: 9).stroke(selected ? Theme.accentBorder : Theme.border))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder private var latencyPill: some View {
        if let latency, latency > 0 {
            Pill(text: "\(latency) ms", bg: latency < 80 ? Theme.onBg : Theme.warnBg, fg: latency < 80 ? Theme.onFg : Theme.warnFg)
                .frame(width: 64)
        } else if latency == -1 {
            Pill(text: "N/A", bg: Theme.neutralBg, fg: Theme.text3).frame(width: 64)
        } else {
            Text("—").font(.system(size: 12)).foregroundStyle(Theme.text3).frame(width: 64)
        }
    }
}

/// Binds the VPN bridge to an interface and controls home/work auto-switch.
private struct AutoSwitchSection: View {
    @Environment(AppModel.self) private var model
    @State private var interfaces = NetInterface.all()

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 12) {
            Text("Bridges & auto-switch").font(.system(size: 14, weight: .semibold))
            HStack {
                Text("VPN interface").font(.system(size: 13)).foregroundStyle(Theme.text2)
                Spacer()
                Picker("", selection: Binding(
                    get: { model.profile.vpnInterfaceMAC },
                    set: { mac in
                        model.profile.vpnInterfaceMAC = mac
                        model.profile.vpnInterfaceName = mac.flatMap { m in interfaces.first { $0.mac == m }?.title }
                    })) {
                    Text("Any").tag(String?.none)
                    ForEach(interfaces) { iface in Text(verbatim: iface.title).tag(String?.some(iface.mac)) }
                    if let mac = model.profile.vpnInterfaceMAC, !interfaces.contains(where: { $0.mac == mac }) {
                        Text("\(model.profile.vpnInterfaceName ?? mac) — not connected").tag(String?.some(mac))
                    }
                }
                .labelsHidden().frame(width: 240)
            }
            if !model.profile.proxies.isEmpty {
                HStack {
                    Text("Proxy bridge").font(.system(size: 13)).foregroundStyle(Theme.text2)
                    Spacer()
                    Picker("", selection: Binding(
                        get: { model.profile.activeProxyID ?? model.profile.proxies.first?.id },
                        set: { model.profile.activeProxyID = $0 })) {
                        ForEach(model.profile.proxies) { proxy in
                            Text(verbatim: proxy.title).tag(Optional(proxy.id))
                        }
                    }
                    .labelsHidden().frame(width: 240)
                }
            }
            Toggle("Switch bridge automatically when the network changes", isOn: $model.profile.autoSwitch)
            Toggle("Ask VPN / Proxy on an unknown network", isOn: $model.profile.askOnUnknownNetwork)
                .disabled(!model.profile.autoSwitch)
            Text("A wired adapter wins over Wi-Fi. Bind a proxy to your Ethernet adapter in Proxies, and the VPN to Wi-Fi here: plug in at work → proxy, unplug at home → VPN.")
                .font(.caption).foregroundStyle(Theme.text3)
        }
        .padding(16).card(radius: 12)
    }
}

private struct AddSubscriptionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    let onAdd: (String, String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add Subscription").font(.system(size: 17, weight: .semibold))
            Text("A subscription link from your VPN provider. ProxyGate fetches it as Happ and gets the full Xray config.")
                .font(.caption).foregroundStyle(Theme.text2)
            VStack(alignment: .leading, spacing: 6) {
                Text("Name (optional)").font(.caption).foregroundStyle(Theme.text3)
                TextField("", text: $name, prompt: Text("My VPN"))
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("Subscription link").font(.caption).foregroundStyle(Theme.text3)
                TextField("", text: $url, prompt: Text("https://…")).font(Theme.mono)
            }
            Spacer()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add") { onAdd(name, url); dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(url.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(20).frame(width: 460, height: 300)
    }
}

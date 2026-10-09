import PGCore
import SwiftUI

struct ProxiesPage: View {
    @Environment(AppModel.self) private var model
    @State private var editing: ProxyServer?
    @State private var editingChains = false

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "Proxies", subtitle: "Servers the rules send traffic through.") {
                    Button("Check All") { model.profile.proxies.forEach(model.checkProxy) }
                        .buttonStyle(GhostButtonStyle())
                        .disabled(model.profile.proxies.isEmpty)
                    Button {
                        editing = ProxyServer(host: "", port: 3128, type: .https)
                    } label: {
                        Label("Add Proxy", systemImage: "plus")
                    }
                    .buttonStyle(AccentButtonStyle())
                }

                if model.profile.proxies.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "server.rack").font(.system(size: 28)).foregroundStyle(Theme.text3)
                        Text("No proxies yet").fontWeight(.semibold)
                        Text("Add an HTTPS or SOCKS proxy, then pick it as the action of a rule.")
                            .foregroundStyle(Theme.text2)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(36)
                    .card(radius: 12)
                } else {
                    LazyVGrid(columns: [GridItem(.flexible(), spacing: 14), GridItem(.flexible(), spacing: 14)], spacing: 14) {
                        ForEach(model.profile.proxies) { proxy in
                            ProxyCard(proxy: proxy, onEdit: { editing = proxy })
                        }
                    }
                }

                HStack {
                    Text("Chains").font(.system(size: 16, weight: .semibold))
                    Spacer()
                    Button("Edit Chains…") { editingChains = true }
                        .buttonStyle(GhostButtonStyle())
                }
                .padding(.top, 6)
                if model.profile.chains.isEmpty {
                    Text("A chain sends traffic through several proxies in order. Use it as a rule action.")
                        .foregroundStyle(Theme.text2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(16)
                        .card(radius: 12)
                } else {
                    ForEach(model.profile.chains) { chain in
                        ChainRow(chain: chain)
                    }
                }
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 18)
        }
        .sheet(item: $editing) { proxy in
            ProxyEditor(proxy: proxy) { saved in
                var p = model.profile
                if let i = p.proxies.firstIndex(where: { $0.id == saved.id }) {
                    p.proxies[i] = saved
                } else {
                    p.proxies.append(saved)
                    // The first proxy becomes the default route.
                    if p.proxies.count == 1, let d = p.rules.lastIndex(where: \.isDefault), p.rules[d].action == .direct {
                        p.rules[d].action = .proxy(saved.id)
                    }
                }
                model.profile = p
                model.checkProxy(saved)
            }
        }
        .sheet(isPresented: $editingChains) {
            ChainsEditor(profile: $model.profile)
        }
    }
}

struct ProxyCard: View {
    @Environment(AppModel.self) private var model
    let proxy: ProxyServer
    let onEdit: () -> Void

    private var usedBy: String {
        let names = model.profile.rules.filter { $0.action == .proxy(proxy.id) }.map(\.name)
        let chains = model.profile.chains.filter { $0.proxyIDs.contains(proxy.id) }.map { String(localized: "chain \($0.name)") }
        let all = names + chains
        return all.isEmpty ? "—" : all.joined(separator: ", ")
    }

    var body: some View {
        let status = model.proxyStatus[proxy.id]
        let checking = model.checkingProxies.contains(proxy.id)
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Image(systemName: "server.rack")
                    .frame(width: 36, height: 36)
                    .foregroundStyle(Color(hex: 0xB9C1CA))
                    .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9))
                VStack(alignment: .leading, spacing: 2) {
                    Text(proxy.endpoint).font(.system(size: 14, weight: .semibold, design: .monospaced)).lineLimit(1)
                    Text("\(typeName) · \(proxy.useAuth ? String(localized: "login \(proxy.username)") : String(localized: "no authentication"))\(proxy.interfaceName.map { " · \($0)" } ?? "")")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.text2)
                }
                Spacer()
                if checking {
                    ProgressView().controlSize(.small)
                } else if let status {
                    Pill(text: status.ok ? String(localized: "Working") : String(localized: "Not responding"),
                         bg: status.ok ? Theme.onBg : Theme.warnBg, fg: status.ok ? Theme.onFg : Theme.warnFg)
                        .help(status.text)
                } else {
                    Pill(text: String(localized: "Not checked"))
                }
            }
            HStack(spacing: 10) {
                tile("Latency", status?.latencyMs.map { "\($0) ms" } ?? "—")
                tile("Used by", usedBy)
                tile("Session traffic", ByteFormat.short(model.traffic(through: proxy)))
            }
            if let status, !status.ok {
                Text(status.text)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Theme.warnFg)
                    .lineLimit(2)
            }
            HStack(spacing: 8) {
                Button("Check") { model.checkProxy(proxy) }
                    .buttonStyle(GhostButtonStyle())
                    .disabled(checking)
                Button("Edit…", action: onEdit)
                    .buttonStyle(GhostButtonStyle())
                Spacer()
                Button("Delete") {
                    var p = model.profile
                    p.removeProxy(proxy.id)
                    model.profile = p
                }
                .buttonStyle(GhostButtonStyle(destructive: true))
            }
        }
        .padding(16)
        .card(radius: 12, border: status?.ok == true ? Theme.accentBorder : Theme.border)
    }

    private var typeName: String {
        switch proxy.type {
        case .https: return "HTTPS (CONNECT)"
        case .socks5: return "SOCKS5"
        case .socks4: return "SOCKS4"
        }
    }

    private func tile(_ title: LocalizedStringKey, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.text3)
            Text(value).fontWeight(.semibold).monospacedDigit().lineLimit(1).truncationMode(.tail)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(Theme.header, in: RoundedRectangle(cornerRadius: 8))
    }
}

struct ChainRow: View {
    @Environment(AppModel.self) private var model
    let chain: ProxyChain

    var body: some View {
        HStack(spacing: 12) {
            Text(chain.name).fontWeight(.semibold).frame(width: 140, alignment: .leading)
            node(Label("This Mac", systemImage: "laptopcomputer"), accent: false)
            ForEach(Array(model.profile.chainProxies(chain.id).enumerated()), id: \.offset) { _, proxy in
                arrow
                node(Text(proxy.title).font(Theme.mono), accent: true)
            }
            arrow
            node(Label("Internet", systemImage: "globe"), accent: false)
            Spacer()
        }
        .padding(16)
        .card(radius: 12)
    }

    private var arrow: some View {
        Image(systemName: "arrow.right").foregroundStyle(Color(hex: 0x59626C))
    }

    private func node<V: View>(_ content: V, accent: Bool) -> some View {
        content
            .font(.system(size: 12))
            .padding(.horizontal, 12)
            .padding(.vertical, 7)
            .foregroundStyle(accent ? Theme.accentFg : Theme.text)
            .background(accent ? Theme.accentBg : Theme.raised, in: RoundedRectangle(cornerRadius: 9))
    }
}

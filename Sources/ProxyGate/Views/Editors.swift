import AppKit
import PGCore
import SwiftUI

struct FullWidthButtonStyle: PrimitiveButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        Button(configuration)
            .frame(maxWidth: .infinity)
            .controlSize(.regular)
            .buttonStyle(.bordered)
    }
}

struct ProxyEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var proxy: ProxyServer
    @State private var port: Int
    @State private var checkResult: String?
    @State private var checking = false
    @State private var interfaces = NetInterface.all()
    let onSave: (ProxyServer) -> Void

    init(proxy: ProxyServer, onSave: @escaping (ProxyServer) -> Void) {
        _proxy = State(initialValue: proxy)
        _port = State(initialValue: Int(proxy.port))
        self.onSave = onSave
    }

    private var valid: Bool {
        !proxy.host.trimmingCharacters(in: .whitespaces).isEmpty && (1...65535).contains(port)
    }

    private var result: ProxyServer {
        var p = proxy
        p.host = p.host.trimmingCharacters(in: .whitespaces)
        p.port = UInt16(clamping: port)
        return p
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section("Server") {
                    TextField("Address", text: $proxy.host, prompt: Text("IP address or hostname"))
                    TextField("Port", value: $port, format: .number.grouping(.never))
                }
                Section("Protocol") {
                    Picker("Protocol", selection: $proxy.type) {
                        Text("HTTPS (HTTP CONNECT)").tag(ProxyType.https)
                        Text("SOCKS Version 5").tag(ProxyType.socks5)
                        Text("SOCKS Version 4 / 4a").tag(ProxyType.socks4)
                    }
                    .pickerStyle(.radioGroup)
                    .labelsHidden()
                }
                Section {
                    Picker("Network interface", selection: interfaceBinding) {
                        Text("Any").tag(String?.none)
                        ForEach(interfaces) { iface in
                            Text(verbatim: iface.title).tag(String?.some(iface.mac))
                        }
                        if let mac = proxy.interfaceMAC, !interfaces.contains(where: { $0.mac == mac }) {
                            Text("\(proxy.interfaceName ?? mac) — not connected").tag(String?.some(mac))
                        }
                    }
                } footer: {
                    Text("With an interface chosen, the proxy is used only while that adapter is connected, and traffic to it goes through it. Rules with this proxy are skipped otherwise, and the next matching rule applies.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Authentication") {
                    Toggle("Enable authentication", isOn: $proxy.useAuth)
                    if proxy.useAuth {
                        TextField(proxy.type == .socks4 ? "User ID" : "Username", text: $proxy.username)
                        if proxy.type != .socks4 {
                            SecureField("Password", text: $proxy.password)
                        }
                    }
                }
            }
            .formStyle(.grouped)
            HStack {
                Button("Check") { check() }
                    .disabled(!valid || checking)
                if checking { ProgressView().controlSize(.small) }
                if let checkResult {
                    Text(checkResult)
                        .lineLimit(2)
                        .font(.caption)
                        .foregroundStyle(checkResult.hasPrefix("OK") ? .green : .red)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("OK") {
                    onSave(result)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!valid)
            }
            .padding(16)
        }
        .frame(width: 480, height: 560)
    }

    private var interfaceBinding: Binding<String?> {
        Binding(get: { proxy.interfaceMAC }, set: { mac in
            proxy.interfaceMAC = mac
            if let mac, let iface = interfaces.first(where: { $0.mac == mac }) {
                proxy.interfaceName = iface.title
            } else if mac == nil {
                proxy.interfaceName = nil
            }
        })
    }

    private func check() {
        let proxy = result
        checking = true
        checkResult = nil
        Task.detached {
            let text: String
            do {
                text = try ProxyClient.check(proxy)
            } catch {
                text = "Failed: \(error)"
            }
            await MainActor.run {
                checkResult = text
                checking = false
            }
        }
    }
}

struct ChainsEditor: View {
    @Environment(\.dismiss) private var dismiss
    @Binding var profile: Profile
    @State private var selectedChain: UUID?
    @State private var selectedMember: Int?

    private var chainIndex: Int? {
        selectedChain.flatMap { id in profile.chains.firstIndex { $0.id == id } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Proxy Chains").font(.headline)
            Text("Traffic goes through every proxy of a chain in order. Use a chain as a rule action.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 12) {
                VStack(alignment: .leading) {
                    List(selection: $selectedChain) {
                        ForEach(profile.chains) { chain in
                            Text(chain.name).tag(chain.id)
                        }
                    }
                    .frame(width: 200)
                    HStack {
                        Button("Create New") {
                            let chain = ProxyChain(name: "Chain \(profile.chains.count + 1)")
                            profile.chains.append(chain)
                            selectedChain = chain.id
                        }
                        Button("Remove") {
                            if let id = selectedChain {
                                profile.removeChain(id)
                                selectedChain = nil
                            }
                        }
                        .disabled(selectedChain == nil)
                    }
                }
                if let ci = chainIndex {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Name", text: $profile.chains[ci].name)
                        List(selection: $selectedMember) {
                            ForEach(Array(profile.chains[ci].proxyIDs.enumerated()), id: \.offset) { index, id in
                                Text("\(index + 1). \(profile.proxy(id)?.title ?? "missing")").tag(index)
                            }
                        }
                        HStack {
                            Menu("Add Proxy") {
                                ForEach(profile.proxies) { proxy in
                                    Button(proxy.title) { profile.chains[ci].proxyIDs.append(proxy.id) }
                                }
                            }
                            .fixedSize()
                            .disabled(profile.proxies.isEmpty)
                            Button("Remove") {
                                if let m = selectedMember {
                                    profile.chains[ci].proxyIDs.remove(at: m)
                                    selectedMember = nil
                                }
                            }
                            .disabled(selectedMember == nil)
                            Button { move(ci, -1) } label: { Image(systemName: "arrow.up") }
                                .disabled((selectedMember ?? 0) == 0)
                            Button { move(ci, 1) } label: { Image(systemName: "arrow.down") }
                                .disabled(selectedMember.map { $0 >= profile.chains[ci].proxyIDs.count - 1 } ?? true)
                        }
                    }
                } else {
                    Text("Select or create a chain")
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 640, height: 400)
    }

    private func move(_ ci: Int, _ delta: Int) {
        guard let m = selectedMember else { return }
        let target = m + delta
        guard profile.chains[ci].proxyIDs.indices.contains(target) else { return }
        profile.chains[ci].proxyIDs.swapAt(m, target)
        selectedMember = target
    }
}

struct ActionOptions: View {
    let profile: Profile

    var body: some View {
        Text("Global (follow active bridge)").tag(RuleAction.global)
        Text("VPN only").tag(RuleAction.vpn)
        Text("Direct").tag(RuleAction.direct)
        Text("Direct + DPI bypass").tag(RuleAction.directDPI)
        Text("Block").tag(RuleAction.block)
        if !profile.proxies.isEmpty {
            Divider()
            ForEach(profile.proxies) { proxy in
                Text(profile.describeLong(.proxy(proxy.id))).tag(RuleAction.proxy(proxy.id))
            }
        }
        if !profile.chains.isEmpty {
            Divider()
            ForEach(profile.chains) { chain in
                Text("Chain \(chain.name)").tag(RuleAction.chain(chain.id))
            }
        }
    }
}

struct RuleEditor: View {
    @Environment(\.dismiss) private var dismiss
    @State var rule: Rule
    let profile: Profile
    let seenApps: [String]
    let seenHosts: [String]
    let onSave: (Rule) -> Void

    init(rule: Rule, profile: Profile, seenApps: [String], seenHosts: [String], onSave: @escaping (Rule) -> Void) {
        _rule = State(initialValue: rule)
        self.profile = profile
        self.seenApps = seenApps
        self.seenHosts = seenHosts
        self.onSave = onSave
    }

    private var hasInvalid: Bool {
        Patterns.split(rule.targetHosts).contains { Patterns.hostKind($0) == .invalid }
            || Patterns.split(rule.targetPorts).contains { Patterns.portKind($0) == .invalid }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Form {
                Section {
                    TextField("Name", text: $rule.name)
                        .disabled(rule.isDefault)
                    Picker("Action", selection: $rule.action) {
                        ActionOptions(profile: profile)
                    }
                    .disabled(rule.locked)
                    if !rule.isDefault && !rule.locked {
                        Toggle("Enabled", isOn: $rule.enabled)
                    }
                }
                if !rule.isDefault {
                    Section("Applications") {
                        PatternListEditor(kind: .applications, text: $rule.applications, suggestions: seenApps)
                    }
                    Section {
                        PatternListEditor(kind: .hosts, text: $rule.targetHosts, suggestions: seenHosts)
                    } header: {
                        Text("Target hosts")
                    } footer: {
                        Text("*.example.com also matches example.com. Several entries can be pasted at once.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Section("Target ports") {
                        PatternListEditor(kind: .ports, text: $rule.targetPorts)
                    }
                }
            }
            .formStyle(.grouped)
            HStack {
                if hasInvalid {
                    Label("Some entries are invalid", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.caption)
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("OK") {
                    onSave(rule)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(rule.name.trimmingCharacters(in: .whitespaces).isEmpty || hasInvalid)
            }
            .padding(16)
        }
        .frame(width: 620, height: rule.isDefault ? 240 : 720)
    }
}

struct ImportRulesSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Binding var profile: Profile
    @State private var text = ""

    private var decoded: Result<[Rule], Error> {
        Result { try RuleTransfer.decode(text).rules.filter { !$0.isDefault } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Paste Rules").font(.title2.weight(.semibold))
            Text("Paste the text copied with “Copy as Text”. Proxies used by the rules are added if missing (without passwords).")
                .font(.callout)
                .foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.system(.caption, design: .monospaced))
                .frame(height: 90)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
            Group {
                if text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Text("Nothing pasted yet").foregroundStyle(.secondary)
                } else {
                    switch decoded {
                    case .success(let rules):
                        List(rules) { rule in
                            HStack {
                                Text(rule.name).fontWeight(.medium)
                                Spacer()
                                Text([rule.applications, rule.targetHosts, rule.targetPorts]
                                    .filter { !$0.isEmpty }.joined(separator: " · "))
                                    .lineLimit(1)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    case .failure(let error):
                        Label(loc(String(describing: error)), systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
            }
            .frame(maxHeight: .infinity, alignment: .top)
            HStack {
                Button("Paste from Clipboard") {
                    text = NSPasteboard.general.string(forType: .string) ?? ""
                }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(importTitle) {
                    if (try? RuleTransfer.importRules(text, into: &profile)) != nil {
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled((try? decoded.get()) == nil)
            }
        }
        .padding(16)
        .frame(width: 600, height: 420)
        .onAppear {
            // Prefill when the clipboard already holds rules.
            if let clip = NSPasteboard.general.string(forType: .string), (try? RuleTransfer.decode(clip)) != nil {
                text = clip
            }
        }
    }

    private var importTitle: String {
        let n = (try? decoded.get().count) ?? 0
        return n > 0 ? String(localized: "Import \(n) Rules") : String(localized: "Import")
    }
}

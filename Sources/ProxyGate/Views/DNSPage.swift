import PGCore
import SwiftUI

/// DNS provider, provider-resolved domains for apps, a resolver check, and hostname detection.
/// The DPI auto-tune uses the same provider (one model: `Profile.dns`).
struct DNSPage: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false
    @State private var checkHost = "www.youtube.com"

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "DNS", subtitle: "Name lookup for blocked sites and hostname detection.") { EmptyView() }

                SectionHeader(title: "Provider") {
                    Picker("", selection: Binding(get: { model.profile.dns.transport }, set: { model.setDNSTransport($0) })) {
                        Text("Encrypted (DoH)").tag(DNSTransport.doh)
                        Text("Plain DNS").tag(DNSTransport.udp)
                    }
                    .pickerStyle(.segmented).labelsHidden().fixedSize()
                    Button { adding.toggle() } label: { Label("Add", systemImage: "plus") }
                        .buttonStyle(GhostButtonStyle())
                }
                VStack(spacing: 8) {
                    ForEach(model.profile.dns.providers) { provider in
                        DNSProviderRow(provider: provider, selected: provider.id == model.profile.dns.provider.id,
                                       transport: model.profile.dns.transport)
                    }
                    if adding {
                        CustomProviderForm { adding = false }
                    }
                }
                Text("Plain DNS can be rewritten on the way. DoH is encrypted.")
                    .font(.caption).foregroundStyle(Theme.text3)

                appsCard

                SectionHeader(title: "Check") {
                    TextField("", text: $checkHost, prompt: Text(verbatim: "www.youtube.com"))
                        .font(Theme.mono).frame(width: 220)
                        .onSubmit { model.checkDNS(checkHost) }
                    if model.dnsChecking { ProgressView().controlSize(.small) }
                    Button("Check") { model.checkDNS(checkHost) }
                        .buttonStyle(AccentButtonStyle())
                        .disabled(model.dnsChecking || !model.engineConnected || !DNSName.isValid(checkHost.trimmingCharacters(in: .whitespaces)))
                }
                if let report = model.dnsReport {
                    DNSCheckCard(report: report)
                }
                Text("A found address only means the name resolves. Whether the site opens is checked by Auto-tune on the DPI page.")
                    .font(.caption).foregroundStyle(Theme.text3)

                SectionHeader("Hostname detection")
                VStack(alignment: .leading, spacing: 10) {
                    Toggle("Detect target hostnames (TLS SNI / HTTP Host header)", isOn: $model.profile.dns.sniffHostnames)
                    Stepper(value: $model.profile.dns.sniffTimeoutMs, in: 50...2000, step: 50) {
                        Text("Wait for the client's first bytes: \(model.profile.dns.sniffTimeoutMs) ms")
                    }
                    .disabled(!model.profile.dns.sniffHostnames)
                    Toggle("Send hostnames to the proxy (resolve DNS through proxy)", isOn: $model.profile.dns.sendHostnameToProxy)
                    Text("Apps resolve names themselves, so ProxyGate sees only IPs. It reads the name from the TLS or HTTP request, so rules like *.example.com work.")
                        .font(.caption).foregroundStyle(Theme.text3)
                }
                .padding(16).card(radius: 12)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
    }

    private var appsCard: some View {
        @Bindable var model = model
        let parsed = DNSDomainList.parse(model.profile.dns.resolveDomains)
        let state = model.dnsState
        return VStack(alignment: .leading, spacing: 10) {
            ToggleCard(isOn: $model.profile.dns.resolveThroughProvider,
                       title: "Resolve blocked sites through the provider",
                       note: appsNote(state),
                       disabled: !model.engineConnected) {
                if model.profile.dns.resolveThroughProvider {
                    if state.active {
                        StatusPill(text: String(localized: "Active"), tone: .ok)
                    } else if state.lastError != nil {
                        StatusPill(text: String(localized: "Error"), tone: .fail)
                    } else {
                        StatusPill(text: String(localized: "Starting…"), tone: .warn)
                    }
                }
            }
            if model.profile.dns.resolveThroughProvider {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Domains and their subdomains").font(.caption).foregroundStyle(Theme.text3)
                    TextField("", text: $model.profile.dns.resolveDomains, prompt: Text(verbatim: "youtube.com; googlevideo.com"), axis: .vertical)
                        .lineLimit(1...4).font(Theme.mono)
                    if !parsed.invalid.isEmpty {
                        Text("Skipped: \(parsed.invalid.joined(separator: ", "))")
                            .font(.caption).foregroundStyle(Theme.warnFg)
                    }
                    if !state.conflicts.isEmpty {
                        Text("Your own resolver files win for: \(state.conflicts.joined(separator: ", "))")
                            .font(.caption).foregroundStyle(Theme.warnFg)
                    }
                    if let error = state.lastError {
                        Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
                    }
                    Text("Other names, corporate ones too, keep using the system DNS. Turned off when ProxyGate quits.")
                        .font(.caption).foregroundStyle(Theme.text3)
                }
                .padding(14).card(radius: 12)
            }
        }
    }

    private func appsNote(_ state: SystemDNSState) -> String {
        guard model.profile.dns.resolveThroughProvider else {
            return String(localized: "Off. Apps use the system DNS.")
        }
        if state.active {
            return String(localized: "\(state.domains.count) domains via \(state.upstream ?? "")")
        }
        return String(localized: "Apps use the system DNS for now.")
    }
}

private struct DNSProviderRow: View {
    @Environment(AppModel.self) private var model
    let provider: DNSProvider
    let selected: Bool
    let transport: DNSTransport

    var body: some View {
        ChoiceRow(title: provider.name, detail: provider.ips.first(where: \.isV4)?.description ?? provider.addresses.first,
                  selected: selected, onTap: { model.selectDNSProvider(provider.id) }) {
            if provider.supportsDoH {
                StatusPill(text: "DoH", tone: selected && transport == .doh ? .accent : .neutral)
            } else if selected && transport == .doh {
                StatusPill(text: String(localized: "Plain only"), tone: .warn)
            }
            if !provider.builtIn {
                Button { model.removeDNSProvider(provider.id) } label: { Image(systemName: "trash") }
                    .buttonStyle(GhostButtonStyle(destructive: true))
                    .help("Remove")
            }
        }
    }
}

private struct CustomProviderForm: View {
    @Environment(AppModel.self) private var model
    let onDone: () -> Void
    @State private var name = ""
    @State private var addresses = ""
    @State private var doh = ""
    @State private var error: DNSInputError?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            field("Name", $name, prompt: "Home router")
            field("IP addresses", $addresses, prompt: "192.0.2.53; 2001:db8::53", mono: true)
            field("DoH address (optional)", $doh, prompt: "https://dns.example/dns-query", mono: true)
            if let error {
                Text(LocalizedStringKey(error.rawValue)).font(.caption).foregroundStyle(Theme.warnFg)
            }
            HStack {
                Text("The IP is used to reach the server, so a broken system DNS can't block it.")
                    .font(.caption).foregroundStyle(Theme.text3)
                Spacer()
                Button("Cancel", action: onDone).buttonStyle(GhostButtonStyle())
                Button("Add") {
                    error = model.addDNSProvider(name: name, addresses: addresses, dohURL: doh)
                    if error == nil { onDone() }
                }
                .buttonStyle(AccentButtonStyle())
            }
        }
        .padding(14).card(radius: 12, border: Theme.accentBorder)
    }

    private func field(_ label: LocalizedStringKey, _ text: Binding<String>, prompt: String, mono: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.caption).foregroundStyle(Theme.text3)
            TextField("", text: text, prompt: Text(verbatim: prompt)).font(mono ? Theme.mono : .body)
        }
    }
}

/// Result of a DNS check: one row per resolver.
struct DNSCheckCard: View {
    let report: DNSCheckReport

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(report.checks.enumerated()), id: \.offset) { i, check in
                if i > 0 { RowDivider() }
                DiagnosticRow(subject: check.system ? String(localized: "System") : check.source,
                              detail: detail(check), status: DNSText.status(check.outcome.status),
                              tone: check.outcome.status == .ok ? .ok : .warn)
            }
            if report.plainDiffers {
                RowDivider()
                Text("Plain DNS and DoH gave different addresses. Plain DNS may be rewritten on the way.")
                    .font(.caption).foregroundStyle(Theme.warnFg)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 14).padding(.vertical, 10)
            }
        }
        .card(radius: 12)
    }

    private func detail(_ check: DNSCheck) -> String {
        let time = check.ms.map { " · \($0) ms" } ?? ""
        if check.outcome.status == .ok {
            let shown = check.outcome.addresses.prefix(2).joined(separator: ", ")
            let more = check.outcome.addresses.count > 2 ? " +\(check.outcome.addresses.count - 2)" : ""
            return shown + more + time
        }
        return (check.outcome.detail ?? "") + time
    }
}

/// Localized words for DNS results, shared by the DNS and DPI pages.
enum DNSText {
    static func status(_ s: DNSStatus) -> String {
        switch s {
        case .ok: return String(localized: "Found")
        case .nxdomain: return String(localized: "Not found")
        case .noData: return String(localized: "No address")
        case .timeout: return String(localized: "No answer")
        case .failed: return String(localized: "Error")
        }
    }
}

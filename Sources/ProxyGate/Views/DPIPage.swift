import PGCore
import SwiftUI

struct DPIPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "DPI bypass", subtitle: "Defeats ISP DPI on direct routes. It never touches VPN or proxy traffic.") {
                    if dpiBusy {
                        ProgressView().controlSize(.small)
                        if let m = dpiMessage { Text(m).font(.caption).foregroundStyle(Theme.text3) }
                    }
                    Button(model.dpiCoreInstalled ? "Update Core" : "Install Core") { installActive() }
                        .buttonStyle(GhostButtonStyle())
                        .disabled(dpiBusy || !model.engineConnected)
                }

                enginePicker

                if !model.dpiCoreInstalled {
                    NoticeBanner(text: notInstalledNote)
                }

                ToggleCard(isOn: Binding(get: { model.bypassEnabled }, set: { model.setBypass($0) }),
                           title: "DPI bypass", note: modeNote, disabled: !model.dpiCoreInstalled) {
                    if model.bypassEnabled {
                        StatusPill(text: model.dpiCoreRunning ? String(localized: "Running") : String(localized: "Starting…"),
                                   tone: model.dpiCoreRunning ? .ok : .warn)
                    }
                }
                if let error = model.dpiCoreError {
                    Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
                }

                if model.dpiCoreInstalled {
                    autohostlistCard
                }

                SectionHeader(title: "Strategy") {
                    if model.tuning {
                        ProgressView().controlSize(.small)
                        Text(progressText).font(.caption).foregroundStyle(Theme.text3).lineLimit(1)
                        Button("Stop") { model.cancelTune() }.buttonStyle(GhostButtonStyle(destructive: true))
                    } else {
                        Button("⚡ Auto-tune") { model.tuneBypass() }
                            .buttonStyle(AccentButtonStyle())
                            .disabled(!anyCoreInstalled)
                    }
                }

                if let report = model.tuneReport, !model.tuning {
                    TuneReportCard(report: report)
                }
                VStack(spacing: 8) {
                    ForEach(Array(model.activeStrategies.enumerated()), id: \.offset) { index, strategy in
                        ChoiceRow(title: strategy.label, detail: strategy.flags.joined(separator: " "),
                                  selected: index == model.bypassStrategyIndex) {
                            model.selectStrategy(index)
                        }
                    }
                }
                Text("Auto-tune checks DNS first, then each strategy of the installed cores. Effectiveness depends on your ISP.")
                    .font(.caption).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
    }

    private var anyCoreInstalled: Bool { model.tpwsVersion != nil || model.byedpiVersion != nil }

    private var progressText: String {
        guard let p = model.tuneProgress else { return String(localized: "Starting…") }
        switch p.phase {
        case .dns: return String(localized: "Checking DNS…")
        case .direct: return String(localized: "Checking direct access…")
        case .strategy: return "\(p.engine?.title ?? "") · \(p.strategy ?? "") (\(p.step)/\(p.total))"
        }
    }

    private var modeNote: String {
        if !model.bypassEnabled { return String(localized: "Off") }
        if model.activeBridge == .direct {
            return String(localized: "VPN/proxy off — bypass applies to all traffic.")
        }
        return String(localized: "VPN/proxy on — bypass applies only to Direct rules.")
    }

    private var dpiBusy: Bool { model.dpiEngine == .byedpi ? model.byedpiBusy : model.tpwsBusy }
    private var dpiMessage: String? { model.dpiEngine == .byedpi ? model.byedpiMessage : model.tpwsMessage }
    private func installActive() { model.dpiEngine == .byedpi ? model.installByedpi() : model.installTpws() }
    private var notInstalledNote: String {
        model.dpiEngine == .byedpi
            ? String(localized: "ByeDPI is not installed yet.")
            : String(localized: "The DPI-bypass core (tpws) is not installed yet.")
    }

    private var enginePicker: some View {
        HStack(spacing: 12) {
            engineCard(.tpws, note: "Split, disorder, OOB.")
            engineCard(.byedpi, note: "Split, disorder, OOB, TLS records. Another way to cut the request.")
        }
    }

    private func engineCard(_ engine: DPIEngine, note: LocalizedStringKey) -> some View {
        let selected = model.dpiEngine == engine
        let installed = engine == .byedpi ? model.byedpiVersion != nil : model.tpwsVersion != nil
        return Button { model.setDpiEngine(engine) } label: {
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                        .foregroundStyle(selected ? Theme.accent : Theme.text3)
                    Text(engine.title).font(.system(size: 13.5, weight: .semibold))
                    Spacer()
                    if installed { StatusPill(text: String(localized: "Installed")) }
                }
                Text(note).font(.system(size: 11.5)).foregroundStyle(Theme.text2)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .card(radius: 12, border: selected ? Theme.accentBorder : Theme.border)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var autohostlistCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 14) {
                Toggle("", isOn: Binding(
                    get: { model.profile.bypassAutohostlist },
                    set: { model.profile.bypassAutohostlist = $0 }))
                    .toggleStyle(.switch).controlSize(.mini).labelsHidden()
                VStack(alignment: .leading, spacing: 3) {
                    Text("Bypass only blocked hosts").font(.system(size: 13, weight: .semibold))
                    Text(autohostlistNote).font(.system(size: 11)).foregroundStyle(Theme.text2).lineLimit(2)
                }
                Spacer()
                if !model.profile.bypassHosts.isEmpty {
                    StatusPill(text: "\(model.profile.bypassHosts.count)")
                }
            }
            if !model.profile.bypassHosts.isEmpty {
                FlowLayout(spacing: 6) {
                    ForEach(model.profile.bypassHosts, id: \.self) { host in
                        Button { model.profile.bypassHosts.removeAll { $0 == host } } label: {
                            HStack(spacing: 5) {
                                Text(host).font(Theme.mono)
                                Image(systemName: "xmark").font(.system(size: 8, weight: .bold))
                            }
                            .padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Theme.hostChipBg, in: Capsule())
                            .foregroundStyle(Theme.hostChipFg)
                        }
                        .buttonStyle(.plain)
                        .help("Remove from the list")
                    }
                }
                Button("Clear list") { model.profile.bypassHosts = [] }
                    .buttonStyle(GhostButtonStyle())
            }
        }
        .padding(14).card(radius: 12)
    }

    private var autohostlistNote: String {
        if !model.profile.bypassAutohostlist {
            return String(localized: "Bypass applies to all direct traffic.")
        }
        if model.profile.bypassHosts.isEmpty {
            return String(localized: "Learning. Until the list fills, bypass applies to all direct traffic. Run Auto-tune to seed it.")
        }
        return String(localized: "Bypass is applied only to these hosts.")
    }
}

/// The auto-tune outcome: verdict with the chosen DNS + core + strategy, launch errors as they are,
/// then one diagnosed row per test host.
private struct TuneReportCard: View {
    @Environment(AppModel.self) private var model
    let report: TuneReport

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 4) {
                Text(verdictTitle).font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(report.verdict == .found || report.verdict == .notBlocked ? Theme.onFg : Theme.warnFg)
                if let line = choiceLine {
                    Text(line).font(Theme.mono).foregroundStyle(Theme.text2).textSelection(.enabled)
                }
            }
            ForEach(Array(report.launchErrors.enumerated()), id: \.offset) { _, e in
                Text("\(e.engine.title) · \(e.strategy): \(e.message)")
                    .font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
            }
            VStack(spacing: 0) {
                ForEach(Array(report.hosts.enumerated()), id: \.offset) { i, probe in
                    if i > 0 { RowDivider() }
                    let s = TuneText.row(probe, provider: model.profile.dns.upstream.title)
                    DiagnosticRow(subject: probe.host, detail: s.detail, status: s.status, tone: s.tone)
                }
            }
            .card(radius: 12)
            if !unresolved.isEmpty {
                HStack {
                    Text("Apps can't resolve some of these sites.").font(.caption).foregroundStyle(Theme.warnFg)
                    Spacer()
                    Button("Resolve via \(model.profile.dns.upstream.title)") { model.resolveThroughProvider(hosts: unresolved) }
                        .buttonStyle(GhostButtonStyle())
                }
            }
            if report.verdict == .found {
                Text("A page that opens doesn't prove video works. Check playback too.")
                    .font(.caption).foregroundStyle(Theme.text3)
            }
        }
    }

    private var unresolved: [String] {
        report.hosts.filter { $0.appsCannotResolve && $0.address != nil && !DNSDomainList.covers(model.dnsState.domains, host: $0.host) }
            .map(\.host)
    }

    private var choiceLine: String? {
        guard report.verdict == .found, let engine = report.engine else { return nil }
        let strategies = engine.strategies()
        let label = strategies.indices.contains(report.strategyIndex) ? strategies[report.strategyIndex].label : ""
        let dns = report.dnsSource ?? String(localized: "System")
        return String(localized: "DNS: \(dns) · \(engine.title) · \(label)")
    }

    private var verdictTitle: String {
        switch report.verdict {
        case .found: return String(localized: "Found a working setup")
        case .notBlocked: return String(localized: "The test sites open without bypass.")
        case .dnsProblem: return String(localized: "Names did not resolve, so strategies were not tested. Check DNS.")
        case .engineProblem: return String(localized: "The DPI core did not start, so strategies were not tested.")
        case .ipBlocked: return String(localized: "The sites refuse connections by IP. DPI bypass can't help, use VPN.")
        case .noStrategy: return String(localized: "No strategy helped on the reachable sites.")
        case .cancelled: return String(localized: "Auto-tune stopped.")
        }
    }
}

/// Localized wording for one auto-tune row.
enum TuneText {
    static func row(_ p: HostProbe, provider: String) -> (detail: String, status: String, tone: StatusTone) {
        if p.directOK {
            return (String(localized: "Opens without bypass"), String(localized: "Not blocked"), .neutral)
        }
        if p.ok {
            let strategies = p.engine?.strategies() ?? []
            let label = strategies.indices.contains(p.strategyIndex) ? strategies[p.strategyIndex].label : ""
            var detail = "\(p.engine?.title ?? "") · \(label)"
            if p.appsCannotResolve {
                detail += " · " + String(localized: "apps can't resolve it yet")
            }
            return (detail, p.latencyMs.map { "✓ \($0) ms" } ?? "✓", p.appsCannotResolve ? .warn : .ok)
        }
        switch p.failure {
        case .dnsNotFound, .dnsTimeout, .dnsFailed:
            let sys = p.systemDNS.map { DNSText.status($0.status) } ?? "-"
            return (String(localized: "System: \(sys). \(provider) didn't help either."), failureText(p.failure), .fail)
        case .tcpFailed:
            return (String(localized: "The address refuses connections. DPI bypass can't help."), failureText(p.failure), .fail)
        case .certError:
            return (String(localized: "Wrong address or traffic inspection."), failureText(p.failure), .fail)
        case .engineFailed:
            return (String(localized: "See the core error above."), failureText(p.failure), .fail)
        default:
            return (p.detail ?? "", failureText(p.failure), .fail)
        }
    }

    static func failureText(_ f: ProbeFailure?) -> String {
        switch f {
        case .dnsNotFound: return String(localized: "Name not found")
        case .dnsTimeout: return String(localized: "DNS timeout")
        case .dnsFailed: return String(localized: "DNS error")
        case .tcpFailed: return String(localized: "No connection")
        case .tlsTimeout: return String(localized: "TLS timeout")
        case .tlsError: return String(localized: "TLS error")
        case .certError: return String(localized: "Certificate error")
        case .engineFailed: return String(localized: "Core did not start")
        case .noStrategy: return String(localized: "No strategy helped")
        case .cancelled: return String(localized: "Stopped")
        case nil: return "✗"
        }
    }
}

import PGCore
import SwiftUI

struct DPIPage: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "DPI bypass", subtitle: "Defeats ISP DPI on direct routes. It never touches VPN or proxy traffic.") {
                    if model.tuning {
                        ProgressView().controlSize(.small)
                        Text(progressText).font(.caption).foregroundStyle(Theme.text3).lineLimit(1)
                        Button("Stop") { model.cancelTune() }.buttonStyle(GhostButtonStyle(destructive: true))
                    } else {
                        Button("⚡ Auto-tune") { model.tuneBypass() }
                            .buttonStyle(AccentButtonStyle())
                            .disabled(!model.anyDPICoreInstalled || !model.engineConnected)
                    }
                }

                bypassBlock
                rulesBlock
                checkBlock
                coresBlock
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
    }

    private var progressText: String {
        guard let p = model.tuneProgress else { return String(localized: "Starting…") }
        switch p.phase {
        case .dns: return String(localized: "Checking DNS…")
        case .direct: return String(localized: "Checking direct access…")
        case .strategy: return "\(p.engine?.title ?? "") · \(p.strategy ?? "") (\(p.step)/\(p.total))"
        }
    }

    // MARK: Main switch

    private var bypassBlock: some View {
        VStack(alignment: .leading, spacing: 10) {
            ToggleCard(isOn: Binding(get: { model.bypassEnabled }, set: { model.setBypass($0) }),
                       title: "DPI bypass", note: bypassNote, disabled: !model.anyDPICoreInstalled) {
                if model.bypassEnabled {
                    StatusPill(text: bypassStatus.text, tone: bypassStatus.tone)
                }
            }
            HStack(spacing: 12) {
                Toggle("All direct traffic", isOn: Binding(
                    get: { model.bypassAllDirect }, set: { model.setBypassAllDirect($0) }))
                    .toggleStyle(.switch).controlSize(.mini)
                    .disabled(!model.anyDPICoreInstalled)
                    .help("Bypass for every Direct route, not only the rules below")
                if model.installedDPIEngines.count > 1 {
                    Picker("Core", selection: Binding(
                        get: { model.primaryDPIEngine }, set: { model.setPrimaryDPIEngine($0) })) {
                        ForEach(model.installedDPIEngines, id: \.self) { engine in
                            Text(verbatim: engine.title).tag(engine)
                        }
                    }
                    .pickerStyle(.segmented).fixedSize()
                }
                Spacer()
            }
            .padding(.horizontal, 14)
        }
    }

    private var runningCores: [DPIEngine] { model.installedDPIEngines.filter { model.coreRunning($0) } }

    private var bypassNote: String {
        if !model.anyDPICoreInstalled { return String(localized: "No DPI core installed") }
        if !model.bypassEnabled { return String(localized: "Off") }
        let cores = runningCores.isEmpty ? model.installedDPIEngines : runningCores
        return cores.map(\.title).joined(separator: " + ")
    }

    private var bypassStatus: (text: String, tone: StatusTone) {
        if model.installedDPIEngines.contains(where: { model.coreError($0) != nil }) {
            return (String(localized: "Error"), .fail)
        }
        if !runningCores.isEmpty { return (String(localized: "Running"), .ok) }
        return (String(localized: "Starting…"), .warn)
    }

    // MARK: Rules

    private var rulesBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader(title: "Rules with bypass") {
                Button { model.newDPIRule() } label: { Label("Rule", systemImage: "plus") }
                    .buttonStyle(GhostButtonStyle())
            }
            if model.dpiRules.isEmpty {
                Text("Add a Direct + DPI rule to bypass DPI for chosen sites.")
                    .font(.caption).foregroundStyle(Theme.text3)
            } else {
                VStack(spacing: 8) {
                    ForEach(model.dpiRules) { rule in
                        DPIRuleRow(rule: rule)
                    }
                }
                Text("Rules come from the Rules page. Auto-tune checks each one.")
                    .font(.caption).foregroundStyle(Theme.text3)
            }
        }
    }

    // MARK: Check

    private var checkBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader("DPI check")
            TestHostsCard()
            if let report = model.tuneReport, !model.tuning {
                TuneReportCard(report: report)
            }
        }
    }

    // MARK: Cores

    private var coresBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            SectionHeader("Cores")
            if model.installedDPIEngines.isEmpty {
                NoticeBanner(text: String(localized: "Install a DPI core in Settings.")) {
                    Button("Open Settings") { model.section = .settings }.buttonStyle(GhostButtonStyle())
                }
            } else {
                VStack(spacing: 8) {
                    ForEach(model.installedDPIEngines, id: \.self) { engine in
                        CoreRow(engine: engine)
                    }
                }
            }
        }
    }
}

/// One Direct + DPI rule: its switch, name, and what auto-tune found for it.
private struct DPIRuleRow: View {
    @Environment(AppModel.self) private var model
    let rule: Rule

    var body: some View {
        let result = model.ruleTuneResult(rule.id)
        HStack(spacing: 12) {
            Toggle("", isOn: Binding(get: { rule.enabled }, set: { model.setRuleEnabled(rule.id, $0) }))
                .toggleStyle(.switch).controlSize(.mini).labelsHidden()
            Text(verbatim: rule.name).font(.system(size: 13.5))
                .foregroundStyle(rule.enabled ? Theme.text : Theme.text3)
                .lineLimit(1)
            Spacer()
            if let detail = detail(result) {
                Text(verbatim: detail).font(Theme.mono).foregroundStyle(Theme.text3)
                    .lineLimit(1).truncationMode(.middle)
            }
            let pill = status(result)
            StatusPill(text: pill.text, tone: pill.tone)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.border))
    }

    private func detail(_ result: RuleTuneResult?) -> String? {
        guard let result, result.ok, let engine = result.engine else { return rule.dpiEngine?.title }
        let strategies = engine.strategies()
        guard strategies.indices.contains(result.strategyIndex) else { return engine.title }
        return "\(engine.title) · \(strategies[result.strategyIndex].label)"
    }

    private func status(_ result: RuleTuneResult?) -> (text: String, tone: StatusTone) {
        guard let result else { return (String(localized: "Not tested"), .neutral) }
        if !result.ok { return (String(localized: "No strategy"), .fail) }
        if let ms = result.latencyMs { return (String(localized: "OK · \(ms) ms"), .ok) }
        return (String(localized: "OK"), .ok)
    }
}

/// The hosts auto-tune probes, as removable chips plus a field to add one.
private struct TestHostsCard: View {
    @Environment(AppModel.self) private var model
    @State private var newHost = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if !model.dpiTestHostList.isEmpty {
                FlowLayout(spacing: 6) {
                    ForEach(model.dpiTestHostList, id: \.self) { host in
                        Button { model.removeDpiTestHost(host) } label: {
                            HStack(spacing: 5) {
                                Text(verbatim: host).font(Theme.mono)
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
            }
            HStack(spacing: 8) {
                TextField("", text: $newHost, prompt: Text(verbatim: "youtube.com"))
                    .textFieldStyle(.roundedBorder).font(Theme.mono)
                    .frame(maxWidth: 240)
                    .onSubmit(add)
                Button("Add", action: add)
                    .buttonStyle(GhostButtonStyle())
                    .disabled(trimmed.isEmpty)
                Spacer()
            }
            Text("Sites to test. During the test they always go direct.")
                .font(.caption).foregroundStyle(Theme.text3)
        }
        .padding(14).card(radius: 12)
    }

    private var trimmed: String { newHost.trimmingCharacters(in: .whitespacesAndNewlines) }

    private func add() {
        guard !trimmed.isEmpty else { return }
        model.addDpiTestHost(trimmed)
        newHost = ""
    }
}

/// One installed DPI core: its current strategy, state, and a menu to pick a strategy by hand.
private struct CoreRow: View {
    @Environment(AppModel.self) private var model
    let engine: DPIEngine

    var body: some View {
        let strategies = engine.strategies()
        let current = model.strategyIndex(for: engine)
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 12) {
                Text(verbatim: engine.title).font(.system(size: 13.5))
                if let version = model.coreVersion(engine) {
                    Text(verbatim: version).font(.caption).foregroundStyle(Theme.text3)
                }
                Spacer()
                if strategies.indices.contains(current) {
                    Text(verbatim: strategies[current].label).font(Theme.mono).foregroundStyle(Theme.text3)
                        .lineLimit(1).truncationMode(.middle)
                }
                if model.coreBusy(engine) { ProgressView().controlSize(.small) }
                StatusPill(text: status.text, tone: status.tone)
                Menu {
                    ForEach(Array(strategies.enumerated()), id: \.offset) { index, strategy in
                        Button { model.selectStrategy(index, for: engine) } label: {
                            if index == current {
                                Label(strategy.label, systemImage: "checkmark")
                            } else {
                                Text(verbatim: strategy.label)
                            }
                        }
                    }
                } label: {
                    Text("Manual")
                }
                .menuStyle(.borderlessButton).fixedSize().buttonStyle(GhostButtonStyle())
                .help("Pick a strategy by hand")
            }
            if let error = model.coreError(engine) {
                Text(error).font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 9))
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Theme.border))
    }

    private var status: (text: String, tone: StatusTone) {
        if model.coreError(engine) != nil { return (String(localized: "Error"), .fail) }
        if model.coreRunning(engine) { return (String(localized: "Running"), .ok) }
        return (String(localized: "Installed"), .neutral)
    }
}

/// The last auto-tune outcome: one verdict line with the chosen DNS + core + strategy, launch
/// errors as they are, and the per-host table behind "Details".
private struct TuneReportCard: View {
    @Environment(AppModel.self) private var model
    let report: TuneReport
    @State private var showDetails = false

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
                Text(verbatim: "\(e.engine.title) · \(e.strategy): \(e.message)")
                    .font(.caption).foregroundStyle(Theme.warnFg).textSelection(.enabled)
            }
            if !unresolved.isEmpty {
                HStack {
                    Text("Apps can't resolve some of these sites.").font(.caption).foregroundStyle(Theme.warnFg)
                    Spacer()
                    Button("Resolve via \(model.profile.dns.upstream.title)") { model.resolveThroughProvider(hosts: unresolved) }
                        .buttonStyle(GhostButtonStyle())
                }
            }
            if !report.hosts.isEmpty {
                DisclosureGroup("Details", isExpanded: $showDetails) {
                    VStack(spacing: 0) {
                        ForEach(Array(report.hosts.enumerated()), id: \.offset) { i, probe in
                            if i > 0 { RowDivider() }
                            let s = TuneText.row(probe, provider: model.profile.dns.upstream.title)
                            DiagnosticRow(subject: probe.host, detail: s.detail, status: s.status, tone: s.tone)
                        }
                    }
                    .card(radius: 12)
                    .padding(.top, 6)
                }
                .font(.system(size: 12))
                .foregroundStyle(Theme.text2)
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

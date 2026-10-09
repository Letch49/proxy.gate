import AppKit
import PGCore
import SwiftUI

enum Grouping: String, CaseIterable, Identifiable {
    case application = "Application"
    case domain = "Domain"
    case type = "Type"
    case none = "No grouping"
    var id: String { rawValue }
}

enum RouteFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case proxy = "Via proxy"
    case direct = "Direct"
    var id: String { rawValue }

    func matches(_ kind: RouteKind) -> Bool {
        switch self {
        case .all: return true
        case .proxy: return kind == .proxy || kind == .chain
        case .direct: return kind == .direct
        }
    }
}

/// A table row: either a merged flow or a group of them.
struct ConnRow: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let target: String
    let active: Int
    let total: Int
    let timeText: String
    let rule: String
    let kind: RouteKind?
    let sent: UInt64
    let received: UInt64
    let lastActivity: Date
    let isGroup: Bool
    var children: [ConnRow]?

    /// What "Create rule" uses for this row.
    var ruleApplication: String?
    var ruleDomain: String?
}

// MARK: - Connections

struct ConnectionsPage: View {
    @Environment(AppModel.self) private var model
    @AppStorage("grouping") private var grouping: Grouping = .application
    @AppStorage("showIdle") private var showIdle = true
    @AppStorage("logExpanded") private var logExpanded = false
    @State private var routeFilter: RouteFilter = .all
    @State private var search = ""
    // Sorting by name keeps rows in place; sorting by activity would reshuffle every refresh.
    @State private var sortOrder = [KeyPathComparator(\ConnRow.title)]
    @State private var selection = Set<String>()

    var body: some View {
        VStack(spacing: 12) {
            toolbar
            table
                .card()
            LogDrawer(expanded: $logExpanded)
        }
        .padding(.horizontal, 24)
        .padding(.top, 12)
        .padding(.bottom, 16)
    }

    private var toolbar: some View {
        HStack(spacing: 12) {
            Picker("Group by", selection: $grouping) {
                ForEach(Grouping.allCases) { Text(loc($0.rawValue)).tag($0) }
            }
            .pickerStyle(.menu)
            .fixedSize()

            HStack(spacing: 6) {
                ForEach(RouteFilter.allCases) { filter in
                    let selected = routeFilter == filter
                    Button {
                        routeFilter = filter
                    } label: {
                        Text("\(loc(filter.rawValue)) · \(countText(count(filter)))")
                            .font(.system(size: 12))
                            .lineLimit(1)
                            .fixedSize()
                            .padding(.horizontal, 10)
                            .padding(.vertical, 4)
                            .foregroundStyle(selected ? Theme.accentFg : Theme.text2)
                            .background(selected ? Theme.accentBg : .clear, in: Capsule())
                            .overlay(Capsule().stroke(selected ? Theme.accentBorder : Color(hex: 0x2A3037)))
                    }
                    .buttonStyle(.plain)
                }
            }

            Toggle("Show idle", isOn: $showIdle)
                .toggleStyle(.checkbox)
                .fixedSize()
                .help("Keep recently closed connections in the list (Settings → idle time)")
                .foregroundStyle(Theme.text2)
            Spacer()
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(Theme.text3)
                TextField("Filter apps or hosts", text: $search)
                    .textFieldStyle(.plain)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .frame(minWidth: 140, maxWidth: 240)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color(hex: 0x2A3037)))
        }
        .controlSize(.small)
    }

    private func count(_ filter: RouteFilter) -> Int {
        model.flows.values.filter { (showIdle || $0.active > 0) && filter.matches($0.kind) }.count
    }

    private var table: some View {
        Table(sorted(buildRows()), children: \.children, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Application / host", value: \.title) { row in
                HStack(spacing: 8) {
                    if row.isGroup {
                        Text(String(row.title.prefix(1)).uppercased())
                            .font(.system(size: 11, weight: .bold))
                            .frame(width: 22, height: 22)
                            .foregroundStyle(Color(hex: 0x0D0F12))
                            .background(tileColor(row.title), in: RoundedRectangle(cornerRadius: 6))
                        Text(row.title).fontWeight(.semibold).lineLimit(1)
                        Text(row.subtitle).font(.system(size: 11)).foregroundStyle(Theme.text3).lineLimit(1)
                    } else {
                        Circle()
                            .fill(row.active > 0 ? Theme.on : Color(hex: 0x59626C))
                            .frame(width: 7, height: 7)
                        Text(row.title).lineLimit(1).truncationMode(.middle)
                        Text(row.target)
                            .font(Theme.mono)
                            .foregroundStyle(Theme.text2)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                .opacity(dim(row))
            }
            .width(min: 200, ideal: 300)
            TableColumn("Conn.", value: \.active) { row in
                Text(row.total > 1 || row.isGroup ? "\(countText(row.active)) / \(countText(row.total))" : countText(row.active))
                    .monospacedDigit()
                    .foregroundStyle(Theme.text2)
                    .opacity(dim(row))
                    .help("active / total this session")
            }
            .width(min: 60, ideal: 80)
            TableColumn("Time", value: \.lastActivity) { row in
                Text(row.timeText).monospacedDigit().foregroundStyle(Theme.text2).opacity(dim(row))
            }
            .width(min: 70, ideal: 100)
            TableColumn("Route", value: \.rule) { row in
                let colors = Theme.route(row.kind)
                Pill(text: row.rule, bg: colors.bg, fg: colors.fg)
                    .opacity(dim(row))
            }
            .width(min: 130, ideal: 200)
            TableColumn("↓ Received", value: \.received) { row in
                Text(ByteFormat.short(row.received))
                    .monospacedDigit()
                    .fontWeight(row.isGroup ? .medium : .regular)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .opacity(dim(row))
            }
            .width(min: 70, ideal: 90)
            TableColumn("↑ Sent", value: \.sent) { row in
                Text(ByteFormat.short(row.sent))
                    .monospacedDigit()
                    .foregroundStyle(Theme.text2)
                    .frame(maxWidth: .infinity, alignment: .trailing)
                    .opacity(dim(row))
            }
            .width(min: 70, ideal: 90)
        }
        .scrollContentBackground(.hidden)
        .alternatingRowBackgrounds(.disabled)
        .contextMenu(forSelectionType: String.self) { ids in
            if let row = ids.first.flatMap(findRow) {
                if let app = row.ruleApplication {
                    Button("Create Rule for “\(app)”…") { model.createRule(application: app) }
                }
                if let domain = row.ruleDomain {
                    Button("Create Rule for “*.\(domain)”…") { model.createRule(domain: domain) }
                }
                Divider()
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(row.isGroup ? row.title : "\(row.title) → \(row.target)", forType: .string)
                }
            }
        }
    }

    private func tileColor(_ name: String) -> Color {
        let palette: [UInt32] = [0x8AB4F8, 0x7FE3D3, 0xCBB8FF, 0xF3C97A, 0xC7CDD4, 0x9CD67F]
        let hash = name.unicodeScalars.reduce(0) { ($0 &* 31 &+ Int($1.value)) & 0xFFFF }
        return Color(hex: palette[hash % palette.count])
    }

    private func dim(_ row: ConnRow) -> Double {
        row.active > 0 ? 1 : 0.5
    }

    // MARK: Rows

    private func visibleFlows() -> [Flow] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return model.flows.values.filter { flow in
            (showIdle || flow.active > 0)
                && routeFilter.matches(flow.kind)
                && (query.isEmpty || flow.app.lowercased().contains(query) || flow.target.lowercased().contains(query))
        }
    }

    private func buildRows() -> [ConnRow] {
        let flows = visibleFlows()
        switch grouping {
        case .none:
            return flows.map { flowRow($0) }
        case .application:
            return group(flows, by: \.appGroup) { key, members in
                (key, "\(loc(members[0].category.rawValue)) · " + String(localized: "\(Set(members.map(\.host)).count) hosts"), key, nil)
            }
        case .domain:
            return group(flows, by: \.domain) { key, members in
                (key, String(localized: "\(Set(members.map(\.appGroup)).count) apps"), nil, key)
            }
        case .type:
            return group(flows, by: { $0.category.rawValue }) { key, members in
                (loc(key), String(localized: "\(Set(members.map(\.appGroup)).count) apps"), nil, nil)
            }
        }
    }

    private func flowRow(_ f: Flow) -> ConnRow {
        let time: String
        if let since = f.activeSince {
            time = ByteFormat.duration(model.now.timeIntervalSince(since))
        } else {
            time = String(localized: "idle \(ByteFormat.duration(model.now.timeIntervalSince(f.lastActivity)))")
        }
        return ConnRow(
            id: "f:" + f.id, title: f.app, subtitle: "", target: f.target, active: f.active, total: f.total,
            timeText: time, rule: f.rule, kind: f.kind, sent: f.sent, received: f.received,
            lastActivity: f.lastActivity, isGroup: false, children: nil,
            ruleApplication: f.appGroup, ruleDomain: f.domain)
    }

    private func group(_ flows: [Flow], by key: (Flow) -> String, describe: (String, [Flow]) -> (String, String, String?, String?)) -> [ConnRow] {
        Dictionary(grouping: flows, by: key).map { key, members in
            let (title, subtitle, ruleApp, ruleDomain) = describe(key, members)
            let rules = Set(members.map(\.rule))
            let active = members.reduce(0) { $0 + $1.active }
            let kinds = Set(members.map(\.kind))
            return ConnRow(
                id: "g:\(grouping.rawValue):\(key)", title: title, subtitle: subtitle, target: "",
                active: active, total: members.reduce(0) { $0 + $1.total },
                timeText: active > 0 ? String(localized: "\(countText(active)) open") : String(localized: "idle"),
                rule: rules.count == 1 ? rules.first! : String(localized: "\(rules.count) rules"),
                kind: kinds.count == 1 ? kinds.first : nil,
                sent: members.reduce(0) { $0 + $1.sent }, received: members.reduce(0) { $0 + $1.received },
                lastActivity: members.map(\.lastActivity).max() ?? .distantPast, isGroup: true,
                children: members.map { flowRow($0) },
                ruleApplication: ruleApp, ruleDomain: ruleDomain)
        }
    }

    private func sorted(_ rows: [ConnRow]) -> [ConnRow] {
        rows.sorted(using: sortOrder).map { row in
            var r = row
            r.children = row.children.map(sorted)
            return r
        }
    }

    private func findRow(_ id: String) -> ConnRow? {
        for row in buildRows() {
            if row.id == id { return row }
            if let child = row.children?.first(where: { $0.id == id }) { return child }
        }
        return nil
    }
}

/// Collapsible log under the connection list.
struct LogDrawer: View {
    @Environment(AppModel.self) private var model
    @Binding var expanded: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("Log").fontWeight(.semibold)
                Text(loc(model.logMode.rawValue)).font(.system(size: 11)).foregroundStyle(Theme.text3)
                Spacer()
                Button(expanded ? "Collapse" : "Expand") {
                    withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() }
                }
                .buttonStyle(GhostButtonStyle())
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            Rectangle().fill(Color(hex: 0x1F2328)).frame(height: 1)
            if expanded {
                LogView(showHeader: false)
                    .frame(height: 220)
            } else {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(model.log.suffix(3)) { line in
                        LogLineView(line: line)
                    }
                }
                .frame(maxWidth: .infinity, minHeight: 54, alignment: .topLeading)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
            }
        }
        .background(Color(hex: 0x111316), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.border))
    }
}

struct LogLineView: View {
    @Environment(AppModel.self) private var model
    let line: LogLine

    var body: some View {
        Text(model.formatted(line))
            .font(.system(size: 11.5, design: .monospaced))
            .foregroundStyle(color)
            .lineLimit(1)
            .truncationMode(.tail)
    }

    private var color: Color {
        switch line.kind {
        case .normal: return Theme.text2
        case .error: return Theme.warnFg
        case .blocked: return Theme.offFg
        case .notice: return Theme.text3
        }
    }
}

// MARK: - Traffic

struct TrafficPage: View {
    enum Mode: String, CaseIterable, Identifiable {
        case apps = "By application", hosts = "By host"
        var id: String { rawValue }
    }

    @Environment(AppModel.self) private var model
    @State private var mode: Mode = .apps

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeader(title: "Traffic", subtitle: "Totals for this session, refreshed every 2 seconds.") {
                Picker("", selection: $mode) {
                    ForEach(Mode.allCases) { Text(loc($0.rawValue)).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                Button("Reset") { model.resetStatistics() }
                    .buttonStyle(GhostButtonStyle())
            }
            HStack(spacing: 10) {
                stat("Session", ByteFormat.duration(model.now.timeIntervalSince(model.sessionStart)))
                stat("Connections", countText(model.totalConnections))
                stat("Errors", countText(model.totalFailures))
                stat("Blocked", countText(model.totalBlocked))
                stat("Received", ByteFormat.short(model.totalReceived))
                stat("Sent", ByteFormat.short(model.totalSent))
            }
            Group {
                switch mode {
                case .apps: TrafficView()
                case .hosts: StatisticsView()
                }
            }
            .card()
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
    }

    private func stat(_ title: LocalizedStringKey, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.system(size: 11)).foregroundStyle(Theme.text3)
            Text(value).font(.system(size: 16, weight: .semibold).monospacedDigit())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12)
        .padding(.vertical, 9)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(hex: 0x2A3037)))
    }
}

struct TrafficView: View {
    @Environment(AppModel.self) private var model
    @State private var sortOrder = [KeyPathComparator(\AppTraffic.received, order: .reverse)]

    var body: some View {
        Table(model.appTraffic.values.sorted(using: sortOrder), sortOrder: $sortOrder) {
            TableColumn("Application", value: \.id) { Text($0.id).lineLimit(1) }
                .width(min: 160, ideal: 240)
            TableColumn("Type") { Text(loc($0.category.rawValue)).foregroundStyle(Theme.text2) }
                .width(min: 80, ideal: 130)
            TableColumn("Active", value: \.active) { Text(countText($0.active)).monospacedDigit() }
                .width(min: 50, ideal: 60)
            TableColumn("Connections", value: \.total) { Text(countText($0.total)).monospacedDigit() }
                .width(min: 60, ideal: 80)
            TableColumn("Download", value: \.downRate) { Text(ByteFormat.rate($0.downRate)).monospacedDigit() }
                .width(min: 70, ideal: 90)
            TableColumn("Upload", value: \.upRate) { Text(ByteFormat.rate($0.upRate)).monospacedDigit() }
                .width(min: 70, ideal: 90)
            TableColumn("Received", value: \.received) { Text(ByteFormat.short($0.received)).monospacedDigit() }
                .width(min: 60, ideal: 80)
            TableColumn("Sent", value: \.sent) { Text(ByteFormat.short($0.sent)).monospacedDigit() }
                .width(min: 60, ideal: 80)
        }
        .scrollContentBackground(.hidden)
        .alternatingRowBackgrounds(.disabled)
    }
}

struct StatisticsView: View {
    @Environment(AppModel.self) private var model
    @State private var sortOrder = [KeyPathComparator(\HostStat.received, order: .reverse)]

    var body: some View {
        Table(model.hostStats.values.sorted(using: sortOrder), sortOrder: $sortOrder) {
            TableColumn("Host", value: \.id) { Text($0.id).font(Theme.mono).lineLimit(1) }
                .width(min: 130, ideal: 200)
            TableColumn("Applications") { Text($0.apps.sorted().joined(separator: ", ")).lineLimit(1) }
                .width(min: 100, ideal: 180)
            TableColumn("Connections", value: \.connections) { Text(countText($0.connections)).monospacedDigit() }
                .width(min: 60, ideal: 80)
            TableColumn("Errors", value: \.failures) { Text(countText($0.failures)).monospacedDigit() }
                .width(min: 40, ideal: 50)
            TableColumn("Received", value: \.received) { Text(ByteFormat.short($0.received)).monospacedDigit() }
                .width(min: 60, ideal: 75)
            TableColumn("Sent", value: \.sent) { Text(ByteFormat.short($0.sent)).monospacedDigit() }
                .width(min: 60, ideal: 75)
            TableColumn("Route", value: \.route) { Text($0.route).lineLimit(1) }
                .width(min: 100, ideal: 200)
        }
        .scrollContentBackground(.hidden)
        .alternatingRowBackgrounds(.disabled)
    }
}

// MARK: - Log

struct LogPage: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PageHeader(title: "Log", subtitle: "Compact mode hides close events and repeats each host at most once a minute.") {
                EmptyView()
            }
            LogView(showHeader: true)
                .background(Color(hex: 0x111316), in: RoundedRectangle(cornerRadius: 10))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Theme.border))
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
    }
}

struct LogView: View {
    @Environment(AppModel.self) private var model
    var showHeader = true
    @State private var follow = true

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 0) {
            if showHeader {
                HStack {
                    Picker("", selection: $model.logMode) {
                        ForEach(LogMode.allCases) { Text(loc($0.rawValue)).tag($0) }
                    }
                    .labelsHidden()
                    .fixedSize()
                    Toggle("Auto-scroll", isOn: $follow).toggleStyle(.checkbox)
                    Spacer()
                    Button("Copy Log") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(model.log.map(model.formatted).joined(separator: "\n"), forType: .string)
                    }
                    .buttonStyle(GhostButtonStyle())
                    Button("Clear Log") { model.clearLog() }
                        .buttonStyle(GhostButtonStyle())
                }
                .controlSize(.small)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                Rectangle().fill(Color(hex: 0x1F2328)).frame(height: 1)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 3) {
                        ForEach(model.log) { line in
                            LogLineView(line: line)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(line.id)
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .textSelection(.enabled)
                }
                .onChange(of: model.log.last?.id) { _, last in
                    if follow, let last {
                        proxy.scrollTo(last, anchor: .bottom)
                    }
                }
            }
        }
    }
}

import AppKit
import PGCore
import SwiftUI

struct RulesPage: View {
    @Environment(AppModel.self) private var model
    @State private var editing: Rule?
    @State private var importing = false
    @State private var note: String?
    @AppStorage("routeTestApp") private var testApp = "codex"
    @AppStorage("routeTestTarget") private var testTarget = "api.openai.com:443"

    var body: some View {
        @Bindable var model = model
        VStack(alignment: .leading, spacing: 14) {
            PageHeader(title: "Rules", subtitle: "Checked top to bottom — the first match wins. Drag to reorder.") {
                if let note {
                    Text(note).font(.caption).foregroundStyle(Theme.onFg)
                }
                Menu {
                    Button("Copy All Rules") { copy(model.profile.rules) }
                } label: {
                    Label("Copy as Text", systemImage: "doc.on.doc")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .buttonStyle(GhostButtonStyle())
                .help("Copy rules as a base64 string to share or move to another Mac")
                Button {
                    importing = true
                } label: {
                    Label("Paste", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(GhostButtonStyle())
                if !model.hasRussianRule || !model.hasDockerRule || !model.hasYouTubeRule {
                    Menu {
                        if !model.hasRussianRule { Button("Russian / local sites → Direct") { model.addRussianDirectRule() } }
                        if !model.hasDockerRule { Button("Docker → Direct") { model.addDockerRule() } }
                        if !model.hasYouTubeRule { Button("YouTube → Direct + DPI") { model.addYouTubeRule() } }
                    } label: {
                        Label("Presets", systemImage: "wand.and.stars")
                    }
                    .menuStyle(.borderlessButton).fixedSize().buttonStyle(GhostButtonStyle())
                }
                Button {
                    editing = Rule(name: String(localized: "New rule"))
                } label: {
                    Label("New Rule", systemImage: "plus")
                }
                .buttonStyle(AccentButtonStyle())
            }

            routeTester

            List {
                ForEach(model.profile.rules.filter { $0.locked && !$0.isDefault }) { rule in
                    RuleCard(rule: rule, onEdit: { editing = rule }, onCopy: nil)
                        .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                        .listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                        .moveDisabled(true)
                }
                ForEach(model.profile.rules.filter { !$0.isDefault && !$0.locked }) { rule in
                    RuleCard(rule: rule, onEdit: { editing = rule }, onCopy: { copy([rule]) })
                        .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                        .listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                }
                .onMove { from, to in
                    var p = model.profile
                    let locked = p.rules.filter { $0.locked && !$0.isDefault }
                    var custom = p.rules.filter { !$0.isDefault && !$0.locked }
                    custom.move(fromOffsets: from, toOffset: to)
                    p.rules = locked + custom + p.rules.filter(\.isDefault)
                    model.profile = p
                }
                if let defaultRule = model.profile.rules.last(where: \.isDefault) {
                    RuleCard(rule: defaultRule, onEdit: { editing = defaultRule }, onCopy: nil)
                        .listRowInsets(EdgeInsets(top: 4, leading: 0, bottom: 4, trailing: 0))
                        .listRowSeparator(.hidden)
                        .listRowBackground(Color.clear)
                        .moveDisabled(true)
                }
            }
            .listStyle(.plain)
            .scrollContentBackground(.hidden)
        }
        .padding(.horizontal, 24)
        .padding(.top, 18)
        .onAppear(perform: openDraft)
        .onChange(of: model.ruleDraft?.id) { _, _ in openDraft() }
        .sheet(item: $editing) { rule in
            RuleEditor(rule: rule, profile: model.profile, seenApps: model.seenApps.sorted(), seenHosts: model.recentHosts) { saved in
                var p = model.profile
                if let i = p.rules.firstIndex(where: { $0.id == saved.id }) {
                    p.rules[i] = saved
                } else {
                    p.rules.insert(saved, at: p.rules.firstIndex(where: \.isDefault) ?? p.rules.count)
                }
                model.profile = p
            }
        }
        .sheet(isPresented: $importing) {
            ImportRulesSheet(profile: $model.profile)
        }
    }

    private var routeTester: some View {
        HStack(spacing: 10) {
            Image(systemName: "arrow.right.circle").foregroundStyle(Theme.accentFg)
            Text("Test route:").foregroundStyle(Theme.text2)
            TextField("Application", text: $testApp)
                .textFieldStyle(.plain)
                .font(Theme.mono)
                .frame(width: 140)
            Image(systemName: "arrow.right").foregroundStyle(Theme.text3)
            TextField("host:port", text: $testTarget)
                .textFieldStyle(.plain)
                .font(Theme.mono)
            Spacer()
            if let rule = model.testRoute(app: testApp, target: testTarget) {
                let colors = Theme.route(kind(rule.action))
                Pill(text: String(localized: "matches “\(rule.name)” → \(model.profile.describe(rule.action))"), bg: colors.bg, fg: colors.fg)
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(Theme.sidebar, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Color(hex: 0x344049), style: StrokeStyle(lineWidth: 1, dash: [4, 3])))
    }

    private func kind(_ action: RuleAction) -> RouteKind {
        switch action {
        case .direct, .directDPI: return .direct
        case .block: return .block
        case .proxy, .chain, .vpn, .global: return .proxy
        }
    }

    private func openDraft() {
        if let draft = model.ruleDraft {
            model.ruleDraft = nil
            editing = draft
        }
    }

    private func copy(_ rules: [Rule]) {
        let exported = rules.filter { !$0.isDefault }
        guard !exported.isEmpty else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(RuleTransfer.export(exported, from: model.profile), forType: .string)
        note = String(localized: "Copied \(exported.count) rules")
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { note = nil }
    }
}

struct RuleCard: View {
    @Environment(AppModel.self) private var model
    let rule: Rule
    let onEdit: () -> Void
    let onCopy: (() -> Void)?

    private struct Chip: Identifiable {
        let id = UUID()
        let text: String
        let bg: Color
        let fg: Color
        let mono: Bool
        var shadowed = false
    }

    /// Host targets covered by an earlier/dynamic rule — marked inactive (a red dot).
    private var shadowedHosts: Set<String> {
        guard let i = model.profile.rules.firstIndex(where: { $0.id == rule.id }) else { return [] }
        return RuleShadow.shadowedHosts(in: model.profile.rules, ruleIndex: i)
    }

    private var chips: [Chip] {
        let shadowed = shadowedHosts
        var out: [Chip] = []
        for app in Patterns.split(rule.applications) where app.lowercased() != "any" {
            out.append(Chip(text: "▢ " + app, bg: Theme.appChipBg, fg: Theme.appChipFg, mono: false))
        }
        for host in Patterns.split(rule.targetHosts) where host.lowercased() != "any" {
            let isName = [.domain, .wildcard].contains(Patterns.hostKind(host))
            out.append(Chip(text: host, bg: isName ? Theme.hostChipBg : Theme.neutralBg, fg: isName ? Theme.hostChipFg : Theme.neutralFg, mono: true, shadowed: shadowed.contains(host)))
        }
        for port in Patterns.split(rule.targetPorts) where port.lowercased() != "any" {
            out.append(Chip(text: ":" + port, bg: Theme.portChipBg, fg: Theme.portChipFg, mono: true))
        }
        if out.count > 8 {
            let rest = out.count - 7
            out = Array(out.prefix(7)) + [Chip(text: "+\(rest)", bg: Theme.neutralBg, fg: Theme.neutralFg, mono: true)]
        }
        return out
    }

    private var hitsText: String {
        if rule.isDefault { return String(localized: "everything else · always last") }
        if !rule.enabled { return String(localized: "disabled") }
        guard let hits = model.ruleHits[rule.name], hits.count > 0 else { return String(localized: "no matches yet") }
        return String(localized: "matched \(countText(hits.count)) times · \(hits.last.formatted(.relative(presentation: .named)))")
    }

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: rule.isDefault || rule.locked ? "lock" : "line.3.horizontal")
                .foregroundStyle(Color(hex: 0x59626C))
                .frame(width: 16)
            Toggle("", isOn: Binding(
                get: { rule.enabled },
                set: { value in update { $0.enabled = value } }))
                .toggleStyle(.switch)
                .controlSize(.mini)
                .labelsHidden()
                .disabled(rule.isDefault || rule.locked)
                .opacity(rule.isDefault ? 0 : 1)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(rule.name).fontWeight(.semibold).lineLimit(1)
                    if rule.dynamic {
                        Text("dynamic").font(.system(size: 9.5, weight: .bold)).foregroundStyle(Theme.warnFg)
                            .padding(.horizontal, 6).padding(.vertical, 1).background(Theme.warnBg, in: Capsule())
                    }
                }
                Text(hitsText).font(.system(size: 11)).foregroundStyle(Theme.text3).lineLimit(1)
            }
            .frame(width: 190, alignment: .leading)
            Group {
                if chips.isEmpty {
                    Text("Any application, any host, any port").foregroundStyle(Theme.text3)
                } else {
                    FlowLayout(spacing: 6) {
                        ForEach(chips) { chip in
                            HStack(spacing: 5) {
                                if chip.shadowed { Circle().fill(Color(hex: 0xE5484D)).frame(width: 6, height: 6) }
                                Text(chip.text)
                                    .font(chip.mono ? Theme.mono : .system(size: 12))
                                    .lineLimit(1)
                                    .strikethrough(chip.shadowed, color: Color(hex: 0xE5484D))
                            }
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .foregroundStyle(chip.shadowed ? Theme.text3 : chip.fg)
                            .background(chip.bg.opacity(chip.shadowed ? 0.4 : 1), in: RoundedRectangle(cornerRadius: 6))
                            .help(chip.shadowed ? String(localized: "Overridden by an earlier rule — inactive") : "")
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            VStack(alignment: .leading, spacing: 2) {
                Text("Action").textCase(.uppercase).font(.system(size: 10)).foregroundStyle(Theme.text3)
                Picker("Action", selection: Binding(
                    get: { rule.action },
                    set: { value in update { $0.action = value } })) {
                    ActionOptions(profile: model.profile)
                }
                .labelsHidden()
                .frame(width: 220)
                .disabled(rule.locked)
            }
            Button(action: onEdit) {
                Image(systemName: "pencil")
                    .frame(width: 28, height: 28)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(Theme.text2)
            .accessibilityLabel("Edit rule \(rule.name)")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .background(rule.dynamic ? Color(hex: 0x211c12) : (rule.isDefault ? Theme.header : Theme.card), in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(rule.dynamic ? Color(hex: 0x5A4322) : (rule.isDefault ? Theme.accentBorder : Theme.border)))
        .opacity(rule.enabled ? 1 : 0.55)
        .contentShape(Rectangle())
        .onTapGesture(count: 2, perform: onEdit)
        .contextMenu {
            Button("Edit…", action: onEdit)
            if !rule.isDefault && !rule.locked {
                Button("Clone") {
                    var p = model.profile
                    guard let i = p.rules.firstIndex(where: { $0.id == rule.id }) else { return }
                    var copy = rule
                    copy.id = UUID()
                    copy.name += String(localized: " (copy)")
                    p.rules.insert(copy, at: i + 1)
                    model.profile = p
                }
                if let onCopy {
                    Button("Copy as Text", action: onCopy)
                }
                Divider()
                Button("Delete", role: .destructive) {
                    var p = model.profile
                    p.rules.removeAll { $0.id == rule.id }
                    model.profile = p
                }
            }
        }
    }

    private func update(_ change: (inout Rule) -> Void) {
        var p = model.profile
        guard let i = p.rules.firstIndex(where: { $0.id == rule.id }) else { return }
        change(&p.rules[i])
        model.profile = p
    }
}

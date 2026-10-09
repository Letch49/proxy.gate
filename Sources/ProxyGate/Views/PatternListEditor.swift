import AppKit
import PGCore
import SwiftUI

/// Edits a `;`-separated rule field as a list: one validated entry per row,
/// with presets and suggestions from what ProxyGate has already seen.
struct PatternListEditor: View {
    enum Kind {
        case applications, hosts, ports

        var placeholder: String {
            switch self {
            case .applications: return "App name, e.g. codex or Google Chrome"
            case .hosts: return "example.com, *.corp.local, 10.0.0.0/8…"
            case .ports: return "443 or 8000-9000"
            }
        }

        var emptyText: String {
            switch self {
            case .applications: return "Any application"
            case .hosts: return "Any host"
            case .ports: return "Any port"
            }
        }
    }

    struct Preset {
        let title: String
        let entries: [String]
    }

    let kind: Kind
    @Binding var text: String
    var suggestions: [String] = []
    @State private var input = ""
    @State private var error: String?

    private var entries: [String] { Patterns.split(text) }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            VStack(spacing: 0) {
                if entries.isEmpty {
                    Text(loc(kind.emptyText))
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                } else {
                    ScrollView {
                        VStack(spacing: 0) {
                            ForEach(Array(entries.enumerated()), id: \.offset) { index, entry in
                                row(entry, index: index)
                                if index < entries.count - 1 { Divider() }
                            }
                        }
                    }
                    .frame(maxHeight: 132)
                }
            }
            .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))

            HStack(spacing: 6) {
                TextField("", text: $input, prompt: Text(loc(kind.placeholder)))
                    .textFieldStyle(.roundedBorder)
                    .onSubmit(addInput)
                Button("Add", action: addInput)
                    .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
                addMenu
            }
            if let error {
                Text(error).font(.caption).foregroundStyle(.red)
            }
        }
    }

    private func row(_ entry: String, index: Int) -> some View {
        let k = entryKind(entry)
        return HStack(spacing: 8) {
            Image(systemName: icon(k))
                .foregroundStyle(k == .invalid ? .red : .secondary)
                .frame(width: 16)
            Text(entry)
                .lineLimit(1)
            Spacer()
            Text(loc(k.rawValue))
                .font(.caption)
                .foregroundStyle(k == .invalid ? .red : .secondary)
            Button {
                var list = entries
                list.remove(at: index)
                text = Patterns.join(list)
            } label: {
                Image(systemName: "xmark.circle.fill")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .help("Remove")
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var addMenu: some View {
        Menu {
            ForEach(presets, id: \.title) { preset in
                Button(loc(preset.title)) { add(preset.entries) }
            }
            if kind == .applications {
                Divider()
                Button("Choose Application…") { browse() }
                Menu("Running Applications") {
                    ForEach(runningApps, id: \.self) { name in
                        Button(name) { add([name]) }
                    }
                }
            }
            if !suggestions.isEmpty {
                Divider()
                suggestionItems
            }
        } label: {
            Image(systemName: "plus.rectangle.on.rectangle")
        }
        .fixedSize()
        .help(kind == .applications ? "Presets and recently seen applications" : "Presets and recently seen hosts")
    }

    @ViewBuilder
    private var suggestionItems: some View {
        if kind == .hosts {
            // Grouped by domain: "*.chatgpt.com" or a specific host.
            let byDomain = Dictionary(grouping: suggestions.prefix(150), by: Patterns.baseDomain)
            Menu("Seen Hosts") {
                ForEach(byDomain.keys.sorted(), id: \.self) { domain in
                    let hosts = byDomain[domain]!.sorted()
                    if IPAddr(domain) != nil {
                        Button(domain) { add([domain]) }
                    } else {
                        Menu(domain) {
                            Button("*.\(domain)  (all subdomains)") { add(["*.\(domain)"]) }
                            Divider()
                            ForEach(hosts, id: \.self) { host in
                                Button(host) { add([host]) }
                            }
                        }
                    }
                }
            }
        } else {
            Menu("Seen Applications") {
                ForEach(suggestions.sorted { $0.lowercased() < $1.lowercased() }, id: \.self) { name in
                    Button(name) { add([name]) }
                }
            }
        }
    }

    private var presets: [Preset] {
        switch kind {
        case .hosts:
            return [
                Preset(title: "Local networks", entries: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "*.local"]),
                Preset(title: "Localhost", entries: ["localhost", "127.0.0.1", "::1"]),
                Preset(title: "Russian domains (.ru, .рф, .su)", entries: ["*.ru", "*.xn--p1ai", "*.su"]),
                Preset(title: "Apple services", entries: ["*.apple.com", "*.icloud.com", "*.mzstatic.com", "*.apple-cloudkit.com"]),
                Preset(title: "Google", entries: ["*.google.com", "*.googleapis.com", "*.gstatic.com", "*.youtube.com"]),
                Preset(title: "OpenAI / ChatGPT", entries: ["*.openai.com", "*.chatgpt.com", "*.oaistatic.com"]),
                Preset(title: "GitHub", entries: ["*.github.com", "*.githubusercontent.com", "*.githubassets.com"]),
            ]
        case .ports:
            return [
                Preset(title: "Web (80, 443)", entries: ["80", "443"]),
                Preset(title: "SSH (22)", entries: ["22"]),
                Preset(title: "Mail (25, 465, 587, 993)", entries: ["25", "465", "587", "993"]),
                Preset(title: "Dev servers (3000-9999)", entries: ["3000-9999"]),
            ]
        case .applications:
            return [
                Preset(title: "Browsers", entries: ["Google Chrome", "Safari", "Firefox", "Arc", "Yandex"]),
                Preset(title: "Terminal tools", entries: ["curl", "git", "ssh", "python3", "node", "uv", "codex"]),
            ]
        }
    }

    private var runningApps: [String] {
        Set(NSWorkspace.shared.runningApplications
            .filter { $0.activationPolicy == .regular }
            .compactMap(\.localizedName))
            .sorted()
    }

    private func entryKind(_ entry: String) -> PatternKind {
        switch kind {
        case .hosts: return Patterns.hostKind(entry)
        case .ports: return Patterns.portKind(entry)
        case .applications: return .application
        }
    }

    private func icon(_ k: PatternKind) -> String {
        switch k {
        case .domain: return "globe"
        case .wildcard: return "asterisk"
        case .ip: return "number"
        case .range: return "arrow.left.and.right"
        case .cidr: return "point.3.connected.trianglepath.dotted"
        case .port, .portRange: return "door.left.hand.open"
        case .application: return "app"
        case .invalid: return "exclamationmark.triangle.fill"
        }
    }

    private func addInput() {
        // Accept pasted lists ("a.com, b.com; c.com" or one per line).
        let items = kind == .applications
            ? Patterns.split(input)
            : input.components(separatedBy: CharacterSet(charactersIn: ";,\n ")).filter { !$0.isEmpty }
        let invalid = items.filter { entryKind($0) == .invalid }
        guard invalid.isEmpty else {
            error = String(localized: "Not valid: \(invalid.joined(separator: ", "))")
            return
        }
        add(items)
        input = ""
    }

    private func add(_ items: [String]) {
        error = nil
        var list = entries
        for item in items {
            let value = kind == .hosts ? item.lowercased() : item
            if !list.contains(where: { $0.caseInsensitiveCompare(value) == .orderedSame }) {
                list.append(value)
            }
        }
        text = Patterns.join(list)
    }

    private func browse() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        guard panel.runModal() == .OK else { return }
        add(panel.urls.map { $0.pathExtension == "app" ? $0.deletingPathExtension().lastPathComponent : $0.lastPathComponent })
    }
}

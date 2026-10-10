import AppKit
import PGCore
import SwiftUI

/// Local MCP endpoint so an AI agent can read and edit rules and read the log and stats.
struct MCPPage: View {
    @Environment(AppModel.self) private var model
    @State private var showToken = false

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    private var setupCommand: String {
        "claude mcp add --transport http proxygate \(model.mcpURL) --header \"Authorization: Bearer \(model.mcpToken)\""
    }

    private var statusNote: String {
        if !model.mcpEnabled { return String(localized: "Off") }
        if model.mcpActive { return String(localized: "An agent has connected") }
        if model.mcpRunning { return String(localized: "Waiting for an agent") }
        return String(localized: "Not running")
    }

    var body: some View {
        @Bindable var model = model
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "AI control (MCP)",
                           subtitle: "A local endpoint so an AI agent can manage rules and read the log and stats.") { EmptyView() }

                HStack(spacing: 14) {
                    Toggle("", isOn: $model.mcpEnabled)
                        .toggleStyle(.switch).controlSize(.mini).labelsHidden()
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Let an AI agent manage rules (MCP)").font(.system(size: 13, weight: .semibold))
                        Text(statusNote).font(.system(size: 11)).foregroundStyle(Theme.text2).lineLimit(1)
                    }
                    Spacer()
                    if model.mcpEnabled {
                        Pill(text: model.mcpRunning ? String(localized: "Active") : String(localized: "Stopped"),
                             bg: model.mcpRunning ? Theme.onBg : Theme.warnBg,
                             fg: model.mcpRunning ? Theme.onFg : Theme.warnFg)
                    }
                }
                .padding(.horizontal, 14).padding(.vertical, 11)
                .card(radius: 12, border: model.mcpEnabled ? Theme.accentBorder : Theme.border)

                if model.mcpEnabled {
                    VStack(alignment: .leading, spacing: 12) {
                        detailRow("Address") {
                            Text(model.mcpURL).font(Theme.mono).textSelection(.enabled)
                        }
                        detailRow("Port") {
                            TextField("", value: Binding(
                                get: { model.mcpPort },
                                set: { model.mcpPort = min(65535, max(1024, $0)) }),
                                format: .number.grouping(.never))
                                .frame(width: 100)
                        }
                        detailRow("Token") {
                            HStack(spacing: 8) {
                                Text(showToken ? model.mcpToken : String(repeating: "•", count: 20))
                                    .font(Theme.mono).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Button(showToken ? "Hide" : "Show") { showToken.toggle() }
                                Button("Copy") { copy(model.mcpToken) }
                                Button("New token") { model.regenerateMCPToken(); showToken = false }
                            }
                        }
                        Divider().overlay(Theme.border)
                        Button("Copy Claude Code command") { copy(setupCommand) }
                            .buttonStyle(AccentButtonStyle())
                    }
                    .padding(16).card(radius: 12)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Runs a local server on 127.0.0.1 only, guarded by the token above. An agent can view, add, change, delete and reorder rules, and read the journal and stats. It cannot start redirection or change VPN, DPI or AnyConnect.")
                    Text("To connect from Claude Code, enable this, then run \"Copy Claude Code command\" and paste it in a terminal. The status turns green once an agent has connected. Regenerate the token to revoke access.")
                }
                .font(.caption).foregroundStyle(Theme.text3)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
    }

    private func detailRow<Content: View>(_ title: LocalizedStringKey, @ViewBuilder _ content: () -> Content) -> some View {
        HStack(spacing: 12) {
            Text(title).font(.system(size: 12)).foregroundStyle(Theme.text3).frame(width: 70, alignment: .leading)
            content()
            Spacer(minLength: 0)
        }
    }
}

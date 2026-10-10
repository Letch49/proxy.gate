import PGCore
import SwiftUI

struct AnyConnectPage: View {
    @Environment(AppModel.self) private var model
    @State private var server = ""
    @State private var user = ""
    @State private var password = ""
    @State private var loaded = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                PageHeader(title: "AnyConnect", subtitle: "Cisco AnyConnect tunnel (openconnect). Only corporate subnets go through it; VPN keeps working in parallel.") { EmptyView() }

                if !model.openConnectInstalled {
                    HStack(spacing: 10) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Theme.warnFg)
                        Text("openconnect is not installed yet.")
                        Spacer()
                        Button("Open Settings") { model.section = .settings }.buttonStyle(GhostButtonStyle())
                    }
                    .padding(14).card(radius: 12, border: Theme.borderStrong)
                }

                stateCard

                VStack(alignment: .leading, spacing: 12) {
                    field("Access point", $server, prompt: "vpn.company.com", mono: true)
                    field("Login", $user, prompt: "username", mono: false)
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Password · Keychain").font(.caption).foregroundStyle(Theme.text3)
                        SecureField("", text: $password, prompt: Text("••••••••"))
                    }
                    HStack {
                        Text("The second factor is approved by a push on your phone — nothing to type here.")
                            .font(.caption).foregroundStyle(Theme.text3)
                        Spacer()
                        if model.anyConnectUp || model.anyConnectBusy {
                            Button("Disconnect") { model.anyConnectDisconnect() }.buttonStyle(GhostButtonStyle(destructive: true))
                        } else {
                            Button("Authorize") { model.anyConnectConnect(server: server, user: user, password: password) }
                                .buttonStyle(AccentButtonStyle())
                                .disabled(server.isEmpty || user.isEmpty || !model.openConnectInstalled)
                        }
                    }
                }
                .padding(16).card(radius: 12)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
        }
        .onAppear {
            guard !loaded else { return }
            loaded = true
            server = model.anyConnectServer
            user = model.anyConnectUser
            password = model.savedAnyConnectPassword(server: server, user: user)
        }
    }

    @ViewBuilder private var stateCard: some View {
        let ac = model.anyConnect
        switch ac.phase {
        case .authenticating, .connecting:
            row(spinner: true, title: String(localized: ac.phase == .authenticating ? "Authorizing…" : "Connecting…"), sub: nil, accent: true)
        case .awaitingApproval:
            row(spinner: true, title: String(localized: "Approve the sign-in on your phone"),
                sub: String(localized: "A push “Is this you?” was sent to your phone — tap Approve."), accent: true)
        case .connected:
            row(spinner: false, title: String(localized: "Connected · \(ac.server ?? "")"),
                sub: ac.routes.isEmpty ? String(localized: "corporate subnets routed through the tunnel")
                                       : String(localized: "\(countTextRoutes(ac.routes.count)) · VPN runs in parallel"), accent: true)
        case .error:
            row(spinner: false, title: String(localized: "Not connected"), sub: ac.message, accent: false)
        case .idle:
            EmptyView()
        }
    }

    private func row(spinner: Bool, title: String, sub: String?, accent: Bool) -> some View {
        HStack(spacing: 12) {
            if spinner { ProgressView().controlSize(.small) }
            else { Circle().fill(accent ? Theme.on : Theme.offFg).frame(width: 9, height: 9) }
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.system(size: 14, weight: .semibold))
                // `sub` can be an engine message; look it up in the string table so ru/en match.
                if let sub { Text(LocalizedStringKey(sub)).font(.system(size: 12.5)).foregroundStyle(Theme.text2) }
            }
            Spacer()
        }
        .padding(16).card(radius: 12, border: accent ? Theme.accentBorder : Theme.border)
    }

    private func field(_ label: LocalizedStringKey, _ text: Binding<String>, prompt: String, mono: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.caption).foregroundStyle(Theme.text3)
            TextField("", text: text, prompt: Text(prompt))
                .font(mono ? Theme.mono : .body)
                .disabled(model.anyConnectUp || model.anyConnectBusy)
        }
    }

    private func countTextRoutes(_ n: Int) -> String { String(localized: "\(n) subnets") }
}

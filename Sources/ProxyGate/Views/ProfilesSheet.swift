import AppKit
import PGCore
import SwiftUI
import UniformTypeIdentifiers

struct ProfilesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var selection: UUID?
    @State private var renaming = false
    @State private var newName = ""

    private var selected: Profile? {
        selection.flatMap { id in model.profiles.first { $0.id == id } }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Profiles").font(.title2.weight(.semibold))
            Text("A profile holds proxies, rules, DNS and advanced settings. Double-click to load.")
                .font(.callout)
                .foregroundStyle(.secondary)
            HStack(alignment: .top, spacing: 12) {
                List(selection: $selection) {
                    ForEach(model.profiles) { profile in
                        HStack {
                            Image(systemName: profile.id == model.activeProfileID ? "checkmark.circle.fill" : "circle")
                                .foregroundStyle(profile.id == model.activeProfileID ? Color.accentColor : .secondary)
                            Text(profile.name)
                            Spacer()
                            Text("\(profile.proxies.count) proxies · \(profile.rules.count) rules")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        .tag(profile.id)
                    }
                }
                .contextMenu(forSelectionType: UUID.self) { _ in
                } primaryAction: { ids in
                    if let id = ids.first { model.activate(id) }
                }
                VStack(spacing: 8) {
                    Button("Load") { if let id = selection { model.activate(id) } }
                        .disabled(selection == nil || selection == model.activeProfileID)
                    Button("New") { add(Profile.makeDefault(name: "Profile \(model.profiles.count + 1)")) }
                    Button("Duplicate") {
                        guard var copy = selected else { return }
                        copy.id = UUID()
                        copy.name += " copy"
                        add(copy)
                    }
                    .disabled(selection == nil)
                    Button("Rename…") {
                        newName = selected?.name ?? ""
                        renaming = true
                    }
                    .disabled(selection == nil)
                    Button("Delete") { delete() }
                        .disabled(selection == nil || model.profiles.count < 2)
                    Divider()
                    Button("Import…") { importProfile() }
                    Button("Export…") { exportProfile() }
                        .disabled(selection == nil)
                }
                .buttonStyle(FullWidthButtonStyle())
                .frame(width: 110)
            }
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 600, height: 400)
        .onAppear { selection = model.activeProfileID }
        .alert("Rename Profile", isPresented: $renaming) {
            TextField("Name", text: $newName)
            Button("Cancel", role: .cancel) {}
            Button("Rename") { rename() }
        }
    }

    private func add(_ profile: Profile) {
        model.profiles.append(profile)
        selection = profile.id
        model.persistAndPush()
    }

    private func rename() {
        let name = newName.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, let id = selection, let i = model.profiles.firstIndex(where: { $0.id == id }) else { return }
        model.profiles[i].name = name
        model.persistAndPush()
    }

    private func delete() {
        guard let id = selection, model.profiles.count > 1 else { return }
        if id == model.activeProfileID, let other = model.profiles.first(where: { $0.id != id }) {
            model.activate(other.id)
        }
        model.profiles.removeAll { $0.id == id }
        selection = model.activeProfileID
        model.persistAndPush()
    }

    private func importProfile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            add(try ProfileStore.importProfile(from: url))
        } catch {
            model.alertMessage = "Cannot import profile: \(error.localizedDescription)"
        }
    }

    private func exportProfile() {
        guard let profile = selected else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "\(profile.name).json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try ProfileStore.export(profile, to: url)
        } catch {
            model.alertMessage = "Cannot export profile: \(error.localizedDescription)"
        }
    }
}

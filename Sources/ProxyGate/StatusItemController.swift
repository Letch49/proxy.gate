import AppKit
import PGCore

/// Menu bar item built with AppKit: every menu entry is a plain target/action,
/// and the menu is rebuilt each time it opens so it always reflects the current state.
@MainActor
final class StatusItemController: NSObject, NSMenuDelegate {
    private let model: AppModel
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private var timer: Timer?
    private var lastRunning: Bool?

    init(model: AppModel) {
        self.model = model
        super.init()
        let menu = NSMenu()
        menu.delegate = self
        item.menu = menu
        item.button?.imagePosition = .imageLeading
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: PGConstants.statsInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        guard let button = item.button else { return }
        if lastRunning != model.isRunning {
            lastRunning = model.isRunning
            button.image = GateIcon.statusImage(running: model.isRunning)
        }
        let title = model.showSpeedInMenuBar && model.isRunning
            ? " ↓\(ByteFormat.rate(model.downRate)) ↑\(ByteFormat.rate(model.upRate))"
            : ""
        if button.title != title {
            button.title = title
            button.font = .monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
        }
        button.toolTip = "ProxyGate — \(model.statusText)"
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()

        menu.addItem(disabled("ProxyGate — \(model.statusText)"))
        if model.isRunning {
            menu.addItem(disabled(String(format: String(localized: "%lld connections · ↓ %@ ↑ %@"),
                                         model.activeConnectionCount, ByteFormat.rate(model.downRate), ByteFormat.rate(model.upRate))))
        }
        menu.addItem(.separator())

        let toggle = action(model.isRunning ? String(localized: "Stop Redirection") : String(localized: "Start Redirection"), #selector(toggleRunning))
        toggle.isEnabled = model.engineConnected || !model.helperInstalled
        menu.addItem(toggle)

        let profiles = NSMenu()
        for profile in model.profiles {
            let entry = action(profile.name, #selector(selectProfile(_:)))
            entry.representedObject = profile.id
            entry.state = profile.id == model.activeProfileID ? .on : .off
            profiles.addItem(entry)
        }
        let profileItem = NSMenuItem(title: String(format: String(localized: "Profile: %@"), model.profile.name), action: nil, keyEquivalent: "")
        profileItem.submenu = profiles
        menu.addItem(profileItem)

        let rules = NSMenu()
        for rule in model.profile.rules {
            let entry = action("\(rule.name)  →  \(model.profile.describeLong(rule.action))", #selector(toggleRule(_:)))
            entry.representedObject = rule.id
            entry.state = rule.enabled ? .on : .off
            entry.isEnabled = !rule.isDefault
            rules.addItem(entry)
        }
        rules.addItem(.separator())
        rules.addItem(action(String(localized: "Edit Rules…"), #selector(editRules)))
        let rulesItem = NSMenuItem(title: String(localized: "Rules"), action: nil, keyEquivalent: "")
        rulesItem.submenu = rules
        menu.addItem(rulesItem)

        menu.addItem(.separator())
        menu.addItem(action(String(localized: "Open ProxyGate"), #selector(openMain)))
        menu.addItem(action(String(localized: "Quit ProxyGate"), #selector(quit), key: "q"))
    }

    private func disabled(_ title: String) -> NSMenuItem {
        let entry = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        entry.isEnabled = false
        return entry
    }

    private func action(_ title: String, _ selector: Selector, key: String = "") -> NSMenuItem {
        let entry = NSMenuItem(title: title, action: selector, keyEquivalent: key)
        entry.target = self
        return entry
    }

    @objc private func toggleRunning() {
        model.toggle()
        refresh()
    }

    @objc private func selectProfile(_ sender: NSMenuItem) {
        if let id = sender.representedObject as? UUID {
            model.activate(id)
        }
    }

    @objc private func toggleRule(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? UUID,
              let i = model.profile.rules.firstIndex(where: { $0.id == id }) else { return }
        var profile = model.profile
        profile.rules[i].enabled.toggle()
        model.profile = profile
    }

    @objc private func editRules() {
        AppDelegate.showMainWindow()
        model.section = .rules
    }

    @objc private func openMain() {
        AppDelegate.showMainWindow()
    }

    @objc private func quit() {
        NSApp.terminate(nil)
    }
}

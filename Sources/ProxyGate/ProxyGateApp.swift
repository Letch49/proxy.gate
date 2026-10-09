import AppKit
import PGCore
import SwiftUI

@main
struct ProxyGateApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    private let model = AppModel.shared

    var body: some Scene {
        Window("ProxyGate", id: "main") {
            MainView()
                .environment(model)
                .frame(minWidth: 1000, minHeight: 620)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1280, height: 800)
        .commands {
            CommandGroup(after: .appInfo) {
                Button(model.isRunning ? "Stop Redirection" : "Start Redirection") { model.toggle() }
                    .keyboardShortcut("r")
            }
            CommandMenu("View") {
                ForEach(Array(AppSection.allCases.enumerated()), id: \.element) { index, section in
                    Button(LocalizedStringKey(section.rawValue)) { model.section = section }
                        .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
                }
                Divider()
                Button("Manage Profiles…") { model.sheet = .profiles }
            }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Set by MainView; reopens the SwiftUI window after it was closed.
    @MainActor static var openMainWindowAction: (() -> Void)?
    @MainActor private var statusItem: StatusItemController?

    @MainActor
    static func showMainWindow() {
        NSApp.activate(ignoringOtherApps: true)
        if let window = NSApp.windows.first(where: { $0.identifier?.rawValue.hasPrefix("main") == true && $0.canBecomeMain }) {
            window.makeKeyAndOrderFront(nil)
        } else {
            openMainWindowAction?()
        }
    }

    @MainActor
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.applicationIconImage = GateIcon.appIcon(size: 512)
        statusItem = StatusItemController(model: AppModel.shared)
        NSApp.activate(ignoringOtherApps: true)
    }

    /// Keeps running in the menu bar after the window is closed.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Dock icon click / `open` while running: bring the window back.
    @MainActor
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            AppDelegate.showMainWindow()
        }
        return true
    }
}

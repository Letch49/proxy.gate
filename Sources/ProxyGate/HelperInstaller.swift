import Foundation
import PGCore

/// Installs the engine as a LaunchDaemon (one administrator prompt).
enum HelperInstaller {
    static var isInstalled: Bool {
        FileManager.default.fileExists(atPath: PGConstants.helperPlistPath)
    }

    /// The engine binary shipped inside the app bundle (or next to the app binary in dev builds).
    static var bundledEngine: URL? {
        if let url = Bundle.main.url(forResource: "proxygate-engine", withExtension: nil) {
            return url
        }
        let sibling = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("proxygate-engine")
        return sibling.flatMap { FileManager.default.isExecutableFile(atPath: $0.path) ? $0 : nil }
    }

    static func install() throws {
        guard let engine = bundledEngine else {
            throw NetError("proxygate-engine binary not found in the app bundle")
        }
        let label = PGConstants.helperLabel
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(PGConstants.helperPath)</string>
                <string>--allow-uid</string>
                <string>\(getuid())</string>
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>StandardErrorPath</key><string>\(PGConstants.helperLogPath)</string>
        </dict>
        </plist>
        """
        let script = """
        set -e
        launchctl bootout system/\(label) 2>/dev/null || true
        mkdir -p /Library/PrivilegedHelperTools
        cp \(shellQuote(engine.path)) \(PGConstants.helperPath)
        chown root:wheel \(PGConstants.helperPath)
        chmod 755 \(PGConstants.helperPath)
        cat > \(PGConstants.helperPlistPath) <<'PLIST'
        \(plist)
        PLIST
        chown root:wheel \(PGConstants.helperPlistPath)
        chmod 644 \(PGConstants.helperPlistPath)
        launchctl bootstrap system \(PGConstants.helperPlistPath)
        """
        try runPrivileged(script)
    }

    static func uninstall() throws {
        let script = """
        launchctl bootout system/\(PGConstants.helperLabel) 2>/dev/null || true
        /sbin/pfctl -a \(PFRules.anchor) -F rules 2>/dev/null || true
        /sbin/pfctl -a \(PFRules.anchor) -F nat 2>/dev/null || true
        rm -f \(PGConstants.helperPlistPath) \(PGConstants.helperPath) \(PGConstants.socketPath)
        """
        try runPrivileged(script)
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private static func runPrivileged(_ script: String) throws {
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-\(UUID().uuidString).sh")
        try script.write(to: file, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: file) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        process.arguments = [
            "-e", "on run argv",
            "-e", "do shell script \"/bin/sh \" & quoted form of (item 1 of argv) with administrator privileges",
            "-e", "end run",
            file.path,
        ]
        let errors = Pipe()
        process.standardError = errors
        process.standardOutput = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            let message = String(decoding: errors.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            if message.contains("-128") {
                throw NetError("Cancelled")
            }
            throw NetError(message.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}

import Foundation
import PGCore
import Security

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

    /// The running app's own cdhash (lowercase hex), pinned into the helper so only this build can
    /// drive it. nil if the app is unsigned, then the helper falls back to uid-only auth.
    static let ownCDHash: String? = {
        var code: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, SecCSFlags(), &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(), &info) == errSecSuccess,
              let dict = info as? [String: Any],
              let unique = dict[kSecCodeInfoUnique as String] as? Data else { return nil }
        return CDHash.hex(unique)
    }()

    /// The cdhashes the installed helper pins (its plist is world readable).
    static var pinnedCDHashes: Set<String> {
        guard let data = FileManager.default.contents(atPath: PGConstants.helperPlistPath),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let args = plist["ProgramArguments"] as? [String] else { return [] }
        return CDHash.pinned(in: args)
    }

    /// Installed, but pinned to another app build (app updated without an engine version bump),
    /// so the helper would refuse this app.
    static var needsReinstall: Bool {
        guard isInstalled else { return false }
        return pinnedCDHashes != Set([ownCDHash].compactMap { $0 })
    }

    static func install() throws {
        guard let engine = bundledEngine else {
            throw NetError("proxygate-engine binary not found in the app bundle")
        }
        let label = PGConstants.helperLabel
        var arguments = [PGConstants.helperPath, "--allow-uid", String(getuid())]
        if let hash = ownCDHash {
            arguments += [CDHash.argument, hash]
        }
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": arguments,
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardErrorPath": PGConstants.helperLogPath,
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)

        let dir = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        let plistFile = dir.appendingPathComponent("helper.plist")
        try writePrivate(plistData, to: plistFile)

        let script = """
        set -e
        launchctl bootout system/\(label) 2>/dev/null || true
        mkdir -p /Library/PrivilegedHelperTools
        cp \(shellQuote(engine.path)) \(PGConstants.helperPath)
        chown root:wheel \(PGConstants.helperPath)
        chmod 755 \(PGConstants.helperPath)
        cp \(shellQuote(plistFile.path)) \(PGConstants.helperPlistPath)
        chown root:wheel \(PGConstants.helperPlistPath)
        chmod 644 \(PGConstants.helperPlistPath)
        launchctl bootstrap system \(PGConstants.helperPlistPath)
        """
        try runPrivileged(script, in: dir)
    }

    static func uninstall() throws {
        let script = """
        launchctl bootout system/\(PGConstants.helperLabel) 2>/dev/null || true
        /sbin/pfctl -a \(PFRules.anchor) -F rules 2>/dev/null || true
        /sbin/pfctl -a \(PFRules.anchor) -F nat 2>/dev/null || true
        rm -f \(PGConstants.helperPlistPath) \(PGConstants.helperPath) \(PGConstants.socketPath)
        """
        let dir = try makePrivateDirectory()
        defer { try? FileManager.default.removeItem(at: dir) }
        try runPrivileged(script, in: dir)
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// A fresh directory only this user can enter, so other users cannot swap the script or plist
    /// before the administrator prompt runs them as root. A process of this same user still can
    /// (open item: move to SMAppService).
    private static func makePrivateDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        return dir
    }

    private static func writePrivate(_ data: Data, to file: URL) throws {
        guard FileManager.default.createFile(atPath: file.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw NetError("Cannot write \(file.lastPathComponent)")
        }
    }

    private static func runPrivileged(_ script: String, in dir: URL) throws {
        let file = dir.appendingPathComponent("install.sh")
        try writePrivate(Data(script.utf8), to: file)

        let result = Shell.run("/usr/bin/osascript", [
            "-e", "on run argv",
            "-e", "do shell script \"/bin/sh \" & quoted form of (item 1 of argv) with administrator privileges",
            "-e", "end run",
            file.path,
        ])
        guard result.status == 0 else {
            if result.output.contains("-128") {
                throw NetError("Cancelled")
            }
            throw NetError(result.output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
    }
}

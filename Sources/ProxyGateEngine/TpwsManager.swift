import CryptoKit
import Darwin
import Foundation
import PGCore

/// Manages the tpws DPI-bypass core (from the zapret project). Runs it as a local SOCKS proxy under
/// the shared `_proxygate` service account — so pf passes its outbound (same loop-prevention as Xray)
/// — with the chosen desync strategy on its command line. No config file: strategy = argv flags.
final class TpwsManager: @unchecked Sendable {
    private let lock = NSLock()
    private var lastError: String?
    private var currentStrategy: [String]?

    var installedVersion: String? {
        guard FileManager.default.isExecutableFile(atPath: PGConstants.tpwsPath),
              let v = try? String(contentsOfFile: PGConstants.tpwsVersionPath, encoding: .utf8) else { return nil }
        let trimmed = v.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var running: Bool { LaunchdJob.running(PGConstants.tpwsLabel) }

    var error: String? { lock.withLock { lastError } }

    /// Verifies the tpws binary the app downloaded, then installs it into the support dir.
    func install(from path: String, version: String, sha256 expected: String) throws {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw NetError("downloaded tpws not found at \(path)")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual.caseInsensitiveCompare(expected) == .orderedSame else {
            throw NetError("tpws checksum mismatch")
        }
        try FileManager.default.createDirectory(atPath: PGConstants.supportDir, withIntermediateDirectories: true)
        let tmp = PGConstants.tpwsPath + ".new"
        try? FileManager.default.removeItem(atPath: tmp)
        try data.write(to: URL(fileURLWithPath: tmp))
        _ = ServiceUser.shell("/usr/bin/xattr", ["-d", "com.apple.quarantine", tmp])
        _ = ServiceUser.shell("/bin/chmod", ["755", tmp])
        _ = ServiceUser.shell("/usr/sbin/chown", ["root:wheel", tmp])
        _ = try? FileManager.default.removeItem(atPath: PGConstants.tpwsPath)
        try FileManager.default.moveItem(atPath: tmp, toPath: PGConstants.tpwsPath)
        try version.write(toFile: PGConstants.tpwsVersionPath, atomically: true, encoding: .utf8)
    }

    /// Runs tpws with `strategy` flags, or stops it when nil. Returns whether it is up.
    @discardableResult
    func apply(strategy: [String]?) -> Bool {
        lock.withLock { lastError = nil }
        guard let strategy else { stop(); return false }
        guard Self.validStrategy(strategy) else {
            lock.withLock { lastError = "rejected unsafe tpws strategy" }
            return false
        }
        guard installedVersion != nil else {
            lock.withLock { lastError = "tpws is not installed" }
            return false
        }
        let unchanged = lock.withLock { currentStrategy == strategy } && running
        if unchanged { return true }
        do {
            try launch(strategy: strategy)
            lock.withLock { currentStrategy = strategy }
            return true
        } catch {
            lock.withLock { lastError = "\(error)"; currentStrategy = nil }
            FileHandle.standardError.write(Data("[tpws] failed to start: \(error)\n".utf8))
            return false
        }
    }

    func stop() {
        LaunchdJob.bootout(PGConstants.tpwsLabel)
        try? FileManager.default.removeItem(atPath: PGConstants.tpwsPlistPath)
        lock.withLock { currentStrategy = nil }
    }

    // MARK: - Auto-tune

    /// Runs a throwaway tpws with `flags` and checks whether a blocked host becomes reachable through
    /// it. Runs as _proxygate (pf passes its outbound) and curls over loopback, so it works even
    /// while interception is on.
    func probe(flags: [String], host: String) -> Bool {
        guard installedVersion != nil else { return false }
        let label = PGConstants.tpwsLabel + "-probe"
        let port = PGConstants.tpwsSocksPort + 1
        let plistPath = PGConstants.tpwsPlistPath.replacingOccurrences(of: ".plist", with: "-probe.plist")
        let logPath = PGConstants.tpwsLogPath.replacingOccurrences(of: ".log", with: "-probe.log")
        guard Self.validStrategy(flags) else { return false }
        LaunchdJob.bootout(label)
        defer { LaunchdJob.bootout(label); try? FileManager.default.removeItem(atPath: plistPath) }
        guard (try? LaunchdJob.writePlist([
            "Label": label,
            "UserName": ServiceUser.name,
            "GroupName": ServiceUser.name,
            "ProgramArguments": [PGConstants.tpwsPath, "--socks", "--port=\(port)"] + flags,
            "RunAtLoad": true,
            "StandardErrorPath": logPath,
            "StandardOutPath": logPath,
        ], to: plistPath)) != nil else { return false }
        LaunchdJob.prepareLog(logPath)
        guard ServiceUser.shell("/bin/launchctl", ["bootstrap", "system", plistPath]).status == 0 else { return false }
        for _ in 0..<15 {
            usleep(200_000)
            if LaunchdJob.running(label) { break }
        }
        let r = ServiceUser.shell("/usr/bin/curl", [
            "-x", "socks5h://127.0.0.1:\(port)", "--max-time", "5", "-o", "/dev/null",
            "-s", "-w", "%{http_code}", "https://\(host)/",
        ])
        let code = Int(r.output.trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
        return (200..<400).contains(code)
    }

    /// Strategy flags the engine will accept — a strict allowlist so a hostile client can't smuggle
    /// anything else onto the tpws command line (defence in depth on top of safe plist building).
    static func validStrategy(_ flags: [String]) -> Bool {
        let re = try? NSRegularExpression(pattern: "^--[a-z][a-z0-9-]*(=[A-Za-z0-9,.:_+-]*)?$")
        return flags.allSatisfy { f in
            guard let re else { return false }
            return re.firstMatch(in: f, range: NSRange(f.startIndex..., in: f)) != nil
        }
    }

    private func launch(strategy: [String]) throws {
        try LaunchdJob.writePlist([
            "Label": PGConstants.tpwsLabel,
            "UserName": ServiceUser.name,
            "GroupName": ServiceUser.name,
            "ProgramArguments": [PGConstants.tpwsPath, "--socks", "--port=\(PGConstants.tpwsSocksPort)"] + strategy,
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Interactive",
            "StandardErrorPath": PGConstants.tpwsLogPath,
            "StandardOutPath": PGConstants.tpwsLogPath,
        ], to: PGConstants.tpwsPlistPath)
        LaunchdJob.prepareLog(PGConstants.tpwsLogPath)
        try LaunchdJob.bootstrap(label: PGConstants.tpwsLabel, plistPath: PGConstants.tpwsPlistPath, logPath: PGConstants.tpwsLogPath)
    }
}

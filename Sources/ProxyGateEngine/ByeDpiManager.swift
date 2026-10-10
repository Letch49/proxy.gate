import CryptoKit
import Darwin
import Foundation
import PGCore

/// Manages the ByeDPI (ciadpi) core: a local SOCKS proxy that desyncs the ClientHello (split,
/// disorder, oob, TLS-record split; the macOS build has no fake packets). Runs under the shared
/// `_proxygate` service account (pf passes its outbound, same loop-prevention as tpws/Xray). Flags
/// are ciadpi's own `-s/-d/-o/-q/-r` options; no config file.
final class ByeDpiManager: @unchecked Sendable {
    private let lock = NSLock()
    private var lastError: String?
    private var currentStrategy: [String]?

    var installedVersion: String? {
        guard FileManager.default.isExecutableFile(atPath: PGConstants.byedpiPath),
              let v = try? String(contentsOfFile: PGConstants.byedpiVersionPath, encoding: .utf8) else { return nil }
        let trimmed = v.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var running: Bool { LaunchdJob.running(PGConstants.byedpiLabel) }

    var error: String? { lock.withLock { lastError } }

    /// Verifies the ciadpi binary the app downloaded, then installs it into the support dir.
    func install(from path: String, version: String, sha256 expected: String) throws {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw NetError("downloaded ByeDPI not found at \(path)")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual.caseInsensitiveCompare(expected) == .orderedSame else {
            throw NetError("ByeDPI checksum mismatch")
        }
        try FileManager.default.createDirectory(atPath: PGConstants.supportDir, withIntermediateDirectories: true)
        let tmp = PGConstants.byedpiPath + ".new"
        try? FileManager.default.removeItem(atPath: tmp)
        try data.write(to: URL(fileURLWithPath: tmp))
        _ = ServiceUser.shell("/usr/bin/xattr", ["-d", "com.apple.quarantine", tmp])
        _ = ServiceUser.shell("/bin/chmod", ["755", tmp])
        _ = ServiceUser.shell("/usr/sbin/chown", ["root:wheel", tmp])
        _ = try? FileManager.default.removeItem(atPath: PGConstants.byedpiPath)
        try FileManager.default.moveItem(atPath: tmp, toPath: PGConstants.byedpiPath)
        try version.write(toFile: PGConstants.byedpiVersionPath, atomically: true, encoding: .utf8)
    }

    /// Runs ciadpi with `strategy` flags, or stops it when nil. Returns whether it is up.
    @discardableResult
    func apply(strategy: [String]?) -> Bool {
        lock.withLock { lastError = nil }
        guard let strategy else { stop(); return false }
        guard ByeDpiStrategies.valid(strategy) else {
            lock.withLock { lastError = "rejected unsafe ByeDPI strategy" }
            return false
        }
        guard installedVersion != nil else {
            lock.withLock { lastError = "ByeDPI is not installed" }
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
            FileHandle.standardError.write(Data("[byedpi] failed to start: \(error)\n".utf8))
            return false
        }
    }

    func stop() {
        LaunchdJob.bootout(PGConstants.byedpiLabel)
        try? FileManager.default.removeItem(atPath: PGConstants.byedpiPlistPath)
        lock.withLock { currentStrategy = nil }
    }

    /// ciadpi command line for a SOCKS listener on loopback only.
    static func arguments(port: UInt16, flags: [String]) -> [String] {
        [PGConstants.byedpiPath, "-i", "127.0.0.1", "-p", "\(port)"] + flags
    }

    private func launch(strategy: [String]) throws {
        try LaunchdJob.writePlist([
            "Label": PGConstants.byedpiLabel,
            "UserName": ServiceUser.name,
            "GroupName": ServiceUser.name,
            "ProgramArguments": Self.arguments(port: PGConstants.byedpiSocksPort, flags: strategy),
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Interactive",
            "StandardErrorPath": PGConstants.byedpiLogPath,
            "StandardOutPath": PGConstants.byedpiLogPath,
        ], to: PGConstants.byedpiPlistPath)
        LaunchdJob.prepareLog(PGConstants.byedpiLogPath)
        try LaunchdJob.bootstrap(label: PGConstants.byedpiLabel, plistPath: PGConstants.byedpiPlistPath, logPath: PGConstants.byedpiLogPath)
    }
}

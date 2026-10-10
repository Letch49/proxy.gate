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

    /// tpws command line for a SOCKS listener on loopback only (without --bind-addr tpws listens on
    /// every interface, an open proxy for the LAN).
    static func arguments(port: UInt16, flags: [String]) -> [String] {
        [PGConstants.tpwsPath, "--socks", "--bind-addr=127.0.0.1", "--port=\(port)"] + flags
    }

    /// Asks the installed tpws whether it accepts these flags (`--dry-run`), so a version mismatch
    /// shows up as a launch error with tpws's own message instead of a silent failed probe.
    func dryRun(_ flags: [String]) -> String? {
        let r = Shell.run(PGConstants.tpwsPath, ["--socks", "--port=1", "--dry-run"] + flags)
        if r.status == 0 { return nil }
        let tail = r.output.split(separator: "\n").suffix(2).joined(separator: " ")
        return tail.isEmpty ? "tpws rejected the flags (exit \(r.status))" : String(tail)
    }

    /// Desync options a strategy may carry. A strict name allowlist, so a hostile client cannot
    /// smuggle --bind-addr (open proxy), --hostlist/--ipset (read files), --debug=@file (write files)
    /// or --user onto the tpws command line; values are shape-checked as well.
    static let allowedOptions: Set<String> = [
        "split-pos", "split-any-protocol", "split-tls", "split-http-req", "disorder", "oob", "oob-data",
        "hostcase", "hostspell", "hostdot", "hosttab", "hostnospace", "hostpad", "domcase",
        "methodspace", "methodeol", "unixeol", "tlsrec", "tamper-start", "tamper-cutoff", "mss",
    ]

    static func validStrategy(_ flags: [String]) -> Bool {
        let re = try? NSRegularExpression(pattern: "^--([a-z][a-z0-9-]*)(=[A-Za-z0-9,.:_+-]*)?$")
        guard flags.count <= 16 else { return false }
        return flags.allSatisfy { f in
            guard let re, let m = re.firstMatch(in: f, range: NSRange(f.startIndex..., in: f)),
                  let name = Range(m.range(at: 1), in: f) else { return false }
            return allowedOptions.contains(String(f[name]))
        }
    }

    private func launch(strategy: [String]) throws {
        try LaunchdJob.writePlist([
            "Label": PGConstants.tpwsLabel,
            "UserName": ServiceUser.name,
            "GroupName": ServiceUser.name,
            "ProgramArguments": Self.arguments(port: PGConstants.tpwsSocksPort, flags: strategy),
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

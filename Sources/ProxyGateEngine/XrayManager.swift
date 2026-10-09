import CryptoKit
import Darwin
import Foundation
import PGCore

/// Manages the Xray core on behalf of the root engine: installs the binary the app downloaded,
/// and runs it as an unprivileged LaunchDaemon (`UserName=nobody`) so launchd drops privileges,
/// restarts it and captures its log. Running as a known uid also lets pf tell the core's own
/// outbound apart and leave it untouched (see PFRules, `xrayUID`).
final class XrayManager: @unchecked Sendable {
    private let lock = NSLock()
    private var lastError: String?
    private var configHash: String?

    /// uid the core runs as (shared with tpws), creating the account on first use.
    func serviceUID() -> UInt32 { ServiceUser.uid() }
    private var runGID: gid_t { ServiceUser.gid }

    var installedVersion: String? {
        guard FileManager.default.isExecutableFile(atPath: PGConstants.xrayPath),
              let v = try? String(contentsOfFile: PGConstants.xrayVersionPath, encoding: .utf8) else { return nil }
        let trimmed = v.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    var running: Bool { LaunchdJob.running(PGConstants.xrayLabel) }

    var error: String? { lock.withLock { lastError } }

    // MARK: - Install

    /// Verifies `sha256` of the release zip the app downloaded, then installs the core binary and
    /// its geoip/geosite databases (the provider's routing references them) into the support dir.
    func install(fromZip path: String, version: String, sha256 expected: String) throws {
        guard let data = FileManager.default.contents(atPath: path) else {
            throw NetError("downloaded Xray archive not found at \(path)")
        }
        let actual = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        guard actual.caseInsensitiveCompare(expected) == .orderedSame else {
            throw NetError("Xray archive checksum mismatch (expected \(expected.prefix(12))…, got \(actual.prefix(12))…)")
        }
        try FileManager.default.createDirectory(atPath: PGConstants.supportDir, withIntermediateDirectories: true)
        _ = Shell.run("/bin/chmod", ["755", PGConstants.supportDir])
        let unzip = Shell.run("/usr/bin/unzip", ["-o", path, "xray", "-d", PGConstants.supportDir])
        guard unzip.status == 0, FileManager.default.fileExists(atPath: PGConstants.xrayPath) else {
            throw NetError("could not extract the Xray core: \(unzip.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        // geoip/geosite power the provider's routing; best-effort so a naming change can't block install.
        _ = Shell.run("/usr/bin/unzip", ["-o", path, "geoip.dat", "geosite.dat", "-d", PGConstants.supportDir])
        // Downloaded files carry a quarantine xattr that would stop launchd from running them.
        _ = Shell.run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", PGConstants.supportDir])
        _ = Shell.run("/bin/chmod", ["755", PGConstants.xrayPath])
        _ = Shell.run("/usr/sbin/chown", ["-R", "root:wheel", PGConstants.supportDir])
        try version.write(toFile: PGConstants.xrayVersionPath, atomically: true, encoding: .utf8)
    }

    // MARK: - Run

    /// Writes `json` and (re)starts the core; nil stops it. Returns whether the core is meant to run.
    @discardableResult
    func apply(config json: String?) -> Bool {
        lock.withLock { lastError = nil }
        guard let json, !json.isEmpty else {
            stop()
            return false
        }
        guard installedVersion != nil else {
            lock.withLock { lastError = "Xray core is not installed" }
            return false
        }
        let hash = SHA256.hash(data: Data(json.utf8)).map { String(format: "%02x", $0) }.joined()
        let unchanged = lock.withLock { configHash == hash } && running
        if unchanged { return true }
        do {
            try writeConfig(json)
            try launch()
            lock.withLock { configHash = hash }
            return true
        } catch {
            lock.withLock { lastError = "\(error)"; configHash = nil }
            log("Xray core failed to start: \(error)")
            return false
        }
    }

    func stop() {
        LaunchdJob.bootout(PGConstants.xrayLabel)
        try? FileManager.default.removeItem(atPath: PGConstants.xrayPlistPath)
        try? FileManager.default.removeItem(atPath: PGConstants.xrayConfigPath)
        lock.withLock { configHash = nil }
    }

    private func writeConfig(_ json: String) throws {
        try json.write(toFile: PGConstants.xrayConfigPath, atomically: true, encoding: .utf8)
        // The config holds the VLESS UUID: readable by root and the nobody group only.
        _ = Shell.run("/usr/sbin/chown", ["root:\(runGID)", PGConstants.xrayConfigPath])
        _ = Shell.run("/bin/chmod", ["640", PGConstants.xrayConfigPath])
    }

    private func launch() throws {
        try LaunchdJob.writePlist([
            "Label": PGConstants.xrayLabel,
            "UserName": ServiceUser.name,
            "GroupName": ServiceUser.name,
            "ProgramArguments": [PGConstants.xrayPath, "run", "-c", PGConstants.xrayConfigPath],
            "RunAtLoad": true,
            "KeepAlive": true,
            "ProcessType": "Interactive",
            "EnvironmentVariables": ["XRAY_LOCATION_ASSET": PGConstants.supportDir],
            "StandardErrorPath": PGConstants.xrayLogPath,
            "StandardOutPath": PGConstants.xrayLogPath,
        ], to: PGConstants.xrayPlistPath)
        LaunchdJob.prepareLog(PGConstants.xrayLogPath)
        try LaunchdJob.bootstrap(label: PGConstants.xrayLabel, plistPath: PGConstants.xrayPlistPath, logPath: PGConstants.xrayLogPath)
    }

    // MARK: - Helpers

    private func log(_ text: String) {
        FileHandle.standardError.write(Data("[xray] \(text)\n".utf8))
    }

}

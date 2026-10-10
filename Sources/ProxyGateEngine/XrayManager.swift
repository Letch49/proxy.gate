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

    /// Installs the core binary and its geoip/geosite databases (the provider's routing references
    /// them) from the release zip the app downloaded. The client only names the file: the engine
    /// stages a copy, checks it against the release `.dgst` it fetches itself for `version`, and
    /// unzips only that copy.
    func install(fromZip path: String, version: String) throws {
        guard let dgstURL = CoreReleases.xrayChecksumURL(tag: version, arm64: CoreReleases.isAppleSilicon) else {
            throw NetError("rejected Xray version tag")
        }
        let dir = try CoreInstall.makeStagingDir()
        defer { CoreInstall.remove(dir) }
        let staged = try CoreInstall.stage(path, in: dir, name: "xray.zip")
        let dgst = try CoreInstall.fetchText(dgstURL)
        guard let expected = CoreReleases.parseDgst(dgst) else {
            throw NetError("no SHA2-256 in the Xray release checksum file")
        }
        guard staged.sha256 == expected else { throw NetError("Xray archive checksum mismatch") }

        let out = dir + "/out"
        try CoreInstall.makeDir(out)
        let unzip = Shell.run("/usr/bin/unzip", ["-qq", "-o", staged.path, "xray", "-d", out])
        guard unzip.status == 0 else {
            throw NetError("could not extract the Xray core: \(unzip.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        // geoip/geosite power the provider's routing; best-effort so a naming change can't block install.
        _ = Shell.run("/usr/bin/unzip", ["-qq", "-o", staged.path, "geoip.dat", "geosite.dat", "-d", out])
        for name in ["geoip.dat", "geosite.dat"] {
            try? CoreInstall.place(out + "/" + name, at: PGConstants.supportDir + "/" + name, mode: 0o644)
        }
        try CoreInstall.place(out + "/xray", at: PGConstants.xrayPath, mode: 0o755)
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

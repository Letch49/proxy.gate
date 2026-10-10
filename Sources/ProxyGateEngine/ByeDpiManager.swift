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

    /// Installs ciadpi from the release tarball the app downloaded. The client only names the file:
    /// the engine stages a copy, checks it against the hash pinned in `CoreReleases` for `version`
    /// and this Mac's architecture, and extracts the one expected member itself.
    func install(fromTarball path: String, version: String) throws {
        guard let build = CoreReleases.byedpiBuild(version: version, arm64: CoreReleases.isAppleSilicon) else {
            throw NetError("no pinned ByeDPI build for this version")
        }
        // The member is a constant from the table, but keep it a plain file name regardless.
        guard !build.member.isEmpty, !build.member.contains("/"), !build.member.hasPrefix("-"), build.member != ".." else {
            throw NetError("bad ByeDPI archive member")
        }
        let dir = try CoreInstall.makeStagingDir()
        defer { CoreInstall.remove(dir) }
        let staged = try CoreInstall.stage(path, in: dir, name: "byedpi.tar.gz")
        guard staged.sha256 == build.tarballSHA256.lowercased() else {
            throw NetError("ByeDPI archive does not match the pinned checksum")
        }
        let out = dir + "/out"
        try CoreInstall.makeDir(out)
        let tar = Shell.run("/usr/bin/tar", ["-x", "-z", "-f", staged.path, "-C", out, "--", build.member])
        guard tar.status == 0 else {
            throw NetError("could not extract ByeDPI: \(tar.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        // place() accepts only a regular file, so a link entry in the archive is refused.
        try CoreInstall.place(out + "/" + build.member, at: PGConstants.byedpiPath, mode: 0o755)
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

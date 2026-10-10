import Darwin
import Foundation
import PGCore

/// A throwaway DPI core used by the auto-tune: one launchd job per strategy on its own loopback
/// port, so the user's running core is never touched. Runs as the service user like the real core,
/// so pf passes its outbound and the probe goes straight out, never through VPN or a proxy.
final class DPIProbeSession {
    let engine: DPIEngine
    let flags: [String]
    private let label: String
    private let port: UInt16
    private let plistPath: String
    private let logPath: String

    /// Probe cores that may run at once. Each slot has its own label, port, plist and log; ports sit
    /// right above the core's own SOCKS port (tpws 52151-52154, ByeDPI 52161-52164).
    static let slots = 4

    init(engine: DPIEngine, flags: [String], slot: Int = 0) {
        self.engine = engine
        self.flags = flags
        let slot = max(0, min(slot, Self.slots - 1))
        let suffix = slot == 0 ? "-probe" : "-probe\(slot + 1)"
        switch engine {
        case .tpws:
            label = PGConstants.tpwsLabel + suffix
            port = PGConstants.tpwsSocksPort + 1 + UInt16(slot)
            plistPath = PGConstants.tpwsPlistPath.replacingOccurrences(of: ".plist", with: suffix + ".plist")
            logPath = PGConstants.tpwsLogPath.replacingOccurrences(of: ".log", with: suffix + ".log")
        case .byedpi:
            label = PGConstants.byedpiLabel + suffix
            port = PGConstants.byedpiSocksPort + 1 + UInt16(slot)
            plistPath = PGConstants.byedpiPlistPath.replacingOccurrences(of: ".plist", with: suffix + ".plist")
            logPath = PGConstants.byedpiLogPath.replacingOccurrences(of: ".log", with: suffix + ".log")
        }
    }

    /// Starts the core and waits until it really accepts connections. Returns the reason it did not
    /// start (validation, the core's own error output), nil on success.
    func start(dryRun: ([String]) -> String?) -> String? {
        let valid = engine == .tpws ? TpwsManager.validStrategy(flags) : ByeDpiStrategies.valid(flags)
        guard valid else { return "flags rejected by the allowlist" }
        if let err = dryRun(flags) { return err }
        let args = engine == .tpws ? TpwsManager.arguments(port: port, flags: flags)
                                   : ByeDpiManager.arguments(port: port, flags: flags)
        do {
            try LaunchdJob.writePlist([
                "Label": label,
                "UserName": ServiceUser.name,
                "GroupName": ServiceUser.name,
                "ProgramArguments": args,
                "RunAtLoad": true,
                "StandardErrorPath": logPath,
                "StandardOutPath": logPath,
            ], to: plistPath)
            LaunchdJob.prepareLog(logPath)
            _ = Shell.run("/usr/bin/truncate", ["-s", "0", logPath])
            try LaunchdJob.bootstrap(label: label, plistPath: plistPath, logPath: logPath)
        } catch {
            return "\(error)"
        }
        // "running" can be true for the instant before a core exits on a bad option; a listening
        // port is the real proof.
        for _ in 0..<15 {
            if listening() { return nil }
            usleep(200_000)
        }
        let tail = (try? String(contentsOfFile: logPath, encoding: .utf8))?
            .split(separator: "\n").suffix(3).joined(separator: " ") ?? ""
        return tail.isEmpty ? "\(engine.title) did not open its port" : tail
    }

    func stop() {
        LaunchdJob.bootout(label)
        try? FileManager.default.removeItem(atPath: plistPath)
    }

    private func listening() -> Bool {
        guard let s = try? TCPStream.connect(to: [SocketAddress(ip: IPAddr("127.0.0.1")!, port: port)], timeoutMs: 300) else {
            return false
        }
        s.close()
        return true
    }

    /// HTTPS GET of `host` through this core, dialing `ip` (curl --resolve keeps the name for SNI and
    /// the certificate check; plain socks5 makes the core get an IP, so it never resolves anything).
    func fetch(host: String, ip: IPAddr, timeoutSec: Int) -> CurlOutcome {
        DPIProbeSession.curl(host: host, ip: ip, timeoutSec: timeoutSec,
                             extra: ["-x", "socks5://127.0.0.1:\(port)"])
    }

    /// The same request with no core and no proxy, from a source port pf passes untouched: tells
    /// whether the host is blocked at all.
    static func fetchDirect(host: String, ip: IPAddr, timeoutSec: Int) -> CurlOutcome {
        curl(host: host, ip: ip, timeoutSec: timeoutSec,
             extra: ["--noproxy", "*", "--local-port", "\(PFRules.reservedPorts.lowerBound)-\(PFRules.reservedPorts.upperBound)"])
    }

    private static func curl(host: String, ip: IPAddr, timeoutSec: Int, extra: [String]) -> CurlOutcome {
        guard DNSName.isValid(host) else { return .other(-1) }
        let addr = ip.isV4 ? ip.description : "[\(ip)]"
        let r = Shell.run("/usr/bin/curl", extra + [
            "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_appconnect} %{time_total}",
            "--connect-timeout", "\(min(4, timeoutSec))", "--max-time", "\(timeoutSec)",
            "--resolve", "\(host):443:\(addr)", "--", "https://\(host)/",
        ])
        return CurlOutcome.classify(exitCode: r.status, output: r.output)
    }
}

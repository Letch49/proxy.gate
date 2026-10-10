import Foundation

public enum PGConstants {
    public static let version = "0.9.13"
    /// Engine sends counters and the app refreshes live data at this interval (seconds).
    public static let statsInterval: Double = 2
    public static let helperLabel = "com.proxygate.engine"
    public static let helperPath = "/Library/PrivilegedHelperTools/com.proxygate.engine"
    public static let helperPlistPath = "/Library/LaunchDaemons/com.proxygate.engine.plist"
    public static let helperLogPath = "/var/log/proxygate-engine.log"
    public static let socketPath = "/var/run/com.proxygate.engine.sock"

    /// Root-owned working directory for the engine (holds the Xray core and its config).
    public static let supportDir = "/Library/Application Support/ProxyGate"
    public static let xrayPath = supportDir + "/xray"
    public static let xrayVersionPath = supportDir + "/xray.version"
    public static let xrayConfigPath = supportDir + "/xray-config.json"
    public static let xrayLabel = "com.proxygate.xray"
    public static let xrayPlistPath = "/Library/LaunchDaemons/com.proxygate.xray.plist"
    public static let xrayLogPath = "/var/log/proxygate-xray.log"
    /// Loopback SOCKS port the Xray core exposes; the engine dials it as a normal proxy.
    public static let vpnSocksPort: UInt16 = 52140

    // The tpws DPI-bypass core (zapret). Runs as a local SOCKS proxy; direct routes go through it
    // when the DPI bypass is on, so our relay never sees the DPI-mangled packets.
    public static let tpwsPath = supportDir + "/tpws"
    public static let tpwsVersionPath = supportDir + "/tpws.version"
    public static let tpwsLabel = "com.proxygate.tpws"
    public static let tpwsPlistPath = "/Library/LaunchDaemons/com.proxygate.tpws.plist"
    public static let tpwsLogPath = "/var/log/proxygate-tpws.log"
    public static let tpwsSocksPort: UInt16 = 52150
    // ByeDPI (ciadpi), the second DPI-bypass engine: another set of split/disorder/oob/tls-record
    // desyncs. Its macOS build has no fake packets.
    public static let byedpiPath = supportDir + "/ciadpi"
    public static let byedpiVersionPath = supportDir + "/ciadpi.version"
    public static let byedpiLabel = "com.proxygate.byedpi"
    public static let byedpiPlistPath = "/Library/LaunchDaemons/com.proxygate.byedpi.plist"
    public static let byedpiLogPath = "/var/log/proxygate-byedpi.log"
    public static let byedpiSocksPort: UInt16 = 52160
    /// Loopback UDP port of the engine's DNS stub; /etc/resolver files point the chosen domains here.
    public static let dnsStubPort: UInt16 = 52153
}

public enum RouteKind: String, Codable, Sendable {
    case direct, proxy, chain, block
}

public struct EngineStatus: Codable, Sendable {
    public var version: String
    public var running: Bool
    public var error: String?
    public var listenPort: UInt16
    /// Installed Xray core version, nil when the core is not installed.
    public var xrayVersion: String?
    /// Whether the Xray core process is up right now.
    public var xrayRunning: Bool
    public var xrayError: String?
    /// Installed tpws (DPI-bypass) core version, nil when not installed.
    public var tpwsVersion: String?
    public var tpwsRunning: Bool
    public var tpwsError: String?
    /// Installed ByeDPI (ciadpi) core version, nil when not installed.
    public var byedpiVersion: String?
    public var byedpiRunning: Bool
    public var byedpiError: String?
    public var anyConnect = AnyConnectState()
    /// App-facing DNS: resolver files + local stub.
    public var dns = SystemDNSState()

    public init(version: String, running: Bool, error: String?, listenPort: UInt16,
                xrayVersion: String? = nil, xrayRunning: Bool = false, xrayError: String? = nil,
                tpwsVersion: String? = nil, tpwsRunning: Bool = false, tpwsError: String? = nil,
                byedpiVersion: String? = nil, byedpiRunning: Bool = false, byedpiError: String? = nil,
                anyConnect: AnyConnectState = AnyConnectState(), dns: SystemDNSState = SystemDNSState()) {
        self.version = version
        self.running = running
        self.error = error
        self.listenPort = listenPort
        self.xrayVersion = xrayVersion
        self.xrayRunning = xrayRunning
        self.xrayError = xrayError
        self.tpwsVersion = tpwsVersion
        self.tpwsRunning = tpwsRunning
        self.tpwsError = tpwsError
        self.byedpiVersion = byedpiVersion
        self.byedpiRunning = byedpiRunning
        self.byedpiError = byedpiError
        self.anyConnect = anyConnect
        self.dns = dns
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        running = try c.decode(Bool.self, forKey: .running)
        error = try c.decodeIfPresent(String.self, forKey: .error)
        listenPort = try c.decode(UInt16.self, forKey: .listenPort)
        xrayVersion = try c.decodeIfPresent(String.self, forKey: .xrayVersion)
        xrayRunning = try c.decodeIfPresent(Bool.self, forKey: .xrayRunning) ?? false
        xrayError = try c.decodeIfPresent(String.self, forKey: .xrayError)
        tpwsVersion = try c.decodeIfPresent(String.self, forKey: .tpwsVersion)
        tpwsRunning = try c.decodeIfPresent(Bool.self, forKey: .tpwsRunning) ?? false
        tpwsError = try c.decodeIfPresent(String.self, forKey: .tpwsError)
        byedpiVersion = try c.decodeIfPresent(String.self, forKey: .byedpiVersion)
        byedpiRunning = try c.decodeIfPresent(Bool.self, forKey: .byedpiRunning) ?? false
        byedpiError = try c.decodeIfPresent(String.self, forKey: .byedpiError)
        anyConnect = try c.decodeIfPresent(AnyConnectState.self, forKey: .anyConnect) ?? AnyConnectState()
        dns = try c.decodeIfPresent(SystemDNSState.self, forKey: .dns) ?? SystemDNSState()
    }
}

public struct ConnInfo: Codable, Sendable {
    public var id: UInt64
    public var app: AppIdentity
    /// "host:port" (hostname when sniffed, IP otherwise).
    public var target: String
    public var ip: String
    public var port: UInt16
    public var rule: String
    /// "192.0.2.10:3128 HTTPS", "Direct", "Chain X".
    public var route: String
    public var kind: RouteKind
    public var time: Double

    public init(id: UInt64, app: AppIdentity, target: String, ip: String, port: UInt16, rule: String, route: String, kind: RouteKind, time: Double) {
        self.id = id
        self.app = app
        self.target = target
        self.ip = ip
        self.port = port
        self.rule = rule
        self.route = route
        self.kind = kind
        self.time = time
    }
}

public struct ConnClosed: Codable, Sendable {
    public var id: UInt64
    public var sent: UInt64
    public var received: UInt64
    public var time: Double

    public init(id: UInt64, sent: UInt64, received: UInt64, time: Double) {
        self.id = id
        self.sent = sent
        self.received = received
        self.time = time
    }
}

public struct ConnFailed: Codable, Sendable {
    public var info: ConnInfo
    public var error: String

    public init(info: ConnInfo, error: String) {
        self.info = info
        self.error = error
    }
}

public struct ConnBytes: Codable, Sendable {
    public var id: UInt64
    public var sent: UInt64
    public var received: UInt64

    public init(id: UInt64, sent: UInt64, received: UInt64) {
        self.id = id
        self.sent = sent
        self.received = received
    }
}

public struct LogEntry: Codable, Sendable {
    public enum Level: String, Codable, Sendable { case info, warning, error }

    public var level: Level
    public var text: String
    public var time: Double

    public init(level: Level, text: String, time: Double = Date().timeIntervalSince1970) {
        self.level = level
        self.text = text
        self.time = time
    }
}

/// One server to latency-test (a config's index within its subscription, and its endpoint).
public struct PingTarget: Codable, Sendable {
    public var index: Int
    public var host: String
    public var port: UInt16
    public init(index: Int, host: String, port: UInt16) {
        self.index = index
        self.host = host
        self.port = port
    }
}

/// State of the AnyConnect (openconnect) tunnel, reported by the engine.
public struct AnyConnectState: Codable, Sendable {
    public enum Phase: String, Codable, Sendable {
        case idle, authenticating, awaitingApproval, connecting, connected, error
    }
    public var phase: Phase = .idle
    public var server: String?
    /// Split-include subnets the concentrator pushed (go through the tunnel).
    public var routes: [String] = []
    public var message: String?

    public init(phase: Phase = .idle, server: String? = nil, routes: [String] = [], message: String? = nil) {
        self.phase = phase
        self.server = server
        self.routes = routes
        self.message = message
    }
}

/// Engine -> app.
public enum EngineMessage: Codable, Sendable {
    case status(EngineStatus)
    /// Latency in ms per config index (-1 = unreachable), for the given subscription.
    case pingResults(subscription: UUID, latencies: [Int: Int])
    /// Auto-tune finished: the winning engine + strategy (if any) and the per-host diagnosis.
    case bypassTuned(TuneReport)
    case tuneProgress(TuneProgress)
    /// Answer to `checkDNS`: how the system and the chosen provider resolve a name.
    case dnsChecked(DNSCheckReport)
    case opened(ConnInfo)
    case closed(ConnClosed)
    case failed(ConnFailed)
    case blocked(ConnInfo)
    /// Sent once per second with counters of connections that changed.
    case stats([ConnBytes])
    case log(LogEntry)
}

/// App -> engine.
public enum ClientCommand: Codable, Sendable {
    case hello(version: String)
    case config(Profile)
    case start
    case stop
    /// Install the Xray core from the release zip the app downloaded to `zipPath`. The engine copies
    /// it and checks the copy against the release checksum it fetches itself for the `version` tag.
    case installXray(zipPath: String, version: String)
    /// Full Xray JSON config to run, or nil to stop the core. The engine restarts
    /// the core process when the config changes.
    case xrayConfig(String?)
    /// The bridge that `.global` rules resolve to right now (chosen by the app from interface state).
    case activeBridge(Bridge)
    /// Measure TCP latency to these servers (the engine's probes bypass pf), reply with pingResults.
    case pingServers(subscription: UUID, targets: [PingTarget])
    /// Install the tpws binary the app extracted to `path`. The engine copies it and checks the copy
    /// against the release `sha256sum.txt` it fetches itself for the `version` tag.
    case installTpws(path: String, version: String)
    /// Run tpws with these strategy flags (e.g. "--split-pos=1 --disorder"), or nil to stop it.
    case tpwsStrategy([String]?)
    /// Install ByeDPI (ciadpi) from the release tarball the app downloaded to `tarballPath`. The
    /// engine checks it against the hash pinned in `CoreReleases` and extracts the binary itself.
    case installByedpi(tarballPath: String, version: String)
    /// Run ByeDPI with these ciadpi flags, or nil to stop it.
    case byedpiStrategy([String]?)
    /// Whether connections routed `.direct` should go through tpws (DPI bypass on).
    case bypassDirect(Bool)
    /// Resolve these known-blocked hosts, then try the DPI cores and strategies on them; replies
    /// with tuneProgress and a final bypassTuned.
    case tuneBypass(hosts: [String])
    case cancelTune
    /// Resolve `host` through the system and the profile's DNS provider; replies with dnsChecked.
    case checkDNS(host: String)
    /// Connect the AnyConnect tunnel (openconnect) to `server` as `user` (out-of-band 2FA approval).
    case anyConnectConnect(server: String, user: String, password: String)
    case anyConnectDisconnect
}

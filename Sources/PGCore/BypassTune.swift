import Foundation

/// Where a host's probe stopped, in the order the auto-tune checks them. Each stage is a different
/// fix for the user, so they are never folded into one "nothing worked".
public enum ProbeFailure: String, Codable, Sendable {
    case dnsNotFound        // every resolver said NXDOMAIN / no data
    case dnsTimeout         // no resolver answered
    case dnsFailed          // resolvers errored (refused, TLS, HTTP)
    case tcpFailed          // the IP does not accept TCP 443: an IP block, DPI cannot help
    case tlsTimeout         // TCP is up, the TLS handshake stalls (classic DPI)
    case tlsError           // the handshake was reset or broken
    case certError          // a certificate that does not match the name (wrong IP or interception)
    case engineFailed       // the DPI core did not start with these flags
    case noStrategy         // the core ran, no strategy got an HTTP answer
    case cancelled
}

/// Result of one curl run, from its exit code and `-w "%{http_code} %{time_appconnect} %{time_total}"`.
public enum CurlOutcome: Equatable, Sendable {
    case http(code: Int, ms: Int?)
    case connectFailed
    case proxyFailed
    case tlsTimeout
    case timeout
    case tlsError
    case certError
    case other(Int32)

    public static func classify(exitCode: Int32, output: String) -> CurlOutcome {
        let fields = output.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ")
        let code = fields.first.flatMap { Int($0) } ?? 0
        let appConnect = fields.count > 1 ? Double(fields[1]) ?? 0 : 0
        let total = fields.count > 2 ? Double(fields[2]) : nil
        if exitCode == 0, (100..<600).contains(code) {
            return .http(code: code, ms: total.map { Int($0 * 1000) })
        }
        switch exitCode {
        case 7: return .connectFailed
        case 97, 5: return .proxyFailed
        case 28: return appConnect > 0 ? .timeout : .tlsTimeout
        case 35, 56, 52: return .tlsError
        case 51, 58, 59, 60, 77, 83, 90, 91: return .certError
        default: return .other(exitCode)
        }
    }

    public var failure: ProbeFailure? {
        switch self {
        case .http: return nil
        case .connectFailed: return .tcpFailed
        case .proxyFailed, .tlsError, .other: return .tlsError
        case .tlsTimeout, .timeout: return .tlsTimeout
        case .certError: return .certError
        }
    }
}

/// One tested host in the auto-tune report.
public struct HostProbe: Codable, Sendable, Hashable {
    public var host: String
    /// Strategy index within `engine`'s list, -1 if none.
    public var strategyIndex: Int
    public var engine: DPIEngine?
    public var ok: Bool
    public var latencyMs: Int?
    /// The site already answers without any bypass: it does not need DPI bypass.
    public var directOK = false
    /// How apps resolve the host today (the system resolver, which includes our resolver files).
    public var systemDNS: DNSOutcome?
    /// The resolver whose address the probes used, e.g. "System" or "Google (DoH)".
    public var dnsSource: String?
    public var address: String?
    public var failure: ProbeFailure?
    public var detail: String?

    public init(host: String, strategyIndex: Int = -1, engine: DPIEngine? = nil, ok: Bool = false, latencyMs: Int? = nil) {
        self.host = host
        self.strategyIndex = strategyIndex
        self.engine = engine
        self.ok = ok
        self.latencyMs = latencyMs
    }

    /// Apps cannot resolve this host now, even if the probe found an address elsewhere.
    public var appsCannotResolve: Bool {
        guard let s = systemDNS else { return false }
        return s.status != .ok
    }
}

/// A DPI core that refused to start with some flags; shown verbatim so the error is not hidden.
public struct EngineLaunchError: Codable, Sendable, Hashable {
    public var engine: DPIEngine
    public var strategy: String
    public var message: String

    public init(engine: DPIEngine, strategy: String, message: String) {
        self.engine = engine
        self.strategy = strategy
        self.message = message
    }
}

public struct TuneReport: Codable, Sendable {
    /// The winning engine and its strategy index, nil / -1 when nothing worked.
    public var engine: DPIEngine?
    public var strategyIndex: Int
    public var cancelled: Bool
    public var hosts: [HostProbe]
    public var launchErrors: [EngineLaunchError]
    /// Resolver used when the system DNS failed, nil when it was not needed.
    public var dnsSource: String?

    public init(engine: DPIEngine?, strategyIndex: Int, cancelled: Bool, hosts: [HostProbe],
                launchErrors: [EngineLaunchError], dnsSource: String?) {
        self.engine = engine
        self.strategyIndex = strategyIndex
        self.cancelled = cancelled
        self.hosts = hosts
        self.launchErrors = launchErrors
        self.dnsSource = dnsSource
    }

    public enum Verdict: Equatable, Sendable {
        /// A strategy works for at least one blocked host.
        case found
        /// Every tested host opens without bypass.
        case notBlocked
        /// No host got past DNS, so no strategy could be judged.
        case dnsProblem
        /// The cores failed to start, so no strategy could be judged.
        case engineProblem
        /// Every host with an address refused TCP: an IP block, DPI bypass cannot help.
        case ipBlocked
        /// The cores ran on reachable hosts and none got through.
        case noStrategy
        case cancelled
    }

    public var verdict: Verdict {
        if cancelled { return .cancelled }
        if engine != nil, strategyIndex >= 0 { return .found }
        if !hosts.isEmpty, hosts.allSatisfy(\.directOK) { return .notBlocked }
        let dnsFailures: Set<ProbeFailure> = [.dnsNotFound, .dnsTimeout, .dnsFailed]
        let pending = hosts.filter { !$0.directOK }
        if !pending.isEmpty, pending.allSatisfy({ $0.failure.map(dnsFailures.contains) ?? false }) { return .dnsProblem }
        let reachable = pending.filter { !($0.failure.map(dnsFailures.contains) ?? false) }
        if !reachable.isEmpty, reachable.allSatisfy({ $0.failure == .tcpFailed }) { return .ipBlocked }
        if !reachable.isEmpty, reachable.allSatisfy({ $0.failure == .engineFailed }) { return .engineProblem }
        return .noStrategy
    }

    /// Picks the engine/strategy that opened the most hosts. Ties go to the engine tried first
    /// (the user's current one) and then to the earlier, simpler strategy.
    public static func winner(_ wins: [(engine: DPIEngine, index: Int, hosts: Int)]) -> (engine: DPIEngine, index: Int)? {
        var best: (engine: DPIEngine, index: Int, hosts: Int)?
        for w in wins where w.hosts > 0 {
            if best == nil || w.hosts > best!.hosts { best = w }
        }
        return best.map { ($0.engine, $0.index) }
    }
}

/// Live progress of the auto-tune for the UI.
public struct TuneProgress: Codable, Sendable, Hashable {
    public enum Phase: String, Codable, Sendable { case dns, direct, strategy }
    public var phase: Phase
    public var engine: DPIEngine?
    public var strategy: String?
    public var step: Int
    public var total: Int

    public init(phase: Phase, engine: DPIEngine? = nil, strategy: String? = nil, step: Int = 0, total: Int = 0) {
        self.phase = phase
        self.engine = engine
        self.strategy = strategy
        self.step = step
        self.total = total
    }
}

/// Order in which the auto-tune tries the cores: the profile's engine first, then the other one if
/// it is installed.
public enum TunePlan {
    public static func engines(active: DPIEngine, installed: Set<DPIEngine>) -> [DPIEngine] {
        var order = [active] + DPIEngine.allCases.filter { $0 != active }
        order.removeAll { !installed.contains($0) }
        return order
    }

    /// The address a probe should use: the system answer when apps get one, else the provider's.
    /// IPv4 first; IPv6 only when it is redirected (otherwise apps would not reach it through us).
    public static func address(system: DNSOutcome?, provider: DNSOutcome?, allowIPv6: Bool) -> (ip: IPAddr, fromSystem: Bool)? {
        func pick(_ o: DNSOutcome?) -> IPAddr? {
            guard let o, o.status == .ok else { return nil }
            let ips = o.ips.filter { !$0.isPrivate && !$0.isUnspecified }
            return ips.first(where: \.isV4) ?? (allowIPv6 ? ips.first : nil)
        }
        if let ip = pick(system) { return (ip, true) }
        if let ip = pick(provider) { return (ip, false) }
        return nil
    }

    public static func dnsFailure(system: DNSOutcome?, provider: DNSOutcome?) -> ProbeFailure {
        let all = [system, provider].compactMap { $0 }
        if all.contains(where: { $0.status == .nxdomain || $0.status == .noData }) { return .dnsNotFound }
        if !all.isEmpty, all.allSatisfy({ $0.status == .timeout }) { return .dnsTimeout }
        return .dnsFailed
    }
}

extension IPAddr {
    /// 0.0.0.0 or ::, what DNS-level blocking often answers instead of NXDOMAIN.
    public var isUnspecified: Bool { bytes.allSatisfy { $0 == 0 } }
}

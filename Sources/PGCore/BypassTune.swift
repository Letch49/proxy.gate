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

/// One `.directDPI` rule to tune: its id and the hosts to probe for it (already derived by the app,
/// re-validated by the engine).
public struct TuneRuleInput: Codable, Sendable, Hashable {
    public var id: UUID
    public var hosts: [String]

    public init(id: UUID, hosts: [String]) {
        self.id = id
        self.hosts = hosts
    }
}

/// The auto-tune's answer for one `.directDPI` rule.
public struct RuleTuneResult: Codable, Sendable, Hashable {
    public var ruleID: UUID
    /// The rule's probe hosts, each with the engine/strategy that opened it (if any).
    public var hosts: [HostProbe]
    /// The core whose chosen strategy opens the most of this rule's hosts, nil when none does.
    public var engine: DPIEngine?
    public var strategyIndex: Int
    /// Every probe host opens, with the bypass or without it.
    public var ok: Bool
    /// Mean time of a full request through the chosen core, over the hosts it opened.
    public var latencyMs: Int?

    public init(ruleID: UUID, hosts: [HostProbe], engine: DPIEngine?, strategyIndex: Int, ok: Bool, latencyMs: Int?) {
        self.ruleID = ruleID
        self.hosts = hosts
        self.engine = engine
        self.strategyIndex = strategyIndex
        self.ok = ok
        self.latencyMs = latencyMs
    }

    /// All hosts open without any bypass: the rule is not needed right now.
    public var notBlocked: Bool { !hosts.isEmpty && hosts.allSatisfy(\.directOK) }
}

public struct TuneReport: Codable, Sendable {
    /// The engine and strategy that open the most of the general test hosts, nil / -1 when none.
    public var engine: DPIEngine?
    public var strategyIndex: Int
    public var cancelled: Bool
    /// The general test hosts.
    public var hosts: [HostProbe]
    public var launchErrors: [EngineLaunchError]
    /// Resolver used when the system DNS failed, nil when it was not needed.
    public var dnsSource: String?
    /// Per-rule results, one for each tuned `.directDPI` rule.
    public var rules: [RuleTuneResult]
    /// The one strategy chosen per core (opens the most hosts overall), nil when it opened none.
    public var tpwsStrategyIndex: Int?
    public var byedpiStrategyIndex: Int?

    public init(engine: DPIEngine?, strategyIndex: Int, cancelled: Bool, hosts: [HostProbe],
                launchErrors: [EngineLaunchError], dnsSource: String?, rules: [RuleTuneResult] = [],
                tpwsStrategyIndex: Int? = nil, byedpiStrategyIndex: Int? = nil) {
        self.engine = engine
        self.strategyIndex = strategyIndex
        self.cancelled = cancelled
        self.hosts = hosts
        self.launchErrors = launchErrors
        self.dnsSource = dnsSource
        self.rules = rules
        self.tpwsStrategyIndex = tpwsStrategyIndex
        self.byedpiStrategyIndex = byedpiStrategyIndex
    }

    /// The strategy the tune chose for `engine`, nil when none of its strategies opened anything.
    public func chosenStrategy(for engine: DPIEngine) -> Int? {
        engine == .byedpi ? byedpiStrategyIndex : tpwsStrategyIndex
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
        // A rule the tune opened counts too: the general list may be empty or not blocked.
        if rules.contains(where: { $0.engine != nil }) { return .found }
        let all = hosts + rules.flatMap(\.hosts)
        if !all.isEmpty, all.allSatisfy(\.directOK) { return .notBlocked }
        let dnsFailures: Set<ProbeFailure> = [.dnsNotFound, .dnsTimeout, .dnsFailed]
        let pending = all.filter { !$0.directOK }
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

/// What one strategy of one core opened: host -> time of the full request in ms (nil if unknown).
public struct StrategyOutcome: Sendable, Hashable {
    public var engine: DPIEngine
    public var index: Int
    public var opened: [String: Int?]

    public init(engine: DPIEngine, index: Int, opened: [String: Int?]) {
        self.engine = engine
        self.index = index
        self.opened = opened
    }
}

/// How the auto-tune turns "which strategy opened which host" into settings. Pure, so it is tested
/// apart from the probes.
public enum TuneChoice {
    /// One strategy per core, since a core runs one strategy at a time: the one that opened the most
    /// hosts. Ties go to the earlier, simpler strategy. A core whose strategies opened nothing is
    /// left out.
    public static func strategies(_ outcomes: [StrategyOutcome]) -> [DPIEngine: Int] {
        var best: [DPIEngine: StrategyOutcome] = [:]
        for o in outcomes.sorted(by: { $0.index < $1.index }) where !o.opened.isEmpty {
            if let b = best[o.engine], b.opened.count >= o.opened.count { continue }
            best[o.engine] = o
        }
        return best.mapValues(\.index)
    }

    public struct Pick: Equatable, Sendable {
        public var engine: DPIEngine
        public var index: Int
        public var opened: Int
        public var latencyMs: Int?
    }

    /// For a group of hosts (one rule's, or the general list): the core whose chosen strategy opens
    /// the most of them; then the lower mean latency; then `order` (the primary core first).
    public static func pick(hosts: [String], outcomes: [StrategyOutcome], chosen: [DPIEngine: Int],
                            order: [DPIEngine]) -> Pick? {
        let engines = order + DPIEngine.allCases.filter { !order.contains($0) }
        var best: Pick?
        for engine in engines {
            guard let index = chosen[engine],
                  let outcome = outcomes.first(where: { $0.engine == engine && $0.index == index }) else { continue }
            let hits: [Int?] = hosts.compactMap { outcome.opened[$0] }
            guard !hits.isEmpty else { continue }
            let times = hits.compactMap { $0 }
            let latency = times.isEmpty ? nil : times.reduce(0, +) / times.count
            let candidate = Pick(engine: engine, index: index, opened: hits.count, latencyMs: latency)
            guard let current = best else { best = candidate; continue }
            if candidate.opened > current.opened {
                best = candidate
            } else if candidate.opened == current.opened, let l = latency, l < (current.latencyMs ?? Int.max) {
                best = candidate
            }
        }
        return best
    }
}

/// Host lists for the auto-tune: the user's test hosts and the probe hosts of each `.directDPI` rule.
public enum TuneHosts {
    /// Probe hosts per rule, general test hosts, rules, and unique hosts in one run.
    public static let perRule = 3
    public static let maxGeneral = 10
    public static let maxRules = 32
    public static let maxTotal = 24

    /// One host as typed: lowercased, without scheme, path, port or trailing dot. nil when it is not
    /// a host name (an IP, a range, a wildcard, a single label).
    public static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let cut = s.firstIndex(where: { $0 == "/" || $0 == "?" || $0 == "#" }) { s = String(s[..<cut]) }
        if let at = s.lastIndex(of: "@") { s = String(s[s.index(after: at)...]) }
        if let colon = s.firstIndex(of: ":") { s = String(s[..<colon]) }
        while s.hasSuffix(".") { s.removeLast() }
        guard s.contains("."), DNSName.isValid(s), IPAddr(s) == nil else { return nil }
        // A name needs a letter in its last label; this drops partial IPs and "a.b.c.d-e.f.g.h" ranges.
        guard let tld = s.split(separator: ".").last, tld.contains(where: \.isLetter) else { return nil }
        return s
    }

    /// A `;`/`,`/newline list of hosts, normalized, invalid ones dropped, without duplicates.
    public static func parse(_ text: String) -> [String] {
        unique(splitList(text).compactMap(normalize))
    }

    /// The hosts the auto-tune probes for a rule: its own test hosts when set, else names taken from
    /// its targets. Geo categories, IPs, CIDRs and ranges cannot be probed and are skipped;
    /// `*.x.com` becomes `x.com`; other wildcards are skipped.
    public static func probeHosts(targetHosts: String, testHosts: String) -> [String] {
        let own = parse(testHosts)
        if !own.isEmpty { return Array(own.prefix(perRule)) }
        var derived: [String] = []
        for entry in splitList(targetHosts) {
            var e = entry.lowercased()
            if e.hasPrefix("geosite:") || e.hasPrefix("geoip:") { continue }
            if e.hasPrefix("*.") { e = String(e.dropFirst(2)) }
            if e.contains("*") || e.contains("?") || e.contains("/") { continue }
            if let host = normalize(e) { derived.append(host) }
        }
        return Array(unique(derived).prefix(perRule))
    }

    public static func probeHosts(for rule: Rule) -> [String] {
        probeHosts(targetHosts: rule.targetHosts, testHosts: rule.testHosts)
    }

    /// Re-checks a tune request from the control socket: valid names only, the caps above, and the
    /// default test hosts when nothing is left. General hosts take the budget first, then rules in order.
    public static func sanitize(general: [String], rules: [TuneRuleInput]) -> (general: [String], rules: [TuneRuleInput]) {
        var seen = Set<String>()
        func admit(_ host: String) -> Bool {
            if seen.contains(host) { return true }
            guard seen.count < maxTotal else { return false }
            seen.insert(host)
            return true
        }
        var cleanGeneral = Array(unique(general.prefix(256).compactMap(normalize)).prefix(maxGeneral))
        var cleanRules: [TuneRuleInput] = []
        var ids = Set<UUID>()
        for rule in rules.prefix(maxRules) where !ids.contains(rule.id) {
            ids.insert(rule.id)
            let hosts = Array(unique(rule.hosts.prefix(64).compactMap(normalize)).prefix(perRule))
            if !hosts.isEmpty { cleanRules.append(TuneRuleInput(id: rule.id, hosts: hosts)) }
        }
        if cleanGeneral.isEmpty && cleanRules.isEmpty {
            cleanGeneral = parse(Profile.defaultDpiTestHosts)
        }
        cleanGeneral = cleanGeneral.filter(admit)
        cleanRules = cleanRules.compactMap { rule in
            let kept = rule.hosts.filter(admit)
            return kept.isEmpty ? nil : TuneRuleInput(id: rule.id, hosts: kept)
        }
        return (cleanGeneral, cleanRules)
    }

    private static func unique(_ hosts: [String]) -> [String] {
        var seen = Set<String>()
        return hosts.filter { seen.insert($0).inserted }
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

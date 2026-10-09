import Foundation

/// Who opened a connection.
public struct AppIdentity: Codable, Hashable, Sendable {
    public var pid: Int32
    /// Executable file name, e.g. "Google Chrome Helper".
    public var name: String
    public var path: String?
    /// Bundle id of the innermost enclosing bundle.
    public var bundleID: String?
    /// Bundle id of the outermost .app (e.g. com.google.Chrome for its helpers).
    public var outerBundleID: String?
    /// Names of all enclosing bundles without extension, outermost first.
    public var bundleNames: [String] = []

    public init(pid: Int32, name: String) {
        self.pid = pid
        self.name = name
    }

    /// "Google Chrome Helper(com.google.Chrome.helper)" like Proxifier.
    public var display: String {
        if let bundleID { return "\(name)(\(bundleID))" }
        return name
    }

    var matchCandidates: [String] {
        var c = [name]
        if let bundleID { c.append(bundleID) }
        if let outerBundleID { c.append(outerBundleID) }
        for b in bundleNames {
            c.append(b)
            c.append(b + ".app")
        }
        if let path { c.append(path) }
        return c.map { $0.lowercased() }
    }
}

public struct MatchRequest: Sendable {
    public var app: AppIdentity
    public var hostname: String?
    public var ip: IPAddr
    public var port: UInt16

    public init(app: AppIdentity, hostname: String?, ip: IPAddr, port: UInt16) {
        self.app = app
        self.hostname = hostname
        self.ip = ip
        self.port = port
    }
}

/// Case-insensitive glob with `*` and `?`. Inputs must already be lowercased.
public func globMatch(_ pattern: String, _ text: String) -> Bool {
    let p = Array(pattern.utf8), t = Array(text.utf8)
    var pi = 0, ti = 0
    var star = -1, mark = 0
    while ti < t.count {
        if pi < p.count && (p[pi] == UInt8(ascii: "?") || p[pi] == t[ti]) {
            pi += 1
            ti += 1
        } else if pi < p.count && p[pi] == UInt8(ascii: "*") {
            star = pi
            mark = ti
            pi += 1
        } else if star >= 0 {
            pi = star + 1
            mark += 1
            ti = mark
        } else {
            return false
        }
    }
    while pi < p.count && p[pi] == UInt8(ascii: "*") {
        pi += 1
    }
    return pi == p.count
}

func splitList(_ text: String) -> [String] {
    text.components(separatedBy: CharacterSet(charactersIn: ";,\n"))
        .map { $0.trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: "\""))) }
        .filter { !$0.isEmpty }
}

func isAny(_ entries: [String]) -> Bool {
    entries.isEmpty || entries.contains { $0.lowercased() == "any" }
}

enum HostMatcher {
    case ip(IPAddr)
    case range(IPAddr, IPAddr)
    case cidr(IPAddr, Int)
    case glob(String)

    init(_ entry: String, computerName: String) {
        let parts = entry.split(separator: "-", maxSplits: 1).map { String($0) }
        if parts.count == 2, let lo = IPAddr(parts[0]), let hi = IPAddr(parts[1]), lo.isV4 == hi.isV4 {
            self = .range(lo, hi)
            return
        }
        let slash = entry.split(separator: "/", maxSplits: 1).map { String($0) }
        if slash.count == 2, let base = IPAddr(slash[0]), let bits = Int(slash[1]) {
            self = .cidr(base, bits)
            return
        }
        if let ip = IPAddr(entry) {
            self = .ip(ip)
            return
        }
        let lower = entry.lowercased()
        self = .glob(lower == "%computername%" ? computerName.lowercased() : lower)
    }

    func matches(hostname: String?, ip: IPAddr) -> Bool {
        switch self {
        case .ip(let a):
            return a == ip
        case .range(let lo, let hi):
            return lo.isV4 == ip.isV4 && lo <= ip && ip <= hi
        case .cidr(let base, let bits):
            return base.sharesPrefix(with: ip, bits: bits)
        case .glob(let pattern):
            if let hostname {
                if globMatch(pattern, hostname) { return true }
                // "*.example.com" also covers "example.com".
                if pattern.hasPrefix("*."), hostname == String(pattern.dropFirst(2)) { return true }
            }
            return globMatch(pattern, ip.description)
        }
    }
}

struct CompiledRule {
    let rule: Rule
    let apps: [String]?
    let hosts: [HostMatcher]?
    /// `geosite:…` / `geoip:…` targets, matched against the bundled databases by a GeoMatching.
    let geo: [String]?
    let ports: [ClosedRange<UInt16>]?

    init(_ rule: Rule, computerName: String) {
        self.rule = rule
        let appList = splitList(rule.applications)
        apps = isAny(appList) ? nil : appList.map { $0.lowercased() }
        let hostList = splitList(rule.targetHosts)
        if isAny(hostList) {
            hosts = nil
            geo = nil
        } else {
            let geoTokens = hostList.filter { CompiledRule.isGeoToken($0) }.map { $0.lowercased() }
            let plain = hostList.filter { !CompiledRule.isGeoToken($0) }
            hosts = plain.isEmpty ? nil : plain.map { HostMatcher($0, computerName: computerName) }
            geo = geoTokens.isEmpty ? nil : geoTokens
        }
        let portList = splitList(rule.targetPorts)
        ports = isAny(portList) ? nil : portList.compactMap(CompiledRule.parsePorts)
    }

    static func isGeoToken(_ s: String) -> Bool {
        let l = s.lowercased()
        return l.hasPrefix("geosite:") || l.hasPrefix("geoip:")
    }

    static func parsePorts(_ s: String) -> ClosedRange<UInt16>? {
        let parts = s.split(separator: "-", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        guard let first = parts.first, let lo = UInt16(first) else { return nil }
        if parts.count == 2 {
            guard let hi = UInt16(parts[1]), hi >= lo else { return nil }
            return lo...hi
        }
        return lo...lo
    }

    func matches(_ r: MatchRequest, geoDB: GeoMatching?) -> Bool {
        if let ports, !ports.contains(where: { $0.contains(r.port) }) {
            return false
        }
        if hosts != nil || geo != nil {
            let hostOK = hosts?.contains { $0.matches(hostname: r.hostname, ip: r.ip) } ?? false
            let geoOK = geo?.contains { geoDB?.matches(token: $0, host: r.hostname, ip: r.ip) ?? false } ?? false
            if !(hostOK || geoOK) { return false }
        }
        if let apps {
            let candidates = r.app.matchCandidates
            if !apps.contains(where: { pattern in candidates.contains { globMatch(pattern, $0) } }) {
                return false
            }
        }
        return true
    }
}

/// Matches `geosite:…` / `geoip:…` rule targets against the bundled databases. Supplied by the
/// engine (which loads the .dat files); nil elsewhere, where geo tokens simply never match.
public protocol GeoMatching: Sendable {
    func matches(token: String, host: String?, ip: IPAddr) -> Bool
}

/// Rules compiled for fast matching; first enabled match wins, default rule last.
public final class RuleSet: @unchecked Sendable {
    private let compiled: [CompiledRule]
    private let fallback: Rule

    public init(profile: Profile, computerName: String = ProcessInfo.processInfo.hostName) {
        var p = profile
        p.normalizeRules()
        compiled = p.rules.filter { $0.enabled && !$0.isDefault }.map { CompiledRule($0, computerName: computerName) }
        fallback = p.rules.last!
    }

    /// Finds the first matching rule and resolves its action to something the engine runs directly:
    /// `.global` becomes the `activeBridge`; `.vpn` stays `.vpn` when the core is up, else `.block`
    /// (a "VPN only" rule must never leak to direct). Rules whose specific proxy/chain is
    /// `unavailable` (its bound interface is down) are skipped, as is the default rule resolving
    /// onto a down proxy — that one falls back to direct.
    public func match(_ request: MatchRequest, activeBridge: Bridge = .direct,
                      vpnAvailable: Bool = false, dpiAvailable: Bool = false,
                      unavailable: Set<UUID> = [], geoDB: GeoMatching? = nil) -> Rule {
        let selected = compiled.first {
            $0.matches(request, geoDB: geoDB) && RuleSet.selectable($0.rule.action, activeBridge: activeBridge, unavailable: unavailable)
        }?.rule ?? fallback
        var rule = selected
        rule.action = RuleSet.resolve(selected.action, activeBridge: activeBridge,
                                      vpnAvailable: vpnAvailable, dpiAvailable: dpiAvailable, unavailable: unavailable)
        return rule
    }

    /// Whether a rule can be chosen: an explicit proxy/chain whose interface is down is skipped so
    /// the next rule applies. `.global` and `.vpn` are always selectable (they resolve afterwards).
    private static func selectable(_ action: RuleAction, activeBridge: Bridge, unavailable: Set<UUID>) -> Bool {
        switch action {
        case .proxy(let id), .chain(let id): return !unavailable.contains(id)
        case .direct, .block, .global, .vpn, .directDPI: return true
        }
    }

    private static func resolve(_ action: RuleAction, activeBridge: Bridge,
                                vpnAvailable: Bool, dpiAvailable: Bool, unavailable: Set<UUID>) -> RuleAction {
        switch action {
        case .direct, .block:
            return action
        case .directDPI:
            // Through tpws when the DPI core is up, else a plain direct connection.
            return dpiAvailable ? .directDPI : .direct
        case .proxy(let id):
            // Reached only by the default rule (selectable() filters the rest) — fall back to direct.
            return unavailable.contains(id) ? .direct : .proxy(id)
        case .chain(let id):
            return unavailable.contains(id) ? .direct : .chain(id)
        case .vpn:
            return vpnAvailable ? .vpn : .block
        case .global:
            // Resolve one hop into the active bridge; a down/missing bridge falls back to direct.
            switch activeBridge {
            case .direct: return .direct
            case .vpn: return vpnAvailable ? .vpn : .direct
            case .proxy(let id): return unavailable.contains(id) ? .direct : .proxy(id)
            }
        }
    }
}

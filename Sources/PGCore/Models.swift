import Foundation

public enum ProxyType: String, Codable, CaseIterable, Identifiable, Sendable {
    /// HTTP proxy with CONNECT support (Proxifier calls it "HTTPS").
    case https = "HTTPS"
    case socks5 = "SOCKS5"
    case socks4 = "SOCKS4"

    public var id: String { rawValue }
}

public struct ProxyServer: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var host: String
    public var port: UInt16
    public var type: ProxyType
    public var useAuth = false
    public var username = ""
    public var password = ""
    /// MAC of the adapter this proxy is reachable through. The proxy is used only while that
    /// adapter is up, and connections to it leave through it. nil = any adapter.
    public var interfaceMAC: String?
    /// Adapter title for the UI while it is unplugged, e.g. "USB 10/100 LAN (en8)".
    public var interfaceName: String?

    public init(host: String, port: UInt16, type: ProxyType) {
        self.host = host
        self.port = port
        self.type = type
    }

    /// "192.0.2.10:3128", IPv6 literals in brackets.
    public var endpoint: String { ProxyTarget(host: host, port: port).authority }
    /// "192.0.2.10:3128 HTTPS"
    public var title: String { "\(endpoint) \(type.rawValue)" }
}

public struct ProxyChain: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var name: String
    public var proxyIDs: [UUID] = []

    public init(name: String) {
        self.name = name
    }
}

public enum RuleAction: Codable, Hashable, Sendable {
    case direct
    case block
    /// Follow the active bridge — VPN at home, the bound proxy at work (see `Bridge`).
    case global
    /// Always the VPN bridge, wherever you are ("Только VPN").
    case vpn
    /// Direct, but through the DPI-bypass core — for sites DPI blocks but a VPN isn't wanted.
    case directDPI
    /// A specific proxy ("Только Proxy").
    case proxy(UUID)
    case chain(UUID)
}

/// The egress a `.global` rule resolves to right now. The app picks it from which bound interface
/// is up (Ethernet wins) and pushes it to the engine.
public enum Bridge: Codable, Hashable, Sendable {
    case direct
    case vpn
    case proxy(UUID)

    public var action: RuleAction {
        switch self {
        case .direct: return .direct
        case .vpn: return .vpn
        case .proxy(let id): return .proxy(id)
        }
    }
}

public struct Rule: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var enabled = true
    public var name: String
    /// Patterns separated by `;`, e.g. `chrome; com.apple.*; "Google Chrome"`. Empty = any.
    public var applications = ""
    /// Hostname wildcards, IPs, ranges and CIDRs separated by `;`. Empty = any.
    public var targetHosts = ""
    /// Ports and ranges separated by `;`. Empty = any.
    public var targetPorts = ""
    public var action: RuleAction = .direct
    public var isDefault = false
    /// A built-in rule the user can't disable, delete, reorder or change the action of (only its
    /// targets). Used for the "Local networks — direct" rule.
    public var locked = false
    /// Auto-managed rule (AnyConnect routes): shown read-only and highlighted, removed when the
    /// tunnel drops. Implies locked.
    public var dynamic = false

    public init(name: String, applications: String = "", targetHosts: String = "", targetPorts: String = "", action: RuleAction = .direct, isDefault: Bool = false, locked: Bool = false, dynamic: Bool = false) {
        self.name = name
        self.applications = applications
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.action = action
        self.isDefault = isDefault
        self.locked = locked || dynamic
        self.dynamic = dynamic
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        applications = try c.decodeIfPresent(String.self, forKey: .applications) ?? ""
        targetHosts = try c.decodeIfPresent(String.self, forKey: .targetHosts) ?? ""
        targetPorts = try c.decodeIfPresent(String.self, forKey: .targetPorts) ?? ""
        action = try c.decodeIfPresent(RuleAction.self, forKey: .action) ?? .direct
        isDefault = try c.decodeIfPresent(Bool.self, forKey: .isDefault) ?? false
        locked = try c.decodeIfPresent(Bool.self, forKey: .locked) ?? false
        dynamic = try c.decodeIfPresent(Bool.self, forKey: .dynamic) ?? false
    }
}

public struct DNSSettings: Codable, Hashable, Sendable {
    /// Read the TLS SNI / HTTP Host header to learn the hostname behind an IP.
    public var sniffHostnames = true
    /// Pass the hostname (not the IP) to the proxy, so the proxy resolves it.
    public var sendHostnameToProxy = true
    /// How long to wait for the client's first bytes before falling back to the IP.
    public var sniffTimeoutMs = 300

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = DNSSettings()
        sniffHostnames = try c.decodeIfPresent(Bool.self, forKey: .sniffHostnames) ?? d.sniffHostnames
        sendHostnameToProxy = try c.decodeIfPresent(Bool.self, forKey: .sendHostnameToProxy) ?? d.sendHostnameToProxy
        sniffTimeoutMs = try c.decodeIfPresent(Int.self, forKey: .sniffTimeoutMs) ?? d.sniffTimeoutMs
    }
}

public struct AdvancedSettings: Codable, Hashable, Sendable {
    public var listenPort: UInt16 = 18765
    public var captureIPv6 = true
    /// Block UDP/443 so browsers fall back from QUIC (which cannot be proxied) to TCP.
    public var blockQUIC = true
    /// Networks that never reach the engine (pf level), `;`-separated IPs / CIDRs.
    public var bypassNetworks = ""
    public var connectTimeoutSec = 15

    public init() {}

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = AdvancedSettings()
        listenPort = try c.decodeIfPresent(UInt16.self, forKey: .listenPort) ?? d.listenPort
        captureIPv6 = try c.decodeIfPresent(Bool.self, forKey: .captureIPv6) ?? d.captureIPv6
        blockQUIC = try c.decodeIfPresent(Bool.self, forKey: .blockQUIC) ?? d.blockQUIC
        bypassNetworks = try c.decodeIfPresent(String.self, forKey: .bypassNetworks) ?? d.bypassNetworks
        connectTimeoutSec = try c.decodeIfPresent(Int.self, forKey: .connectTimeoutSec) ?? d.connectTimeoutSec
    }
}

public struct Profile: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var name: String
    public var proxies: [ProxyServer] = []
    public var chains: [ProxyChain] = []
    public var rules: [Rule]
    public var dns = DNSSettings()
    public var advanced = AdvancedSettings()
    public var subscriptions: [Subscription] = []
    /// Subscription currently feeding the Xray core, nil when the VPN is off.
    public var activeSubscriptionID: UUID?
    /// Adapter the VPN bridge is bound to (nil = any). The VPN bridge is a candidate only while up.
    public var vpnInterfaceMAC: String?
    public var vpnInterfaceName: String?
    /// The proxy that serves the "proxy bridge" for `.global`/auto-switch (the last one used).
    public var activeProxyID: UUID?
    /// Auto-switch the active bridge when the network changes.
    public var autoSwitch = true
    /// Ask VPN/Proxy on an unknown network where both are available.
    public var askOnUnknownNetwork = true
    /// Minutes between automatic server latency checks (0 = manual only).
    public var pingInterval = 5
    public var hideUnreachableServers = true
    /// Send Russian and LAN destinations direct, bypassing the VPN (done inside Xray via geosite/geoip).
    public var routeLocalDirect = false
    /// DPI bypass (tpws) on direct routes.
    public var bypassEnabled = false
    /// Index into DPIStrategies.all for the active desync strategy.
    public var bypassStrategyIndex = 0
    /// Hosts the DPI auto-tune probes (known-blocked sites), ";"-separated. Editable in Settings.
    public var dpiTestHosts = "www.youtube.com; discord.com; rutracker.org; instagram.com"

    public init(name: String, rules: [Rule]) {
        self.name = name
        self.rules = rules
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? "Default"
        proxies = try c.decodeIfPresent([ProxyServer].self, forKey: .proxies) ?? []
        chains = try c.decodeIfPresent([ProxyChain].self, forKey: .chains) ?? []
        rules = try c.decodeIfPresent([Rule].self, forKey: .rules) ?? []
        dns = try c.decodeIfPresent(DNSSettings.self, forKey: .dns) ?? DNSSettings()
        advanced = try c.decodeIfPresent(AdvancedSettings.self, forKey: .advanced) ?? AdvancedSettings()
        subscriptions = try c.decodeIfPresent([Subscription].self, forKey: .subscriptions) ?? []
        activeSubscriptionID = try c.decodeIfPresent(UUID.self, forKey: .activeSubscriptionID)
        vpnInterfaceMAC = try c.decodeIfPresent(String.self, forKey: .vpnInterfaceMAC)
        vpnInterfaceName = try c.decodeIfPresent(String.self, forKey: .vpnInterfaceName)
        activeProxyID = try c.decodeIfPresent(UUID.self, forKey: .activeProxyID)
        autoSwitch = try c.decodeIfPresent(Bool.self, forKey: .autoSwitch) ?? true
        askOnUnknownNetwork = try c.decodeIfPresent(Bool.self, forKey: .askOnUnknownNetwork) ?? true
        pingInterval = try c.decodeIfPresent(Int.self, forKey: .pingInterval) ?? 5
        hideUnreachableServers = try c.decodeIfPresent(Bool.self, forKey: .hideUnreachableServers) ?? true
        routeLocalDirect = try c.decodeIfPresent(Bool.self, forKey: .routeLocalDirect) ?? false
        bypassEnabled = try c.decodeIfPresent(Bool.self, forKey: .bypassEnabled) ?? false
        bypassStrategyIndex = try c.decodeIfPresent(Int.self, forKey: .bypassStrategyIndex) ?? 0
        dpiTestHosts = try c.decodeIfPresent(String.self, forKey: .dpiTestHosts) ?? "www.youtube.com; discord.com; rutracker.org; instagram.com"
    }

    public var activeSubscription: Subscription? {
        activeSubscriptionID.flatMap { id in subscriptions.first { $0.id == id } }
    }

    public mutating func removeSubscription(_ id: UUID) {
        subscriptions.removeAll { $0.id == id }
        if activeSubscriptionID == id { activeSubscriptionID = nil }
    }

    /// Runnable Xray JSON for the active subscription's chosen config, nil when the VPN is off.
    public func activeVPNConfig(socksPort: UInt16 = PGConstants.vpnSocksPort) -> String? {
        guard let sub = activeSubscription, let json = sub.cachedJSON else { return nil }
        return XraySubscription.assemble(json, index: sub.selectedConfig, socksPort: socksPort, routeLocalDirect: routeLocalDirect)
    }

    public static func makeDefault(name: String = "Default") -> Profile {
        Profile(name: name, rules: [
            Rule(name: "Local networks — direct", targetHosts: "localhost; 127.0.0.1; ::1; %ComputerName%; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16", action: .direct, locked: true),
            Rule(name: "Docker", applications: "Docker Desktop; com.docker.backend", targetHosts: "*.docker.com; *.docker.io", action: .direct),
            Rule(name: "Default", action: .global, isDefault: true),
        ])
    }

    public func proxy(_ id: UUID) -> ProxyServer? { proxies.first { $0.id == id } }
    public func chain(_ id: UUID) -> ProxyChain? { chains.first { $0.id == id } }

    /// Proxies and chains that cannot be used now because their adapter is down.
    /// `active` is `NetInterfaces.active()`.
    public func unavailableRoutes(active: [String: String]) -> Set<UUID> {
        let down = Set(proxies.filter { $0.interfaceMAC.map { active[$0] == nil } ?? false }.map(\.id))
        guard !down.isEmpty else { return [] }
        return down.union(chains.filter { $0.proxyIDs.contains(where: down.contains) }.map(\.id))
    }

    /// Proxies of a chain in order, skipping deleted ones.
    public func chainProxies(_ id: UUID) -> [ProxyServer] {
        chain(id)?.proxyIDs.compactMap { proxy($0) } ?? []
    }

    /// Short description used in the connection list: "192.0.2.10:3128 HTTPS", "Direct".
    public func describe(_ action: RuleAction) -> String {
        switch action {
        case .direct: return "Direct"
        case .block: return "Block"
        case .global: return "Global"
        case .vpn: return "VPN"
        case .directDPI: return "Direct + DPI"
        case .proxy(let id): return proxy(id)?.title ?? "Missing proxy"
        case .chain(let id): return chain(id).map { "Chain \($0.name)" } ?? "Missing chain"
        }
    }

    /// Description used in the rules table: "Proxy HTTPS 192.0.2.10:3128".
    public func describeLong(_ action: RuleAction) -> String {
        switch action {
        case .proxy(let id):
            guard let p = proxy(id) else { return "Missing proxy" }
            return "Proxy \(p.type.rawValue) \(p.endpoint)"
        default:
            return describe(action)
        }
    }

    /// Removes a proxy and everything referring to it.
    public mutating func removeProxy(_ id: UUID) {
        proxies.removeAll { $0.id == id }
        for i in chains.indices {
            chains[i].proxyIDs.removeAll { $0 == id }
        }
        for i in rules.indices where rules[i].action == .proxy(id) {
            rules[i].action = .direct
        }
    }

    public mutating func removeChain(_ id: UUID) {
        chains.removeAll { $0.id == id }
        for i in rules.indices where rules[i].action == .chain(id) {
            rules[i].action = .direct
        }
    }

    /// Guarantees exactly one default rule, placed last.
    public mutating func normalizeRules() {
        var defaultRule = rules.first { $0.isDefault } ?? Rule(name: "Default", action: .direct, isDefault: true)
        defaultRule.enabled = true
        rules.removeAll { $0.isDefault }
        rules.append(defaultRule)
    }
}

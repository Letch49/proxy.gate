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
    /// For a `.directDPI` rule: the core that bypasses its traffic. nil = the profile's primary core.
    public var dpiEngine: DPIEngine?
    /// For a `.directDPI` rule: hosts the auto-tune probes for it, `;`-separated. Empty = derived
    /// from `targetHosts` (see `TuneHosts.probeHosts`).
    public var testHosts = ""

    public init(name: String, applications: String = "", targetHosts: String = "", targetPorts: String = "", action: RuleAction = .direct, isDefault: Bool = false, locked: Bool = false, dynamic: Bool = false,
                dpiEngine: DPIEngine? = nil, testHosts: String = "") {
        self.name = name
        self.applications = applications
        self.targetHosts = targetHosts
        self.targetPorts = targetPorts
        self.action = action
        self.isDefault = isDefault
        self.locked = locked || dynamic
        self.dynamic = dynamic
        self.dpiEngine = dpiEngine
        self.testHosts = testHosts
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
        dpiEngine = try c.decodeIfPresent(DPIEngine.self, forKey: .dpiEngine)
        testHosts = try c.decodeIfPresent(String.self, forKey: .testHosts) ?? ""
    }
}

public struct DNSSettings: Codable, Hashable, Sendable {
    /// Read the TLS SNI / HTTP Host header to learn the hostname behind an IP.
    public var sniffHostnames = true
    /// Pass the hostname (not the IP) to the proxy, so the proxy resolves it.
    public var sendHostnameToProxy = true
    /// How long to wait for the client's first bytes before falling back to the IP.
    public var sniffTimeoutMs = 300
    /// DNS provider for diagnostics and for the domains below (built-in id or a custom one's id).
    public var providerID = "google"
    public var transport: DNSTransport = .doh
    public var customProviders: [DNSProvider] = []
    /// Make apps resolve `resolveDomains` through the provider (scoped /etc/resolver files pointing
    /// at the engine's stub). Every other name, corporate ones included, stays on the system DNS.
    public var resolveThroughProvider = false
    public var resolveDomains = DNSSettings.defaultResolveDomains

    public static let defaultResolveDomains = "youtube.com; googlevideo.com; ytimg.com; ggpht.com; youtu.be; youtube-nocookie.com"

    public init() {}

    public var providers: [DNSProvider] { DNSProviders.builtIn + customProviders }

    /// The selected provider, falling back to the first built-in if it was deleted.
    public var provider: DNSProvider {
        providers.first { $0.id == providerID } ?? DNSProviders.builtIn[0]
    }

    public var upstream: DNSUpstream { DNSUpstream(provider: provider, transport: transport) }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = DNSSettings()
        sniffHostnames = try c.decodeIfPresent(Bool.self, forKey: .sniffHostnames) ?? d.sniffHostnames
        sendHostnameToProxy = try c.decodeIfPresent(Bool.self, forKey: .sendHostnameToProxy) ?? d.sendHostnameToProxy
        sniffTimeoutMs = try c.decodeIfPresent(Int.self, forKey: .sniffTimeoutMs) ?? d.sniffTimeoutMs
        providerID = try c.decodeIfPresent(String.self, forKey: .providerID) ?? d.providerID
        transport = try c.decodeIfPresent(DNSTransport.self, forKey: .transport) ?? d.transport
        customProviders = try c.decodeIfPresent([DNSProvider].self, forKey: .customProviders) ?? []
        resolveThroughProvider = try c.decodeIfPresent(Bool.self, forKey: .resolveThroughProvider) ?? false
        resolveDomains = try c.decodeIfPresent(String.self, forKey: .resolveDomains) ?? d.resolveDomains
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
    /// DPI bypass on: the installed cores run, `.directDPI` rules go through them.
    public var bypassEnabled = false
    /// The primary DPI core: used for `bypassAllDirect` and for `.directDPI` rules with no core set.
    public var dpiEngine: DPIEngine = .tpws
    /// Strategy index per core; both cores run at once while bypass is on, each with its own.
    public var tpwsStrategyIndex = 0
    public var byedpiStrategyIndex = 0
    /// Also send plain `.direct` traffic through the primary core while bypass is on. Off by default:
    /// rules with action `.directDPI` are the one list of what gets bypassed.
    public var bypassAllDirect = false
    /// Hosts the DPI auto-tune probes besides the rules' own hosts, ";"-separated.
    public var dpiTestHosts = Profile.defaultDpiTestHosts
    /// Set once the YouTube preset rule was offered, so a user who deletes it does not get it back.
    public var youTubePresetOffered = false

    public static let defaultDpiTestHosts = "discord.com; instagram.com; rutracker.org"
    /// The default of earlier builds; a profile still holding it gets the new default.
    static let legacyDpiTestHosts = "www.youtube.com; redirector.googlevideo.com; discord.com; rutracker.org; instagram.com"

    /// Keys of earlier builds, read only to migrate. The learned host list itself is dropped.
    private enum LegacyKeys: String, CodingKey {
        case bypassStrategyIndex, bypassAutohostlist, bypassHosts
    }

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
        dpiEngine = try c.decodeIfPresent(DPIEngine.self, forKey: .dpiEngine) ?? .tpws
        let tpwsIndex = try c.decodeIfPresent(Int.self, forKey: .tpwsStrategyIndex)
        let byedpiIndex = try c.decodeIfPresent(Int.self, forKey: .byedpiStrategyIndex)
        tpwsStrategyIndex = tpwsIndex ?? 0
        byedpiStrategyIndex = byedpiIndex ?? 0
        if tpwsIndex == nil, byedpiIndex == nil {
            // One index for the one engine of earlier builds: it belongs to the engine it was set for.
            let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            if let old = try? legacy.decodeIfPresent(Int.self, forKey: .bypassStrategyIndex) {
                setStrategyIndex(old, for: dpiEngine)
            }
        }
        if let allDirect = try c.decodeIfPresent(Bool.self, forKey: .bypassAllDirect) {
            bypassAllDirect = allDirect
        } else {
            // Earlier builds bypassed all direct traffic unless a learned list narrowed it. Keep that
            // for such profiles; a non-empty learned list now maps to rules, so it starts off.
            let legacy = try decoder.container(keyedBy: LegacyKeys.self)
            let autohostlist = try? legacy.decodeIfPresent(Bool.self, forKey: .bypassAutohostlist)
            let learned = (try? legacy.decodeIfPresent([String].self, forKey: .bypassHosts)) ?? nil
            if let autohostlist {
                bypassAllDirect = !autohostlist || (learned ?? []).isEmpty
            } else {
                bypassAllDirect = false
            }
        }
        let testHosts = try c.decodeIfPresent(String.self, forKey: .dpiTestHosts) ?? Profile.defaultDpiTestHosts
        dpiTestHosts = testHosts == Profile.legacyDpiTestHosts ? Profile.defaultDpiTestHosts : testHosts
        youTubePresetOffered = try c.decodeIfPresent(Bool.self, forKey: .youTubePresetOffered) ?? false
    }

    /// Strategy index of `engine`, clamped to its list.
    public func strategyIndex(for engine: DPIEngine) -> Int {
        let raw = engine == .byedpi ? byedpiStrategyIndex : tpwsStrategyIndex
        return engine.strategies().indices.contains(raw) ? raw : 0
    }

    public mutating func setStrategyIndex(_ index: Int, for engine: DPIEngine) {
        let clamped = engine.strategies().indices.contains(index) ? index : 0
        switch engine {
        case .tpws: tpwsStrategyIndex = clamped
        case .byedpi: byedpiStrategyIndex = clamped
        }
    }

    /// Flags of `engine`'s chosen strategy.
    public func strategyFlags(for engine: DPIEngine) -> [String] {
        engine.strategies()[strategyIndex(for: engine)].flags
    }

    // MARK: - YouTube preset

    public static let youTubeTargets = "geosite:youtube; *.youtube.com; youtu.be; *.googlevideo.com; *.ytimg.com; *.ggpht.com"
    /// The page and a video host: a page that opens says nothing about video streams.
    public static let youTubeTestHosts = "www.youtube.com; redirector.googlevideo.com"

    /// "YouTube" through the DPI bypass. Off by default, so it does nothing until the user turns it on.
    public static func youTubePreset(enabled: Bool = false) -> Rule {
        var rule = Rule(name: "YouTube", targetHosts: youTubeTargets, action: .directDPI, testHosts: youTubeTestHosts)
        rule.enabled = enabled
        return rule
    }

    /// A rule already targets YouTube (by its geosite category or its main domain).
    public var hasYouTubeRule: Bool {
        rules.contains { rule in
            splitList(rule.targetHosts).contains { ["geosite:youtube", "*.youtube.com"].contains($0.lowercased()) }
        }
    }

    /// Adds the YouTube preset at the top of an existing profile, once in its lifetime. Returns true
    /// when the profile changed.
    @discardableResult
    public mutating func offerYouTubePreset() -> Bool {
        guard !youTubePresetOffered else { return false }
        youTubePresetOffered = true
        if !hasYouTubeRule { rules.insert(Profile.youTubePreset(), at: 0) }
        return true
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
        var profile = Profile(name: name, rules: [
            Profile.youTubePreset(),
            Rule(name: "Local networks — direct", targetHosts: "localhost; 127.0.0.1; ::1; %ComputerName%; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16", action: .direct, locked: true),
            Rule(name: "Docker", applications: "Docker Desktop; com.docker.backend", targetHosts: "*.docker.com; *.docker.io", action: .direct),
            Rule(name: "Default", action: .global, isDefault: true),
        ])
        profile.youTubePresetOffered = true
        return profile
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

import Foundation

/// A VPN subscription: a URL that returns one or more ready Xray configs. The raw response is
/// cached so configs can be listed and assembled offline; the user picks one to run.
public struct Subscription: Codable, Identifiable, Hashable, Sendable {
    public var id = UUID()
    public var name: String
    public var url: String
    public var autoUpdate = true
    /// Index of the chosen config within the cached response.
    public var selectedConfig = 0
    /// Raw provider response (a JSON array of configs, or a single config object).
    public var cachedJSON: String?
    public var updatedAt: Date?
    /// `subscription-userinfo` header, e.g. "upload=…; download=…; total=…; expire=…".
    public var userInfo: String?
    /// Config index → last measured TCP latency to that server in ms (absent = not yet, -1 = N/A).
    public var latencies: [Int: Int] = [:]
    public var latencyCheckedAt: Date?
    /// Collapsed in the VPN list.
    public var collapsed = false

    public init(name: String, url: String) {
        self.name = name
        self.url = url
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? "VPN"
        url = try c.decodeIfPresent(String.self, forKey: .url) ?? ""
        autoUpdate = try c.decodeIfPresent(Bool.self, forKey: .autoUpdate) ?? true
        selectedConfig = try c.decodeIfPresent(Int.self, forKey: .selectedConfig) ?? 0
        cachedJSON = try c.decodeIfPresent(String.self, forKey: .cachedJSON)
        updatedAt = try c.decodeIfPresent(Date.self, forKey: .updatedAt)
        userInfo = try c.decodeIfPresent(String.self, forKey: .userInfo)
        latencies = try c.decodeIfPresent([Int: Int].self, forKey: .latencies) ?? [:]
        latencyCheckedAt = try c.decodeIfPresent(Date.self, forKey: .latencyCheckedAt)
        collapsed = try c.decodeIfPresent(Bool.self, forKey: .collapsed) ?? false
    }

    /// Host shown in the UI, e.g. "sub.example.com".
    public var host: String { URL(string: url)?.host ?? url }

    /// Traffic/expiry parsed from `userInfo`.
    public var usage: SubscriptionUsage? { userInfo.flatMap(SubscriptionUsage.init) }
}

public struct SubscriptionUsage: Sendable {
    public var upload: UInt64 = 0
    public var download: UInt64 = 0
    public var total: UInt64 = 0
    public var expire: Date?

    public init?(_ header: String) {
        var found = false
        for part in header.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            let key = kv[0].trimmingCharacters(in: .whitespaces)
            let value = kv[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "upload": upload = UInt64(value) ?? 0; found = true
            case "download": download = UInt64(value) ?? 0; found = true
            case "total": total = UInt64(value) ?? 0; found = true
            case "expire": if let t = Double(value) { expire = Date(timeIntervalSince1970: t) }; found = true
            default: break
            }
        }
        guard found else { return nil }
    }

    public var used: UInt64 { upload + download }
    /// Fraction of the plan used (0...1), nil for unlimited (`total == 0`).
    public var fraction: Double? { total == 0 ? nil : min(1, Double(used) / Double(total)) }
    public var unlimited: Bool { total == 0 }
}

/// One config inside a subscription response, summarised for the list.
public struct XrayConfigSummary: Identifiable, Hashable, Sendable {
    public var index: Int
    public var name: String
    /// "VLESS · REALITY", "VLESS · gRPC"…
    public var transport: String
    /// True when the config load-balances across several servers ("Авто").
    public var balancer: Bool

    public var id: Int { index }
}

/// Parses and assembles Xray configs from a subscription's cached JSON. Provider configs are
/// used as-is except for the inbound, which is replaced with a local SOCKS proxy the engine dials.
public enum XraySubscription {
    /// The configs in a cached response, for the picker.
    public static func summaries(_ json: String) -> [XrayConfigSummary] {
        configObjects(json).enumerated().map { index, cfg in
            XrayConfigSummary(
                index: index,
                name: (cfg["remarks"] as? String) ?? "Config \(index + 1)",
                transport: transport(of: cfg),
                balancer: ((cfg["routing"] as? [String: Any])?["balancers"] as? [[Any]])?.isEmpty == false
                    || ((cfg["routing"] as? [String: Any])?["balancers"] as? [[String: Any]])?.isEmpty == false)
        }
    }

    /// Full runnable config JSON for the chosen index, with a loopback SOCKS inbound on `socksPort`.
    /// `credentials` adds SOCKS auth so only the engine can use it; nil = no auth (local testing).
    public static func assemble(_ json: String, index: Int, socksPort: UInt16,
                                credentials: (user: String, pass: String)? = nil,
                                routeLocalDirect: Bool = false) -> String? {
        let configs = configObjects(json)
        guard configs.indices.contains(index) else { return nil }
        var cfg = configs[index]
        var inbound: [String: Any] = [
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": Int(socksPort),
            "protocol": "socks",
            "sniffing": ["enabled": true, "destOverride": ["http", "tls"]],
        ]
        var settings: [String: Any] = ["udp": true]
        if let creds = credentials {
            settings["auth"] = "password"
            settings["accounts"] = [["user": creds.user, "pass": creds.pass]]
        } else {
            settings["auth"] = "noauth"
        }
        inbound["settings"] = settings
        cfg["inbounds"] = [inbound]
        if routeLocalDirect { addLocalDirectRouting(&cfg) }
        guard let data = try? JSONSerialization.data(withJSONObject: cfg) else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// Sends Russian and private (LAN) destinations straight out, ahead of the VPN. Xray does the
    /// matching with its bundled geosite/geoip.dat, so no list parsing is needed on our side.
    private static func addLocalDirectRouting(_ cfg: inout [String: Any]) {
        var outbounds = cfg["outbounds"] as? [[String: Any]] ?? []
        if !outbounds.contains(where: { ($0["tag"] as? String) == "direct" }) {
            outbounds.append(["tag": "direct", "protocol": "freedom"])
            cfg["outbounds"] = outbounds
        }
        var routing = cfg["routing"] as? [String: Any] ?? [:]
        var rules = routing["rules"] as? [[String: Any]] ?? []
        rules.insert(["type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct"], at: 0)
        rules.insert(["type": "field", "domain": ["geosite:category-ru", "geosite:private"], "outboundTag": "direct"], at: 0)
        routing["rules"] = rules
        cfg["routing"] = routing
    }

    /// Server endpoint of each config (index → host:port), for a TCP latency probe.
    public static func serverEndpoints(_ json: String) -> [Int: ProxyTarget] {
        var result: [Int: ProxyTarget] = [:]
        for (index, cfg) in configObjects(json).enumerated() {
            if let ep = endpoint(of: cfg) { result[index] = ep }
        }
        return result
    }

    private static func endpoint(of cfg: [String: Any]) -> ProxyTarget? {
        for ob in cfg["outbounds"] as? [[String: Any]] ?? [] {
            let settings = ob["settings"] as? [String: Any] ?? [:]
            if let node = (settings["vnext"] as? [[String: Any]])?.first ?? (settings["servers"] as? [[String: Any]])?.first,
               let addr = node["address"] as? String, let port = node["port"] as? Int, port > 0, port < 65536 {
                return ProxyTarget(host: addr, port: UInt16(port))
            }
        }
        return nil
    }

    private static func configObjects(_ json: String) -> [[String: Any]] {
        guard let data = json.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) else { return [] }
        if let array = parsed as? [[String: Any]] { return array }
        if let object = parsed as? [String: Any] { return [object] }
        return []
    }

    private static func transport(of cfg: [String: Any]) -> String {
        let outbounds = cfg["outbounds"] as? [[String: Any]] ?? []
        let proxyProtocols: Set<String> = ["vless", "vmess", "trojan", "shadowsocks"]
        guard let ob = outbounds.first(where: { proxyProtocols.contains(($0["protocol"] as? String) ?? "") }) else {
            return "—"
        }
        let proto = (ob["protocol"] as? String ?? "").uppercased()
        let stream = ob["streamSettings"] as? [String: Any] ?? [:]
        let security = (stream["security"] as? String).flatMap { $0 == "none" ? nil : $0.uppercased() }
        let network = stream["network"] as? String
        var parts = [proto]
        if let security { parts.append(security) }
        else if let network, network != "tcp" { parts.append(network.uppercased()) }
        return parts.joined(separator: " · ")
    }
}

import Foundation

/// Copy/paste of rules as a base64 string.
///
/// The payload carries the proxies and chains the rules point to (address, port and type only —
/// credentials are never exported), so a pasted rule keeps its action in another profile or app.
public enum RuleTransfer {
    static let prefix = "proxygate:"

    struct Payload: Codable {
        var version = 1
        var rules: [Rule]
        var proxies: [ProxyServer]
        var chains: [ProxyChain]
    }

    public static func export(_ rules: [Rule], from profile: Profile) -> String {
        let exported = rules.filter { !$0.isDefault }
        var proxyIDs = Set<UUID>()
        var chainIDs = Set<UUID>()
        for rule in exported {
            switch rule.action {
            case .proxy(let id): proxyIDs.insert(id)
            case .chain(let id):
                chainIDs.insert(id)
                profile.chain(id)?.proxyIDs.forEach { proxyIDs.insert($0) }
            default: break
            }
        }
        let proxies = profile.proxies.filter { proxyIDs.contains($0.id) }.map { p -> ProxyServer in
            var safe = p
            safe.useAuth = false
            safe.username = ""
            safe.password = ""
            return safe
        }
        let payload = Payload(rules: exported, proxies: proxies, chains: profile.chains.filter { chainIDs.contains($0.id) })
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let data = (try? encoder.encode(payload)) ?? Data()
        return prefix + data.base64EncodedString()
    }

    /// Decodes pasted text. Accepts the string with or without the "proxygate:" prefix and with
    /// whitespace / line breaks inside.
    public static func decode(_ text: String) throws -> (rules: [Rule], proxies: [ProxyServer], chains: [ProxyChain]) {
        var body = text.filter { !$0.isWhitespace }
        if body.lowercased().hasPrefix(prefix) {
            body = String(body.dropFirst(prefix.count))
        }
        // Tolerate URL-safe base64 and missing padding.
        body = body.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while body.count % 4 != 0 { body += "=" }
        guard !body.isEmpty, let data = Data(base64Encoded: body) else {
            throw NetError("Not a valid base64 string")
        }
        guard let payload = try? JSONDecoder().decode(Payload.self, from: data) else {
            throw NetError("The text does not contain ProxyGate rules")
        }
        guard !payload.rules.isEmpty else { throw NetError("No rules in the text") }
        return (payload.rules, payload.proxies, payload.chains)
    }

    /// Adds decoded rules above the default rule. Proxies are matched by address, port and type;
    /// missing ones are added (without credentials). Returns the number of rules added.
    @discardableResult
    public static func importRules(_ text: String, into profile: inout Profile) throws -> Int {
        let decoded = try decode(text)

        var proxyMap: [UUID: UUID] = [:]
        for proxy in decoded.proxies {
            if let existing = profile.proxies.first(where: {
                $0.host.caseInsensitiveCompare(proxy.host) == .orderedSame && $0.port == proxy.port && $0.type == proxy.type
            }) {
                proxyMap[proxy.id] = existing.id
            } else {
                var copy = proxy
                copy.id = UUID()
                profile.proxies.append(copy)
                proxyMap[proxy.id] = copy.id
            }
        }

        var chainMap: [UUID: UUID] = [:]
        for chain in decoded.chains {
            let members = chain.proxyIDs.compactMap { proxyMap[$0] }
            if let existing = profile.chains.first(where: { $0.name == chain.name && $0.proxyIDs == members }) {
                chainMap[chain.id] = existing.id
            } else {
                var copy = ProxyChain(name: chain.name)
                copy.proxyIDs = members
                profile.chains.append(copy)
                chainMap[chain.id] = copy.id
            }
        }

        var added = 0
        for var rule in decoded.rules where !rule.isDefault {
            rule.id = UUID()
            switch rule.action {
            case .proxy(let id): rule.action = proxyMap[id].map { .proxy($0) } ?? .direct
            case .chain(let id): rule.action = chainMap[id].map { .chain($0) } ?? .direct
            default: break
            }
            let defaultIndex = profile.rules.firstIndex { $0.isDefault } ?? profile.rules.count
            profile.rules.insert(rule, at: defaultIndex)
            added += 1
        }
        profile.normalizeRules()
        return added
    }
}

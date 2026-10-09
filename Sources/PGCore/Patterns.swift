import Foundation

/// What a single rule entry means, for validation and display in editors.
public enum PatternKind: String, Sendable {
    case domain = "Domain"
    case wildcard = "Wildcard"
    case ip = "IP address"
    case range = "IP range"
    case cidr = "Subnet"
    case port = "Port"
    case portRange = "Port range"
    case application = "Application"
    case invalid = "Invalid"
}

public enum Patterns {
    public static func split(_ text: String) -> [String] { splitList(text) }

    /// Joins entries back into rule text; names with spaces stay quoted.
    public static func join(_ entries: [String]) -> String {
        entries.map { $0.contains(" ") ? "\"\($0)\"" : $0 }.joined(separator: "; ")
    }

    public static func hostKind(_ entry: String) -> PatternKind {
        let e = entry.trimmingCharacters(in: .whitespaces)
        let dash = e.split(separator: "-", maxSplits: 1).map(String.init)
        if dash.count == 2, let lo = IPAddr(dash[0]), let hi = IPAddr(dash[1]) {
            return lo.isV4 == hi.isV4 && lo <= hi ? .range : .invalid
        }
        let slash = e.split(separator: "/", maxSplits: 1).map(String.init)
        if slash.count == 2, let ip = IPAddr(slash[0]) {
            guard let bits = Int(slash[1]), bits >= 0, bits <= (ip.isV4 ? 32 : 128) else { return .invalid }
            return .cidr
        }
        if IPAddr(e) != nil { return .ip }
        if e.lowercased() == "%computername%" { return .domain }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-._*?:")
        guard !e.isEmpty, e.lowercased().unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return .invalid }
        return e.contains("*") || e.contains("?") ? .wildcard : .domain
    }

    public static func portKind(_ entry: String) -> PatternKind {
        guard let range = CompiledRule.parsePorts(entry), range.lowerBound > 0 else { return .invalid }
        return range.count == 1 ? .port : .portRange
    }

    /// Registrable-ish domain: "ab.chatgpt.com" -> "chatgpt.com", "x.co.uk" -> "x.co.uk".
    public static func baseDomain(_ host: String) -> String {
        if IPAddr(host) != nil { return host }
        let labels = host.split(separator: ".")
        guard labels.count > 2 else { return host }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        let secondLevel: Set<String> = ["co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.jp", "com.br", "com.cn", "com.tr", "co.kr", "com.ua", "msk.ru", "spb.ru", "com.ru", "co.il", "co.in"]
        return labels.suffix(secondLevel.contains(lastTwo) ? 3 : 2).joined(separator: ".")
    }
}

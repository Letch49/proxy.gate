import Foundation

/// Finds rule targets that are "dead" because an earlier broad rule already covers them — e.g. a
/// `10.0.0.0/8` target shadowed by a dynamic AnyConnect `10.0.0.0/8` route pinned above it. The UI
/// marks those targets inactive (a red dot).
public enum RuleShadow {
    /// Host targets of the rule at `ruleIndex` that an earlier enabled, any-app/any-port rule covers.
    public static func shadowedHosts(in rules: [Rule], ruleIndex: Int) -> Set<String> {
        guard rules.indices.contains(ruleIndex) else { return [] }
        let targets = splitList(rules[ruleIndex].targetHosts)
        guard !targets.isEmpty else { return [] }
        // Only rules that apply to any app and any port can fully shadow a host target.
        let earlier = rules[0..<ruleIndex].filter {
            $0.enabled && isAny(splitList($0.applications)) && isAny(splitList($0.targetPorts))
        }
        let earlierHosts = earlier.flatMap { splitList($0.targetHosts) }.filter { $0.lowercased() != "any" }
        guard !earlierHosts.isEmpty else { return [] }
        var shadowed: Set<String> = []
        for target in targets where earlierHosts.contains(where: { covers($0, target) }) {
            shadowed.insert(target)
        }
        return shadowed
    }

    /// Whether host pattern `a` covers everything `b` matches.
    static func covers(_ a: String, _ b: String) -> Bool {
        if a.caseInsensitiveCompare(b) == .orderedSame { return true }
        // IP / CIDR / range: `a` covers `b` when its interval contains `b`'s interval.
        if let (aLo, aHi) = interval(a), let (bLo, bHi) = interval(b) {
            return aLo.isV4 == bLo.isV4 && aLo <= bLo && bHi <= aHi
        }
        // A wildcard host like "*.corp" covers a literal subdomain.
        let pattern = a.lowercased()
        if pattern.contains("*") || pattern.contains("?") { return globMatch(pattern, b.lowercased()) }
        return false
    }

    /// Low/high address of an IP, CIDR or `a-b` range; nil for hostnames and globs.
    private static func interval(_ s: String) -> (IPAddr, IPAddr)? {
        let range = s.split(separator: "-", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
        if range.count == 2, let lo = IPAddr(range[0]), let hi = IPAddr(range[1]), lo.isV4 == hi.isV4 {
            return (lo, hi)
        }
        let slash = s.split(separator: "/", maxSplits: 1).map(String.init)
        guard let first = slash.first, let base = IPAddr(first) else { return nil }
        let bits = slash.count == 2 ? (Int(slash[1]) ?? (base.isV4 ? 32 : 128)) : (base.isV4 ? 32 : 128)
        return cidrBounds(base, bits)
    }

    private static func cidrBounds(_ base: IPAddr, _ bits: Int) -> (IPAddr, IPAddr) {
        var lo = base.bytes, hi = base.bytes
        for index in lo.indices {
            for bit in 0..<8 where index * 8 + bit >= bits {
                let mask = UInt8(1 << (7 - bit))
                lo[index] &= ~mask
                hi[index] |= mask
            }
        }
        return (IPAddr(bytes: lo), IPAddr(bytes: hi))
    }
}

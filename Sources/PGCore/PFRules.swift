import Darwin
import Foundation

/// pf ruleset that sends every outgoing TCP connection to the local engine.
///
/// Packets leaving a real interface are `route-to`'d onto lo0, where `rdr` rewrites them to the
/// engine's listener. The engine itself connects from source ports in `reservedPorts`, which
/// the first `pass quick` rule lets through untouched — that is what prevents loops.
public enum PFRules {
    public static let anchor = "com.apple/proxygate"
    public static let reservedPorts: ClosedRange<UInt16> = 40000...48999
    public static let defaultBypass = [
        "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fe80::/10", "ff00::/8",
    ]

    /// Keeps only valid IPs / CIDRs, so user text never reaches pfctl verbatim.
    public static func validNetworks(_ text: String) -> [String] {
        splitList(text).compactMap { entry in
            let parts = entry.split(separator: "/", maxSplits: 1).map(String.init)
            guard let first = parts.first, let ip = IPAddr(first) else { return nil }
            if parts.count == 2 {
                guard let bits = Int(parts[1]), bits >= 0, bits <= (ip.isV4 ? 32 : 128) else { return nil }
                return "\(ip)/\(bits)"
            }
            return ip.description
        }
    }

    /// The Mac's own unicast addresses. Connections to them (e.g. Docker reaching a published port
    /// through the host IP) loop over lo0 and break when redirected, so they join the bypass table.
    public static func localAddresses() -> [String] {
        var result: [String] = []
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [] }
        defer { freeifaddrs(list) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            if let sa = entry.pointee.ifa_addr, let addr = SocketAddress(sockaddr: sa),
               !(addr.ip.bytes.count == 16 && addr.ip.bytes[0] == 0xFE && addr.ip.bytes[1] & 0xC0 == 0x80) {
                result.append(addr.ip.description)
            }
            cursor = entry.pointee.ifa_next
        }
        return Array(Set(result)).sorted()
    }

    public static func generate(listenPort: UInt16, captureIPv6: Bool, blockQUIC: Bool, bypass: [String], xrayUID: UInt32? = nil) -> String {
        let lo = reservedPorts.lowerBound - 1, hi = reservedPorts.upperBound + 1
        let table = (defaultBypass + bypass).joined(separator: ", ")
        var lines = [
            // Not const: the engine keeps the Mac's own addresses in it (see Engine.watchLocalAddresses).
            "table <pg_bypass> persist { \(table) }",
            "rdr pass on lo0 inet proto tcp from ! 127.0.0.0/8 port \(lo) <> \(hi) to ! <pg_bypass> -> 127.0.0.1 port \(listenPort)",
        ]
        if captureIPv6 {
            lines.append("rdr pass on lo0 inet6 proto tcp from ! ::1 port \(lo) <> \(hi) to ! <pg_bypass> -> ::1 port \(listenPort)")
        }
        // Filter rules must all follow the translation (rdr) rules above — pf enforces this order.
        if blockQUIC {
            lines.append("block return out quick proto udp from any to ! <pg_bypass> port 443")
        }
        if let xrayUID {
            // The Xray core runs as this uid; its outbound to the VPN server must leave untouched,
            // or it would be redirected back into the engine and loop. Same role as reservedPorts.
            lines.append("pass out quick proto tcp from any to any user \(xrayUID) keep state")
        }
        lines.append("pass out quick proto tcp from any port \(reservedPorts.lowerBound):\(reservedPorts.upperBound) to any keep state")
        lines.append("pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto tcp from any to ! <pg_bypass> keep state")
        if captureIPv6 {
            lines.append("pass out quick on ! lo0 route-to (lo0 ::1) inet6 proto tcp from any to ! <pg_bypass> keep state")
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

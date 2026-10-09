import Foundation
import PGCore

/// Checks that a sniffed hostname really points at the connection's destination IP.
///
/// Apps can put any name into SNI / Host (Telegram's obfuscation sends "www.google.com" to its own
/// servers). Passing such a name to the proxy would connect somewhere else entirely, so the proxy
/// only gets the name when it resolves to the address the app actually dialed.
final class HostVerifier: @unchecked Sendable {
    private let lock = NSLock()
    private var cache: [String: (ips: Set<IPAddr>, expires: Date)] = [:]
    private let ttl: TimeInterval = 300

    func resolves(_ host: String, to ip: IPAddr) -> Bool {
        let now = Date()
        if let entry = lock.withLock({ cache[host] }), entry.expires > now {
            return entry.ips.contains(ip)
        }
        let ips = Set(((try? SocketAddress.resolve(host: host, port: 0)) ?? []).map(\.ip))
        lock.withLock {
            if cache.count > 4000 { cache.removeAll() }
            cache[host] = (ips, now.addingTimeInterval(ttl))
        }
        return ips.contains(ip)
    }
}

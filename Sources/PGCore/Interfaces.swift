import Darwin
import Foundation

/// Network adapters that are up right now, by MAC. Proxies bound to an adapter are usable only
/// while it is up, and connections to them leave through it.
public enum NetInterfaces {
    /// MAC ("00:e0:4c:15:09:ee") → BSD name ("en8") of adapters that are up, running and have
    /// a routable address (not link-local / self-assigned).
    public static func active() -> [String: String] {
        var list: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&list) == 0, let first = list else { return [:] }
        defer { freeifaddrs(list) }
        var macs: [String: String] = [:]
        var addressed: Set<String> = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            cursor = entry.pointee.ifa_next
            let flags = Int32(entry.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_RUNNING != 0, let sa = entry.pointee.ifa_addr else { continue }
            let name = String(cString: entry.pointee.ifa_name)
            if Int32(sa.pointee.sa_family) == AF_LINK {
                if let mac = mac(sa) { macs[name] = mac }
            } else if let addr = SocketAddress(sockaddr: sa), isRoutable(addr.ip) {
                addressed.insert(name)
            }
        }
        var result: [String: String] = [:]
        for (name, mac) in macs where addressed.contains(name) {
            result[mac] = name
        }
        return result
    }

    private static func mac(_ sa: UnsafeMutablePointer<sockaddr>) -> String? {
        sa.withMemoryRebound(to: sockaddr_dl.self, capacity: 1) { dl -> String? in
            let len = Int(dl.pointee.sdl_alen)
            guard len == 6 else { return nil }
            let offset = MemoryLayout<sockaddr_dl>.offset(of: \sockaddr_dl.sdl_data)! + Int(dl.pointee.sdl_nlen)
            let bytes = UnsafeRawPointer(dl).advanced(by: offset).assumingMemoryBound(to: UInt8.self)
            let mac = (0..<len).map { String(format: "%02x", bytes[$0]) }.joined(separator: ":")
            return mac == "00:00:00:00:00:00" ? nil : mac
        }
    }

    private static func isRoutable(_ ip: IPAddr) -> Bool {
        let b = ip.bytes
        if ip.isV4 {
            return !(b[0] == 127 || (b[0] == 169 && b[1] == 254))
        }
        return b[0] & 0xE0 == 0x20 || b[0] & 0xFE == 0xFC
    }
}

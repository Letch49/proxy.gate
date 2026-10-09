import Foundation

/// Plain HTTP through an HTTP proxy without CONNECT ("GET http://host/path"), the way browsers
/// talk to a forward proxy. Needed because many corporate proxies allow CONNECT to port 443 only.
public enum HTTPForward {
    private static let dropped: Set<String> = ["connection", "proxy-connection", "keep-alive", "proxy-authorization"]

    /// Rewrites the first request of a client connection for a forward proxy. Returns nil when
    /// `data` does not start with a complete HTTP request head.
    ///
    /// The request gets `Connection: close`, so the client opens a new connection for its next
    /// request and only one request head per connection ever needs rewriting.
    public static func rewrite(_ data: [UInt8], host: String, port: UInt16, proxy: ProxyServer) -> [UInt8]? {
        guard let end = headEnd(data) else { return nil }
        var lines = String(decoding: data[0..<end], as: UTF8.self).components(separatedBy: "\r\n")
        let parts = lines[0].split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/1.") else { return nil }

        var target = parts[1]
        if target.hasPrefix("/") {
            let name = ProxyTarget(host: host, port: port).authority
            target = "http://" + (port == 80 ? String(name.dropLast(3)) : name) + target
        } else if !target.lowercased().hasPrefix("http://") {
            return nil
        }
        lines[0] = "\(parts[0]) \(target) \(parts[2])"

        var out = [lines[0]]
        for line in lines.dropFirst() where !line.isEmpty {
            let name = line.split(separator: ":", maxSplits: 1).first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            if !dropped.contains(name) {
                out.append(line)
            }
        }
        out.append("Connection: close")
        out.append("Proxy-Connection: close")
        if proxy.useAuth {
            out.append("Proxy-Authorization: Basic " + Data("\(proxy.username):\(proxy.password)".utf8).base64EncodedString())
        }
        return Array((out.joined(separator: "\r\n") + "\r\n\r\n").utf8) + data[(end + 4)...]
    }

    private static func headEnd(_ d: [UInt8]) -> Int? {
        guard d.count >= 4 else { return nil }
        for i in 0...(d.count - 4) where d[i] == 13 && d[i + 1] == 10 && d[i + 2] == 13 && d[i + 3] == 10 {
            return i
        }
        return nil
    }
}

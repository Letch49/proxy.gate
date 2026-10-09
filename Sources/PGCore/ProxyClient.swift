import Foundation

public struct ProxyTarget: Hashable, Sendable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    /// "host:port", IPv6 literals in brackets.
    public var authority: String {
        if let ip = IPAddr(host), !ip.isV4 {
            return "[\(ip)]:\(port)"
        }
        return "\(host):\(port)"
    }
}

/// The proxy answered but refused the target (HTTP 403/405…, SOCKS "not allowed").
/// Distinguished from network errors so the engine can stop retrying a forbidden port.
public struct ProxyRefusedError: Error, CustomStringConvertible, Sendable {
    public let code: Int
    public let description: String

    public init(code: Int, description: String) {
        self.code = code
        self.description = description
    }
}

public enum ProxyClient {
    /// Opens a tunnel to `target` through `chain` (one or more proxies).
    /// Returns the stream plus any bytes the last proxy sent past its handshake.
    public static func connect(through chain: [ProxyServer], to target: ProxyTarget, timeoutMs: Int, bindPorts: ClosedRange<UInt16>? = nil) throws -> (TCPStream, [UInt8]) {
        guard let first = chain.first else { throw NetError("empty proxy chain") }
        let stream: TCPStream
        do {
            stream = try open(first, timeoutMs: timeoutMs, bindPorts: bindPorts)
        } catch {
            throw NetError("Could not connect to proxy \(first.title) - \(error)")
        }
        var leftover: [UInt8] = []
        for (i, proxy) in chain.enumerated() {
            let next = i + 1 < chain.count ? ProxyTarget(host: chain[i + 1].host, port: chain[i + 1].port) : target
            do {
                leftover = try handshake(stream, via: proxy, to: next, timeoutMs: timeoutMs)
            } catch let refused as ProxyRefusedError {
                stream.abort()
                throw ProxyRefusedError(code: refused.code, description: "Could not connect through proxy \(proxy.title) - \(refused.description)")
            } catch {
                stream.abort()
                throw NetError("Could not connect through proxy \(proxy.title) - \(error)")
            }
        }
        return (stream, leftover)
    }

    /// TCP connection to the proxy itself, through its bound adapter if it has one.
    public static func open(_ proxy: ProxyServer, timeoutMs: Int, bindPorts: ClosedRange<UInt16>? = nil) throws -> TCPStream {
        var interface: String?
        if let mac = proxy.interfaceMAC {
            guard let name = NetInterfaces.active()[mac] else {
                throw NetError("network interface \(proxy.interfaceName ?? mac) is not connected")
            }
            interface = name
        }
        let addrs = try SocketAddress.resolve(host: proxy.host, port: proxy.port)
        return try TCPStream.connect(to: addrs, timeoutMs: timeoutMs, bindPorts: bindPorts, interface: interface)
    }

    /// Verifies a proxy by opening a tunnel to www.google.com:443 — the one port every proxy allows
    /// (many corporate proxies refuse CONNECT to anything else).
    public static func check(_ proxy: ProxyServer, timeoutMs: Int = 10000) throws -> String {
        let started = Date()
        let (stream, _) = try connect(through: [proxy], to: ProxyTarget(host: "www.google.com", port: 443), timeoutMs: timeoutMs)
        stream.close()
        let ms = Int(Date().timeIntervalSince(started) * 1000)
        return "OK in \(ms) ms (tunnel to www.google.com:443)"
    }

    public static func handshake(_ s: TCPStream, via proxy: ProxyServer, to target: ProxyTarget, timeoutMs: Int) throws -> [UInt8] {
        s.setTimeout(ms: timeoutMs)
        defer { s.setTimeout(ms: 0) }
        switch proxy.type {
        case .https:
            return try httpConnect(s, proxy: proxy, target: target)
        case .socks5:
            try socks5(s, proxy: proxy, target: target)
            return []
        case .socks4:
            try socks4(s, proxy: proxy, target: target)
            return []
        }
    }

    private static func httpConnect(_ s: TCPStream, proxy: ProxyServer, target: ProxyTarget) throws -> [UInt8] {
        let authority = target.authority
        var request = "CONNECT \(authority) HTTP/1.1\r\nHost: \(authority)\r\n"
        if proxy.useAuth {
            let token = Data("\(proxy.username):\(proxy.password)".utf8).base64EncodedString()
            request += "Proxy-Authorization: Basic \(token)\r\n"
        }
        request += "User-Agent: ProxyGate\r\nProxy-Connection: keep-alive\r\n\r\n"
        try s.writeAll(Array(request.utf8))

        var buffer: [UInt8] = []
        let terminator: [UInt8] = [13, 10, 13, 10]
        while true {
            let chunk = try s.readSome(max: 4096)
            if chunk.isEmpty {
                throw NetError("proxy closed the connection")
            }
            let searchFrom = max(0, buffer.count - 3)
            buffer += chunk
            if let end = find(terminator, in: buffer, from: searchFrom) {
                let header = String(decoding: buffer[0..<end], as: UTF8.self)
                let statusLine = header.components(separatedBy: "\r\n").first ?? ""
                let parts = statusLine.split(separator: " ", maxSplits: 2)
                guard parts.count >= 2, parts[0].hasPrefix("HTTP/"), let code = Int(parts[1]) else {
                    throw NetError("invalid proxy response: \(statusLine)")
                }
                if code == 407 {
                    throw NetError("proxy authentication required (407)")
                }
                guard (200..<300).contains(code) else {
                    throw ProxyRefusedError(code: code, description: "Proxy server cannot establish a connection with the target, status code \(code)")
                }
                return Array(buffer[(end + 4)...])
            }
            if buffer.count > 65536 {
                throw NetError("proxy response header too large")
            }
        }
    }

    private static func socks5(_ s: TCPStream, proxy: ProxyServer, target: ProxyTarget) throws {
        let methods: [UInt8] = proxy.useAuth ? [0x00, 0x02] : [0x00]
        try s.writeAll([5, UInt8(methods.count)] + methods)
        let greeting = try s.readExactly(2)
        guard greeting[0] == 5 else { throw NetError("not a SOCKS5 proxy") }
        switch greeting[1] {
        case 0x00:
            break
        case 0x02:
            let user = Array(proxy.username.utf8), pass = Array(proxy.password.utf8)
            guard user.count <= 255, pass.count <= 255 else { throw NetError("credentials too long") }
            try s.writeAll([1, UInt8(user.count)] + user + [UInt8(pass.count)] + pass)
            let reply = try s.readExactly(2)
            guard reply[1] == 0 else { throw NetError("SOCKS5 authentication failed") }
        case 0xFF:
            throw NetError("SOCKS5 proxy rejected all authentication methods")
        default:
            throw NetError("SOCKS5 proxy chose unsupported method \(greeting[1])")
        }

        var request: [UInt8] = [5, 1, 0]
        if let ip = IPAddr(target.host) {
            request += (ip.isV4 ? [1] : [4]) + ip.bytes
        } else {
            let host = Array(target.host.utf8)
            guard host.count <= 255 else { throw NetError("hostname too long") }
            request += [3, UInt8(host.count)] + host
        }
        request += [UInt8(target.port >> 8), UInt8(target.port & 0xFF)]
        try s.writeAll(request)

        let head = try s.readExactly(4)
        guard head[0] == 5 else { throw NetError("invalid SOCKS5 reply") }
        guard head[1] == 0 else {
            if head[1] == 2 {
                throw ProxyRefusedError(code: 2, description: "SOCKS5: \(socks5Error(2))")
            }
            throw NetError("SOCKS5: \(socks5Error(head[1]))")
        }
        switch head[3] {
        case 1: _ = try s.readExactly(4 + 2)
        case 4: _ = try s.readExactly(16 + 2)
        case 3:
            let len = try s.readExactly(1)[0]
            _ = try s.readExactly(Int(len) + 2)
        default:
            throw NetError("invalid SOCKS5 address type \(head[3])")
        }
    }

    private static func socks5Error(_ code: UInt8) -> String {
        switch code {
        case 1: return "general failure"
        case 2: return "connection not allowed by ruleset"
        case 3: return "network unreachable"
        case 4: return "host unreachable"
        case 5: return "connection refused"
        case 6: return "TTL expired"
        case 7: return "command not supported"
        case 8: return "address type not supported"
        default: return "error \(code)"
        }
    }

    private static func socks4(_ s: TCPStream, proxy: ProxyServer, target: ProxyTarget) throws {
        var request: [UInt8] = [4, 1, UInt8(target.port >> 8), UInt8(target.port & 0xFF)]
        let user = Array((proxy.useAuth ? proxy.username : "").utf8)
        if let ip = IPAddr(target.host) {
            guard ip.isV4 else { throw NetError("SOCKS4 does not support IPv6") }
            request += ip.bytes + user + [0]
        } else {
            // SOCKS4a: hostname resolved by the proxy.
            request += [0, 0, 0, 1] + user + [0] + Array(target.host.utf8) + [0]
        }
        try s.writeAll(request)
        let reply = try s.readExactly(8)
        guard reply[1] == 0x5A else {
            throw NetError("SOCKS4 request rejected (code \(reply[1]))")
        }
    }

    private static func find(_ needle: [UInt8], in haystack: [UInt8], from start: Int) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        var i = start
        while i + needle.count <= haystack.count {
            if haystack[i] == needle[0] && Array(haystack[i..<(i + needle.count)]) == needle {
                return i
            }
            i += 1
        }
        return nil
    }
}

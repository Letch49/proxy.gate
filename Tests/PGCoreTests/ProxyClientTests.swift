import Darwin
import Foundation
import Testing
@testable import PGCore

/// Minimal proxy server: performs the server side of a handshake, then either tunnels
/// to 127.0.0.1 targets (so chains work) or answers any request with an HTTP 200.
private final class FakeProxy: @unchecked Sendable {
    let type: ProxyType
    let credentials: (String, String)?
    let port: UInt16
    private let fd: Int32
    private(set) var targets: [String] = []
    private let lock = NSLock()

    init(_ type: ProxyType, credentials: (String, String)? = nil) throws {
        self.type = type
        self.credentials = credentials
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        var one: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, 4)
        let addr = SocketAddress(ip: IPAddr("127.0.0.1")!, port: 0)
        guard addr.withSockaddr({ bind(sock, $0, $1) }) == 0, listen(sock, 16) == 0 else { throw NetError.errno("listen") }
        fd = sock
        port = SocketAddress.local(of: sock)!.port
        Thread { [self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { return }
                Thread { [self] in serve(TCPStream(fd: c)) }.start()
            }
        }.start()
    }

    var server: ProxyServer {
        var p = ProxyServer(host: "127.0.0.1", port: port, type: type)
        if let (u, pw) = credentials {
            p.useAuth = true
            p.username = u
            p.password = pw
        }
        return p
    }

    private func serve(_ s: TCPStream) {
        defer { s.close() }
        guard let target = try? handshake(s) else { return }
        lock.withLock { targets.append(target.authority) }
        if target.host == "127.0.0.1",
           let up = try? TCPStream.connect(to: [SocketAddress(ip: IPAddr("127.0.0.1")!, port: target.port)], timeoutMs: 2000) {
            let t = Thread { Self.copy(up, s) }
            t.start()
            Self.copy(s, up)
            Thread.sleep(forTimeInterval: 0.2)
            up.close()
            return
        }
        _ = try? s.readSome()
        try? s.writeAll(Array("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".utf8))
    }

    private static func copy(_ from: TCPStream, _ to: TCPStream) {
        while let chunk = try? from.readSome(), !chunk.isEmpty {
            try? to.writeAll(chunk)
        }
        to.shutdownWrite()
    }

    private func handshake(_ s: TCPStream) throws -> ProxyTarget {
        switch type {
        case .https:
            var head: [UInt8] = []
            while !String(decoding: head, as: UTF8.self).hasSuffix("\r\n\r\n") {
                head += try s.readExactly(1)
            }
            let text = String(decoding: head, as: UTF8.self)
            if let (u, p) = credentials {
                let token = Data("\(u):\(p)".utf8).base64EncodedString()
                guard text.contains("Proxy-Authorization: Basic \(token)") else {
                    try s.writeAll(Array("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".utf8))
                    throw NetError("auth")
                }
            }
            let authority = text.split(separator: " ")[1]
            let colon = authority.lastIndex(of: ":")!
            // Like a corporate Squid: CONNECT only to "SSL ports".
            if authority.hasSuffix(":5228") {
                try s.writeAll(Array("HTTP/1.1 403 Forbidden\r\n\r\n".utf8))
                throw NetError("denied")
            }
            try s.writeAll(Array("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
            return ProxyTarget(host: String(authority[..<colon]), port: UInt16(authority[authority.index(after: colon)...])!)
        case .socks5:
            let greeting = try s.readExactly(2)
            let methods = try s.readExactly(Int(greeting[1]))
            if let (u, p) = credentials {
                guard methods.contains(2) else { throw NetError("no auth offered") }
                try s.writeAll([5, 2])
                let ulen = try s.readExactly(2)[1]
                let user = try s.readExactly(Int(ulen))
                let plen = try s.readExactly(1)[0]
                let pass = try s.readExactly(Int(plen))
                let ok = String(decoding: user, as: UTF8.self) == u && String(decoding: pass, as: UTF8.self) == p
                try s.writeAll([1, ok ? 0 : 1])
                guard ok else { throw NetError("auth") }
            } else {
                try s.writeAll([5, 0])
            }
            let req = try s.readExactly(4)
            let host: String
            switch req[3] {
            case 1: host = IPAddr(bytes: try s.readExactly(4)).description
            case 3: host = String(decoding: try s.readExactly(Int(try s.readExactly(1)[0])), as: UTF8.self)
            default: host = IPAddr(bytes: try s.readExactly(16)).description
            }
            let port = try s.readExactly(2)
            try s.writeAll([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            return ProxyTarget(host: host, port: UInt16(port[0]) << 8 | UInt16(port[1]))
        case .socks4:
            let head = try s.readExactly(8)
            var rest: [UInt8] = []
            var zeros = 0
            let isA = head[4] == 0 && head[5] == 0 && head[6] == 0
            while zeros < (isA ? 2 : 1) {
                let b = try s.readExactly(1)[0]
                if b == 0 { zeros += 1 }
                rest.append(b)
            }
            try s.writeAll([0, 0x5A, 0, 0, 0, 0, 0, 0])
            let host = isA
                ? String(decoding: rest.split(separator: 0, omittingEmptySubsequences: false)[1], as: UTF8.self)
                : IPAddr(bytes: Array(head[4..<8])).description
            return ProxyTarget(host: host, port: UInt16(head[2]) << 8 | UInt16(head[3]))
        }
    }
}

@Test func httpsProxyWithAuth() throws {
    let proxy = try FakeProxy(.https, credentials: ("user", "secret"))
    #expect(try ProxyClient.check(proxy.server, timeoutMs: 2000).hasPrefix("OK"))
    var wrong = proxy.server
    wrong.password = "nope"
    #expect(throws: NetError.self) { try ProxyClient.check(wrong, timeoutMs: 2000) }
}

@Test func socks5WithAuthSendsHostname() throws {
    let proxy = try FakeProxy(.socks5, credentials: ("u", "p"))
    #expect(try ProxyClient.check(proxy.server, timeoutMs: 2000).hasPrefix("OK"))
    #expect(proxy.targets == ["www.google.com:443"])
}

@Test func socks4a() throws {
    let proxy = try FakeProxy(.socks4)
    #expect(try ProxyClient.check(proxy.server, timeoutMs: 2000).hasPrefix("OK"))
    #expect(proxy.targets == ["www.google.com:443"])
}

@Test func proxyChain() throws {
    let first = try FakeProxy(.socks5)
    let second = try FakeProxy(.https)
    let (stream, leftover) = try ProxyClient.connect(
        through: [first.server, second.server],
        to: ProxyTarget(host: "example.com", port: 443), timeoutMs: 2000)
    defer { stream.close() }
    #expect(leftover.isEmpty)
    try stream.writeAll(Array("ping".utf8))
    stream.setTimeout(ms: 2000)
    let reply = String(decoding: try stream.readSome(), as: UTF8.self)
    #expect(reply.hasPrefix("HTTP/1.1 200"))
    #expect(first.targets == ["127.0.0.1:\(second.port)"])
    #expect(second.targets == ["example.com:443"])
}

@Test func unreachableProxyReportsError() {
    let dead = ProxyServer(host: "127.0.0.1", port: 1, type: .https)
    #expect(throws: NetError.self) { try ProxyClient.check(dead, timeoutMs: 1000) }
}

@Test func refusedPortIsTyped() throws {
    let proxy = try FakeProxy(.https)
    #expect(throws: ProxyRefusedError.self) {
        _ = try ProxyClient.connect(through: [proxy.server], to: ProxyTarget(host: "mtalk.google.com", port: 5228), timeoutMs: 2000)
    }
    do {
        _ = try ProxyClient.connect(through: [proxy.server], to: ProxyTarget(host: "mtalk.google.com", port: 5228), timeoutMs: 2000)
    } catch let e as ProxyRefusedError {
        #expect(e.code == 403)
        #expect(e.description.contains("status code 403"))
    }
}

@Test func httpForwardRewrite() {
    var proxy = ProxyServer(host: "192.0.2.10", port: 3128, type: .https)
    proxy.useAuth = true
    proxy.username = "u"
    proxy.password = "p"
    let request = Array("GET /search?q=1 HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\nBODY".utf8)
    let out = String(decoding: HTTPForward.rewrite(request, host: "www.google.com", port: 80, proxy: proxy)!, as: UTF8.self)
    #expect(out.hasPrefix("GET http://www.google.com/search?q=1 HTTP/1.1\r\n"))
    #expect(out.contains("Accept: */*\r\n"))
    #expect(!out.contains("keep-alive"))
    #expect(out.contains("Connection: close\r\n"))
    #expect(out.contains("Proxy-Authorization: Basic dTpw\r\n"))
    #expect(out.hasSuffix("\r\n\r\nBODY"))

    let other = String(decoding: HTTPForward.rewrite(Array("POST /x HTTP/1.1\r\nHost: a\r\n\r\n".utf8), host: "a.example", port: 8080, proxy: ProxyServer(host: "p", port: 1, type: .https))!, as: UTF8.self)
    #expect(other.hasPrefix("POST http://a.example:8080/x HTTP/1.1"))

    #expect(HTTPForward.rewrite(Array("GET / HTTP/1.1\r\nHost: a".utf8), host: "a", port: 80, proxy: proxy) == nil)
    #expect(HTTPForward.rewrite([0x16, 3, 1, 0, 5], host: "a", port: 80, proxy: proxy) == nil)
}

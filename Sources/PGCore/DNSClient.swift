import Darwin
import Foundation
import Network

/// Talks to a DNS provider directly (UDP or DoH), never through the system resolver. Used by the
/// engine's local stub and by the diagnostics, so a broken system DNS cannot skew either.
public enum DNSClient {
    /// Sends one query and returns the raw response. Tries the provider's addresses in order within
    /// the overall `timeoutMs`. `bindPorts` puts the DoH socket in pf's pass range, so the engine's
    /// own lookups are never redirected back into itself while interception is on.
    public static func exchange(_ query: [UInt8], upstream: DNSUpstream, timeoutMs: Int,
                                bindPorts: ClosedRange<UInt16>? = nil) throws -> [UInt8] {
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        var lastError: Error = NetError("no resolver address")
        for ip in upstream.provider.ips {
            let left = Int(deadline.timeIntervalSinceNow * 1000)
            guard left > 50 else { throw DNSClientError.timeout }
            do {
                switch upstream.transport {
                case .udp:
                    return try udp(query, server: ip, timeoutMs: left)
                case .doh:
                    guard let url = upstream.provider.dohURL.flatMap(DoHEndpoint.init) else {
                        throw NetError("provider has no DoH address")
                    }
                    return try doh(query, endpoint: url, server: ip, timeoutMs: left, bindPorts: bindPorts)
                }
            } catch {
                lastError = error
            }
        }
        throw lastError
    }

    /// A and AAAA for `host` through `upstream`, merged into one outcome.
    public static func lookup(_ host: String, upstream: DNSUpstream, timeoutMs: Int,
                              bindPorts: ClosedRange<UInt16>? = nil) -> DNSOutcome {
        func one(_ type: DNSRecordType) -> DNSOutcome {
            guard let q = DNSMessage.query(name: host, type: type, id: UInt16.random(in: 1...0xFFFF)) else {
                return DNSOutcome(status: .failed, detail: "invalid name")
            }
            do {
                let raw = try exchange(q, upstream: upstream, timeoutMs: timeoutMs, bindPorts: bindPorts)
                guard let r = DNSMessage.parse(raw) else { return DNSOutcome(status: .failed, detail: "malformed answer") }
                return DNSOutcome.from(r)
            } catch DNSClientError.timeout {
                return DNSOutcome(status: .timeout)
            } catch {
                return DNSOutcome(status: .failed, detail: "\(error)")
            }
        }
        // Both families in parallel: the slower of the two bounds the wait, not their sum.
        var aaaa = DNSOutcome(status: .timeout)
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            aaaa = one(.aaaa)
            done.signal()
        }
        let a = one(.a)
        done.wait()
        return DNSOutcome.merge(a, aaaa)
    }

    /// The Mac's own resolver (getaddrinfo), bounded by `timeoutMs`. A hung lookup is abandoned,
    /// not cancelled: getaddrinfo has no cancel, the worker finishes on its own.
    public static func systemLookup(_ host: String, timeoutMs: Int) -> DNSOutcome {
        final class Box: @unchecked Sendable { var outcome = DNSOutcome(status: .timeout) }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        Thread {
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            var res: UnsafeMutablePointer<addrinfo>?
            let rc = getaddrinfo(host, nil, &hints, &res)
            if rc == 0, let first = res {
                var ips: [IPAddr] = []
                var cursor: UnsafeMutablePointer<addrinfo>? = first
                while let ai = cursor {
                    if let sa = ai.pointee.ai_addr, let addr = SocketAddress(sockaddr: sa), !ips.contains(addr.ip) {
                        ips.append(addr.ip)
                    }
                    cursor = ai.pointee.ai_next
                }
                freeaddrinfo(first)
                box.outcome = ips.isEmpty ? DNSOutcome(status: .noData) : DNSOutcome(status: .ok, addresses: ips.map(\.description))
            } else {
                box.outcome = DNSOutcome.fromGAI(rc)
            }
            done.signal()
        }.start()
        guard done.wait(timeout: .now() + .milliseconds(timeoutMs)) == .success else {
            return DNSOutcome(status: .timeout)
        }
        return box.outcome
    }

    // MARK: - UDP

    static func udp(_ query: [UInt8], server: IPAddr, timeoutMs: Int) throws -> [UInt8] {
        let addr = SocketAddress(ip: server, port: 53)
        let fd = socket(server.isV4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard fd >= 0 else { throw NetError.errno("socket") }
        defer { Darwin.close(fd) }
        guard addr.withSockaddr({ Darwin.connect(fd, $0, $1) }) == 0 else { throw NetError.errno("connect \(addr)") }
        guard query.withUnsafeBytes({ send(fd, $0.baseAddress, $0.count, 0) }) == query.count else {
            throw NetError.errno("send \(addr)")
        }
        let wantID = DNSMessage.id(of: query)
        let deadline = Date().addingTimeInterval(Double(timeoutMs) / 1000)
        var buf = [UInt8](repeating: 0, count: 4096)
        while true {
            let left = Int32(deadline.timeIntervalSinceNow * 1000)
            guard left > 0 else { throw DNSClientError.timeout }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let r = poll(&p, 1, left)
            if r < 0, errno == EINTR { continue }
            guard r > 0 else { throw DNSClientError.timeout }
            let n = buf.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            guard n > 0 else { throw NetError.errno("recv \(addr)") }
            let reply = Array(buf[0..<n])
            // A spoofed or stale datagram with another id is ignored, not trusted.
            if DNSMessage.id(of: reply) == wantID { return reply }
        }
    }

    // MARK: - DoH (RFC 8484, POST over HTTP/1.1)

    static func doh(_ query: [UInt8], endpoint: DoHEndpoint, server: IPAddr, timeoutMs: Int,
                    bindPorts: ClosedRange<UInt16>?) throws -> [UInt8] {
        let tls = NWProtocolTLS.Options()
        // Connect to the bootstrap IP but present and verify the provider's own name.
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, endpoint.host)
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = max(1, timeoutMs / 1000)
        tcp.noDelay = true
        let params = NWParameters(tls: tls, tcp: tcp)
        if let bindPorts {
            let port = UInt16.random(in: bindPorts)
            params.requiredLocalEndpoint = .hostPort(host: server.isV4 ? "0.0.0.0" : "::", port: NWEndpoint.Port(rawValue: port)!)
            params.allowLocalEndpointReuse = true
        }
        let conn = NWConnection(host: NWEndpoint.Host(server.description), port: NWEndpoint.Port(rawValue: endpoint.port)!, using: params)
        let queue = DispatchQueue(label: "proxygate.doh")
        defer { conn.cancel() }
        let deadline = DispatchTime.now() + .milliseconds(timeoutMs)

        let ready = DispatchSemaphore(value: 0)
        final class State: @unchecked Sendable { var error: Error?; var signalled = false }
        let state = State()
        conn.stateUpdateHandler = { s in
            switch s {
            case .ready:
                if !state.signalled { state.signalled = true; ready.signal() }
            case .failed(let e), .waiting(let e):
                if !state.signalled { state.signalled = true; state.error = e; ready.signal() }
            default:
                break
            }
        }
        conn.start(queue: queue)
        guard ready.wait(timeout: deadline) == .success else { throw DNSClientError.timeout }
        if let error = queue.sync(execute: { state.error }) { throw DNSClientError.transport("\(error)") }

        let request = DoHHTTP.request(host: endpoint.host, port: endpoint.port, path: endpoint.path, body: query)
        let sent = DispatchSemaphore(value: 0)
        conn.send(content: Data(request), completion: .contentProcessed { e in
            if let e { queue.async { state.error = e } }
            sent.signal()
        })
        guard sent.wait(timeout: deadline) == .success else { throw DNSClientError.timeout }

        var buffer: [UInt8] = []
        while true {
            let got = DispatchSemaphore(value: 0)
            final class Chunk: @unchecked Sendable { var data: [UInt8] = []; var done = false; var error: Error? }
            let chunk = Chunk()
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                chunk.data = data.map { [UInt8]($0) } ?? []
                chunk.done = complete
                chunk.error = error
                got.signal()
            }
            guard got.wait(timeout: deadline) == .success else { throw DNSClientError.timeout }
            buffer += chunk.data
            guard buffer.count <= 65536 + 4096 else { throw DNSClientError.transport("DoH answer too large") }
            switch DoHHTTP.parse(buffer, complete: chunk.done || chunk.error != nil) {
            case .complete(let status, let body):
                guard status == 200 else { throw DNSClientError.transport("DoH HTTP \(status)") }
                return body
            case .invalid:
                throw DNSClientError.transport("bad DoH response")
            case .incomplete:
                if let e = chunk.error { throw DNSClientError.transport("\(e)") }
                if chunk.done { throw DNSClientError.transport("DoH connection closed early") }
            }
        }
    }
}

public enum DNSClientError: Error, CustomStringConvertible {
    case timeout
    case transport(String)

    public var description: String {
        switch self {
        case .timeout: return "timed out"
        case .transport(let s): return s
        }
    }
}

/// Minimal HTTP/1.1 framing for DoH: one POST per connection, Content-Length or chunked replies.
public enum DoHHTTP {
    public enum Parsed: Equatable {
        case incomplete
        case invalid
        case complete(status: Int, body: [UInt8])
    }

    public static func request(host: String, port: UInt16, path: String, body: [UInt8]) -> [UInt8] {
        let authority = port == 443 ? host : "\(host):\(port)"
        let head = "POST \(path) HTTP/1.1\r\nHost: \(authority)\r\nContent-Type: application/dns-message\r\n"
            + "Accept: application/dns-message\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        return Array(head.utf8) + body
    }

    /// `complete` = the peer closed the stream, so a body without a length ends here.
    public static func parse(_ bytes: [UInt8], complete: Bool) -> Parsed {
        guard let end = find(bytes, [13, 10, 13, 10]) else {
            return bytes.count > 16384 ? .invalid : .incomplete
        }
        let head = String(decoding: bytes[0..<end], as: UTF8.self)
        let lines = head.components(separatedBy: "\r\n")
        let statusParts = lines.first?.split(separator: " ") ?? []
        guard statusParts.count >= 2, statusParts[0].hasPrefix("HTTP/1."), let status = Int(statusParts[1]) else {
            return .invalid
        }
        var length: Int?
        var chunked = false
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if name == "content-length" { length = Int(value) }
            if name == "transfer-encoding", value.lowercased().contains("chunked") { chunked = true }
        }
        let body = Array(bytes[(end + 4)...])
        if chunked {
            switch dechunk(body) {
            case .some(let decoded): return .complete(status: status, body: decoded)
            case .none: return complete ? .invalid : .incomplete
            }
        }
        if let length {
            guard length >= 0, length <= 65535 else { return .invalid }
            if body.count >= length { return .complete(status: status, body: Array(body[0..<length])) }
            return complete ? .invalid : .incomplete
        }
        return complete ? .complete(status: status, body: body) : .incomplete
    }

    /// Decodes a complete chunked body, nil while the terminating chunk has not arrived.
    static func dechunk(_ body: [UInt8]) -> [UInt8]? {
        var out: [UInt8] = []
        var i = 0
        while true {
            guard let lineEnd = find(body, [13, 10], from: i) else { return nil }
            let sizeText = String(decoding: body[i..<lineEnd], as: UTF8.self).split(separator: ";").first ?? ""
            guard let size = Int(sizeText.trimmingCharacters(in: .whitespaces), radix: 16), size >= 0, size <= 65535 else { return nil }
            i = lineEnd + 2
            if size == 0 { return out }
            guard i + size + 2 <= body.count else { return nil }
            out += body[i..<(i + size)]
            i += size + 2
        }
    }

    static func find(_ bytes: [UInt8], _ needle: [UInt8], from start: Int = 0) -> Int? {
        guard bytes.count >= needle.count, start <= bytes.count - needle.count else { return nil }
        for i in start...(bytes.count - needle.count) where bytes[i] == needle[0] {
            if Array(bytes[i..<(i + needle.count)]) == needle { return i }
        }
        return nil
    }
}

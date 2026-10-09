import Darwin
import Foundation

public struct NetError: Error, CustomStringConvertible, Sendable {
    public let description: String

    public init(_ message: String) {
        description = message
    }

    public static func errno(_ op: String, _ code: Int32 = Darwin.errno) -> NetError {
        if code == EAGAIN {
            return NetError("\(op): timed out")
        }
        return NetError("\(op): \(String(cString: strerror(code)))")
    }
}

public struct IPAddr: Hashable, Comparable, Sendable, CustomStringConvertible {
    /// 4 bytes for IPv4, 16 for IPv6. IPv4-mapped IPv6 addresses are normalized to IPv4.
    public let bytes: [UInt8]

    public init(bytes: [UInt8]) {
        if bytes.count == 16, bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            self.bytes = Array(bytes[12...])
        } else {
            self.bytes = bytes
        }
    }

    public init?(_ string: String) {
        var s = string.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("["), s.hasSuffix("]") {
            s = String(s.dropFirst().dropLast())
        }
        if let zone = s.firstIndex(of: "%") {
            s = String(s[..<zone])
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, s, &v4) == 1 {
            self.init(bytes: withUnsafeBytes(of: v4) { Array($0) })
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, s, &v6) == 1 {
            self.init(bytes: withUnsafeBytes(of: v6) { Array($0) })
            return
        }
        return nil
    }

    public var isV4: Bool { bytes.count == 4 }

    /// Loopback, link-local, private (RFC1918) or ULA — never needs DPI bypass or a tunnel.
    public var isPrivate: Bool {
        let b = bytes
        if isV4 {
            return b[0] == 10
                || b[0] == 127
                || (b[0] == 172 && b[1] & 0xF0 == 16)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
        }
        if b == [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1] { return true }   // ::1
        return b[0] & 0xFE == 0xFC || (b[0] == 0xFE && b[1] & 0xC0 == 0x80)  // fc00::/7, fe80::/10
    }

    public var description: String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        bytes.withUnsafeBytes { p in
            _ = inet_ntop(isV4 ? AF_INET : AF_INET6, p.baseAddress, &buf, socklen_t(buf.count))
        }
        return String(cString: buf)
    }

    public static func < (a: IPAddr, b: IPAddr) -> Bool {
        if a.bytes.count != b.bytes.count {
            return a.bytes.count < b.bytes.count
        }
        return a.bytes.lexicographicallyPrecedes(b.bytes)
    }

    /// True when the first `prefix` bits of both addresses are equal.
    public func sharesPrefix(with other: IPAddr, bits prefix: Int) -> Bool {
        guard bytes.count == other.bytes.count else { return false }
        var remaining = max(0, min(prefix, bytes.count * 8))
        var i = 0
        while remaining >= 8 {
            if bytes[i] != other.bytes[i] { return false }
            remaining -= 8
            i += 1
        }
        if remaining > 0 {
            let mask = UInt8(0xFF) << (8 - remaining)
            return bytes[i] & mask == other.bytes[i] & mask
        }
        return true
    }
}

public struct SocketAddress: Hashable, Sendable, CustomStringConvertible {
    public var ip: IPAddr
    public var port: UInt16

    public init(ip: IPAddr, port: UInt16) {
        self.ip = ip
        self.port = port
    }

    public init?(sockaddr p: UnsafePointer<sockaddr>) {
        switch Int32(p.pointee.sa_family) {
        case AF_INET:
            let sin = UnsafeRawPointer(p).loadUnaligned(as: sockaddr_in.self)
            self.init(ip: IPAddr(bytes: withUnsafeBytes(of: sin.sin_addr) { Array($0) }), port: UInt16(bigEndian: sin.sin_port))
        case AF_INET6:
            let sin6 = UnsafeRawPointer(p).loadUnaligned(as: sockaddr_in6.self)
            self.init(ip: IPAddr(bytes: withUnsafeBytes(of: sin6.sin6_addr) { Array($0) }), port: UInt16(bigEndian: sin6.sin6_port))
        default:
            return nil
        }
    }

    public init?(storage: sockaddr_storage) {
        var ss = storage
        let parsed = withUnsafePointer(to: &ss) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { SocketAddress(sockaddr: $0) }
        }
        guard let parsed else { return nil }
        self = parsed
    }

    public var description: String { ProxyTarget(host: ip.description, port: port).authority }

    public func withSockaddr<R>(_ body: (UnsafePointer<sockaddr>, socklen_t) -> R) -> R {
        if ip.isV4 {
            var sin = sockaddr_in()
            sin.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            sin.sin_family = sa_family_t(AF_INET)
            sin.sin_port = port.bigEndian
            ip.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &sin.sin_addr) { $0.copyMemory(from: src) }
            }
            return withUnsafePointer(to: &sin) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        } else {
            var sin6 = sockaddr_in6()
            sin6.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            sin6.sin6_family = sa_family_t(AF_INET6)
            sin6.sin6_port = port.bigEndian
            ip.bytes.withUnsafeBytes { src in
                withUnsafeMutableBytes(of: &sin6.sin6_addr) { $0.copyMemory(from: src) }
            }
            return withUnsafePointer(to: &sin6) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
    }

    public static func local(of fd: Int32) -> SocketAddress? { query(fd, getsockname) }
    public static func peer(of fd: Int32) -> SocketAddress? { query(fd, getpeername) }

    private static func query(_ fd: Int32, _ fn: (Int32, UnsafeMutablePointer<sockaddr>, UnsafeMutablePointer<socklen_t>) -> Int32) -> SocketAddress? {
        var ss = sockaddr_storage()
        var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let rc = withUnsafeMutablePointer(to: &ss) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { fn(fd, $0, &len) }
        }
        return rc == 0 ? SocketAddress(storage: ss) : nil
    }

    /// Resolves a hostname or IP literal. IPv4 addresses come first.
    public static func resolve(host: String, port: UInt16) throws -> [SocketAddress] {
        if let ip = IPAddr(host) {
            return [SocketAddress(ip: ip, port: port)]
        }
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, nil, &hints, &res)
        guard rc == 0, let first = res else {
            throw NetError("cannot resolve \(host): \(String(cString: gai_strerror(rc)))")
        }
        defer { freeaddrinfo(first) }
        var result: [SocketAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let ai = cursor {
            if let sa = ai.pointee.ai_addr, var addr = SocketAddress(sockaddr: sa), !result.contains(where: { $0.ip == addr.ip }) {
                addr.port = port
                result.append(addr)
            }
            cursor = ai.pointee.ai_next
        }
        if result.isEmpty {
            throw NetError("cannot resolve \(host)")
        }
        return result.filter { $0.ip.isV4 } + result.filter { !$0.ip.isV4 }
    }
}

/// Blocking TCP socket.
public final class TCPStream: @unchecked Sendable {
    public let fd: Int32
    private let lock = NSLock()
    private var closed = false

    public init(fd: Int32) {
        self.fd = fd
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    deinit { close() }

    public func read(into buf: UnsafeMutableRawPointer, count: Int) -> Int {
        while true {
            let n = Darwin.read(fd, buf, count)
            if n < 0 && errno == EINTR { continue }
            return n
        }
    }

    /// Reads whatever is available (blocking). Empty array means EOF.
    public func readSome(max: Int = 65536) throws -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: max)
        let n = buf.withUnsafeMutableBytes { read(into: $0.baseAddress!, count: max) }
        if n < 0 {
            throw NetError.errno("read")
        }
        return Array(buf[0..<n])
    }

    public func readExactly(_ count: Int) throws -> [UInt8] {
        var out: [UInt8] = []
        while out.count < count {
            let chunk = try readSome(max: count - out.count)
            if chunk.isEmpty {
                throw NetError("connection closed by peer")
            }
            out += chunk
        }
        return out
    }

    public func write(_ bytes: UnsafeRawBufferPointer) -> Bool {
        guard let base = bytes.baseAddress else { return true }
        var offset = 0
        while offset < bytes.count {
            let n = Darwin.write(fd, base + offset, bytes.count - offset)
            if n < 0 {
                if errno == EINTR { continue }
                return false
            }
            offset += n
        }
        return true
    }

    public func writeAll(_ bytes: [UInt8]) throws {
        let ok = bytes.withUnsafeBytes { write($0) }
        if !ok {
            throw NetError.errno("write")
        }
    }

    /// Read/write timeout for blocking calls; 0 disables it.
    public func setTimeout(ms: Int) {
        var tv = timeval(tv_sec: ms / 1000, tv_usec: Int32((ms % 1000) * 1000))
        let size = socklen_t(MemoryLayout<timeval>.size)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, size)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, size)
    }

    public func waitReadable(timeoutMs: Int) -> Bool {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        while true {
            let r = poll(&p, 1, Int32(timeoutMs))
            if r < 0 && errno == EINTR { continue }
            return r > 0
        }
    }

    public func setKeepAlive() {
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    public func setBlocking() {
        let flags = fcntl(fd, F_GETFL)
        if flags >= 0 {
            _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
        }
    }

    public func shutdownWrite() { _ = Darwin.shutdown(fd, SHUT_WR) }
    public func shutdownBoth() { _ = Darwin.shutdown(fd, SHUT_RDWR) }

    /// Closes with RST instead of FIN.
    public func abort() {
        var l = linger(l_onoff: 1, l_linger: 0)
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, socklen_t(MemoryLayout<linger>.size))
        close()
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        if !closed {
            closed = true
            Darwin.close(fd)
        }
    }

    /// Connects to the first reachable address. With `bindPorts` the local port is
    /// taken from that range, which lets pf recognize (and not redirect) our own traffic.
    /// With `interface` ("en8") the connection leaves through that adapter whatever the routing table says.
    public static func connect(to addrs: [SocketAddress], timeoutMs: Int, bindPorts: ClosedRange<UInt16>? = nil, interface: String? = nil) throws -> TCPStream {
        var lastError = NetError("no addresses to connect to")
        var index: UInt32 = 0
        if let interface {
            index = if_nametoindex(interface)
            guard index != 0 else { throw NetError("network interface \(interface) is gone") }
        }
        for addr in addrs {
            do {
                return try connectOne(addr, timeoutMs: timeoutMs, bindPorts: bindPorts, interfaceIndex: index)
            } catch let e as NetError {
                lastError = e
            }
        }
        throw lastError
    }

    private static func connectOne(_ addr: SocketAddress, timeoutMs: Int, bindPorts: ClosedRange<UInt16>?, interfaceIndex: UInt32) throws -> TCPStream {
        let family = addr.ip.isV4 ? AF_INET : AF_INET6
        var attemptsLeft = bindPorts == nil ? 1 : 16
        while true {
            attemptsLeft -= 1
            let fd = socket(family, SOCK_STREAM, IPPROTO_TCP)
            guard fd >= 0 else { throw NetError.errno("socket") }
            let stream = TCPStream(fd: fd)
            if interfaceIndex != 0 {
                var index = interfaceIndex
                let rc = addr.ip.isV4
                    ? setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
                    : setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size))
                if rc != 0 {
                    let e = NetError.errno("bind to network interface")
                    stream.close()
                    throw e
                }
            }
            if let range = bindPorts {
                try stream.bindRandomPort(in: range, family: family)
            }
            let flags = fcntl(fd, F_GETFL)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

            var err: Int32 = 0
            if addr.withSockaddr({ Darwin.connect(fd, $0, $1) }) != 0 {
                err = errno
                if err == EINPROGRESS {
                    var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    var r: Int32
                    repeat {
                        r = poll(&p, 1, Int32(timeoutMs))
                    } while r < 0 && errno == EINTR
                    if r == 0 {
                        stream.close()
                        throw NetError("connect to \(addr): timed out")
                    }
                    var len = socklen_t(MemoryLayout<Int32>.size)
                    err = 0
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len)
                }
            }
            if err != 0 {
                stream.close()
                if (err == EADDRINUSE || err == EADDRNOTAVAIL) && attemptsLeft > 0 {
                    continue
                }
                throw NetError.errno("connect to \(addr)", err)
            }
            _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
            return stream
        }
    }

    private func bindRandomPort(in range: ClosedRange<UInt16>, family: Int32) throws {
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        let any = IPAddr(bytes: [UInt8](repeating: 0, count: family == AF_INET ? 4 : 16))
        for _ in 0..<64 {
            let local = SocketAddress(ip: any, port: UInt16.random(in: range))
            if local.withSockaddr({ bind(fd, $0, $1) }) == 0 {
                return
            }
        }
        throw NetError.errno("bind local port")
    }
}

public enum UnixSocket {
    private static func address(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw NetError("socket path too long: \(path)")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { p in
            p.copyBytes(from: bytes)
            p[bytes.count] = 0
        }
        return addr
    }

    public static func connect(path: String) throws -> Int32 {
        var addr = try address(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NetError.errno("socket") }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if rc != 0 {
            let e = errno
            Darwin.close(fd)
            throw NetError.errno("connect \(path)", e)
        }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }

    public static func listen(path: String, mode: mode_t) throws -> Int32 {
        var addr = try address(path)
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NetError.errno("socket") }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NetError.errno("bind \(path)", e)
        }
        chmod(path, mode)
        guard Darwin.listen(fd, 8) == 0 else { throw NetError.errno("listen \(path)") }
        return fd
    }
}

/// Newline-delimited JSON over a stream socket.
public final class LineChannel: @unchecked Sendable {
    public let fd: Int32
    private let writeLock = NSLock()
    private let encoder = JSONEncoder()

    public init(fd: Int32) {
        self.fd = fd
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    @discardableResult
    public func send<T: Encodable>(_ value: T) -> Bool {
        writeLock.lock()
        defer { writeLock.unlock() }
        guard var data = try? encoder.encode(value) else { return false }
        data.append(0x0A)
        return data.withUnsafeBytes { p in
            var offset = 0
            while offset < p.count {
                let n = Darwin.write(fd, p.baseAddress! + offset, p.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += n
            }
            return true
        }
    }

    /// Blocks until EOF, calling `handler` for every line.
    public func readLines(_ handler: (Data) -> Void) {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = chunk.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { return }
            buffer.append(contentsOf: chunk[0..<n])
            while let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<nl]
                if !line.isEmpty {
                    handler(Data(line))
                }
                buffer.removeSubrange(buffer.startIndex...nl)
            }
            // A peer that never sends a newline must not grow our memory without bound.
            if buffer.count > 8 * 1024 * 1024 { return }
        }
    }

    /// Wakes up a blocked reader; the reader's owner closes the fd afterwards.
    public func shutdown() { _ = Darwin.shutdown(fd, SHUT_RDWR) }

    public func close() { Darwin.close(fd) }
}

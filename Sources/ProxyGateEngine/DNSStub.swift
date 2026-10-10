import Darwin
import Foundation
import PGCore

/// A tiny caching DNS forwarder on 127.0.0.1 for the domains the user chose. The /etc/resolver
/// files send only those domains here; it answers them through the chosen provider (DoH or plain),
/// refuses everything else, so corporate and other names can never leak to a public resolver
/// through it.
final class DNSStub: @unchecked Sendable {
    struct Config: Equatable {
        var upstream: DNSUpstream
        var domains: [String]
        /// Answer AAAA with "no data" when IPv6 is not redirected, so apps don't take an IPv6 path
        /// around pf (and around the DPI bypass).
        var filterAAAA: Bool
    }

    private let lock = NSLock()
    private var config: Config?
    private var fd: Int32 = -1
    private var generation = 0
    private var answered = 0
    private var failed = 0
    private var lastError: String?
    private let cache = DNSCache()
    private let inflight = DispatchSemaphore(value: 64)
    private let workers = DispatchQueue(label: "proxygate.dnsstub", attributes: .concurrent)

    var counters: (answered: Int, failed: Int, error: String?) { lock.withLock { (answered, failed, lastError) } }

    /// Binds the socket on first use and swaps in the new config. A changed upstream drops the cache.
    func start(_ newConfig: Config) throws {
        let (needBind, upstreamChanged) = lock.withLock { () -> (Bool, Bool) in
            let changed = config?.upstream != newConfig.upstream
            config = newConfig
            return (fd < 0, changed)
        }
        if upstreamChanged { cache.removeAll() }
        guard needBind else { return }
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { throw NetError.errno("dns socket") }
        var one: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        let addr = SocketAddress(ip: IPAddr("127.0.0.1")!, port: PGConstants.dnsStubPort)
        guard addr.withSockaddr({ bind(sock, $0, $1) }) == 0 else {
            let e = errno
            Darwin.close(sock)
            lock.withLock { config = nil }
            throw NetError.errno("bind \(addr)", e)
        }
        let gen = lock.withLock { () -> Int in
            fd = sock
            generation += 1
            return generation
        }
        let t = Thread { [weak self] in self?.loop(sock, generation: gen) }
        t.start()
    }

    func stop() {
        let sock = lock.withLock { () -> Int32 in
            let s = fd
            fd = -1
            generation += 1
            config = nil
            return s
        }
        cache.removeAll()
        if sock >= 0 { Darwin.close(sock) }
    }

    private func loop(_ sock: Int32, generation gen: Int) {
        var buf = [UInt8](repeating: 0, count: 4096)
        var p = pollfd(fd: sock, events: Int16(POLLIN), revents: 0)
        while lock.withLock({ generation == gen }) {
            guard poll(&p, 1, 500) > 0 else { continue }
            var from = sockaddr_storage()
            var len = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let n = buf.withUnsafeMutableBytes { b in
                withUnsafeMutablePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(sock, b.baseAddress, b.count, 0, $0, &len) }
                }
            }
            guard n > 0 else { continue }
            let query = Array(buf[0..<n])
            // Back-pressure: past 64 lookups in flight, drop; the client retries.
            guard inflight.wait(timeout: .now()) == .success else { continue }
            let client = from, clientLen = len
            workers.async { [weak self] in
                defer { self?.inflight.signal() }
                guard let self, let reply = self.answer(query) else { return }
                var to = client
                _ = reply.withUnsafeBytes { b in
                    withUnsafePointer(to: &to) {
                        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sendto(sock, b.baseAddress, b.count, 0, $0, clientLen) }
                    }
                }
            }
        }
    }

    /// The reply for one client query, nil to drop it (malformed).
    func answer(_ query: [UInt8]) -> [UInt8]? {
        guard let q = DNSMessage.question(of: query), let clientID = DNSMessage.id(of: query),
              let cfg = lock.withLock({ config }) else { return nil }
        guard DNSDomainList.covers(cfg.domains, host: q.name) else {
            return DNSMessage.reply(to: query, rcode: DNSMessage.rcodeRefused)
        }
        if cfg.filterAAAA, q.type == DNSRecordType.aaaa.rawValue {
            return DNSMessage.reply(to: query, rcode: DNSMessage.rcodeNoError)
        }
        if let cached = cache.get(q, id: clientID) { return cached }

        // Our own id upstream (0 for DoH, as RFC 8484 suggests), the client's id back.
        let upstreamID: UInt16 = cfg.upstream.transport == .doh ? 0 : UInt16.random(in: 1...0xFFFF)
        do {
            let raw = try DNSClient.exchange(DNSMessage.withID(query, upstreamID), upstream: cfg.upstream,
                                             timeoutMs: 4000, bindPorts: PFRules.reservedPorts)
            guard let r = DNSMessage.parse(raw), r.question?.name == q.name, r.question?.type == q.type else {
                throw NetError("answer does not match the question")
            }
            if let seconds = DNSCache.lifetime(of: r) { cache.put(q, message: raw, seconds: seconds) }
            lock.withLock { answered += 1; lastError = nil }
            return DNSMessage.withID(raw, clientID)
        } catch {
            lock.withLock { failed += 1; lastError = "\(cfg.upstream.title): \(error)" }
            return DNSMessage.reply(to: query, rcode: DNSMessage.rcodeServFail)
        }
    }
}

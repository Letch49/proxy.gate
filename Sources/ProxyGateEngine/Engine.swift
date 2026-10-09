import CSys
import Darwin
import Foundation
import PGCore

/// Accepts redirected connections, applies rules and relays traffic.
final class Engine: @unchecked Sendable {
    private let lock = NSLock()
    private var profile = Profile.makeDefault()
    private var rules = RuleSet(profile: Profile.makeDefault())
    /// Resolved addresses of configured proxies: connections to them always go direct.
    private var proxyIPs: Set<IPAddr> = []
    private var running = false
    private var lastError: String?
    private var pfFD: Int32 = -1
    private var pfToken: String?
    private var listenPort: UInt16 = 0
    /// Bumped on stop so accept loops of the previous run exit.
    private var generation = 0
    /// "<proxy or chain id>|<port>" → until when the proxy is known to refuse that port.
    /// Avoids hammering a corporate proxy that only allows CONNECT to 443.
    private var refusedPorts: [String: Date] = [:]
    private static let refusalMemory: TimeInterval = 600

    private let registry = Registry()
    private let processes = ProcessResolver()
    private let hosts = HostVerifier()
    let xray = XrayManager()
    let tpws = TpwsManager()
    let anyConnect = AnyConnectManager()
    private let geo = GeoDB()
    private var anyConnectState = AnyConnectState()
    /// Concentrator IP + split subnets the AnyConnect tunnel owns; kept out of pf redirection.
    private var anyConnectBypass: [String] = []
    private var userBypassCache: [String] = []
    private var localBypassCache: [String] = []
    /// Latest Xray config pushed by the app; re-applied after the core is (re)installed.
    private var xrayConfigJSON: String?
    /// Latest tpws strategy; re-applied after the core is (re)installed.
    private var tpwsStrategy: [String]?
    /// Cached so rule matching doesn't shell out to launchctl per connection; refreshed on the ticker.
    private var vpnRunning = false
    private var tpwsRunning = false
    /// Route `.direct` connections through tpws for DPI bypass.
    private var bypassDirect = false
    /// Egress that `.global` rules resolve to, set by the app from the current network.
    private var activeBridge: Bridge = .direct

    /// Set by the control server.
    var emit: (EngineMessage) -> Void = { _ in }

    var status: EngineStatus {
        // Use the cached running flags (refreshed on the ticker) — never shell out to launchctl per
        // status, which is built on every command and every state change.
        lock.withLock {
            EngineStatus(version: PGConstants.version, running: running, error: lastError, listenPort: listenPort,
                         xrayVersion: xray.installedVersion, xrayRunning: vpnRunning, xrayError: xray.error,
                         tpwsVersion: tpws.installedVersion, tpwsRunning: tpwsRunning, tpwsError: tpws.error,
                         anyConnect: anyConnectState)
        }
    }

    // MARK: - Xray core

    func installXray(zipPath: String, version: String, sha256: String) {
        do {
            try xray.install(fromZip: zipPath, version: version, sha256: sha256)
            log(.info, "Xray core \(version) installed")
            if let json = lock.withLock({ xrayConfigJSON }) { xray.apply(config: json) }
        } catch {
            log(.error, "Xray core install failed: \(error)")
        }
    }

    func applyXray(config json: String?) {
        lock.withLock { xrayConfigJSON = json }
        let running = xray.apply(config: json)
        lock.withLock { vpnRunning = running }
        if let err = xray.error { log(.warning, err) }
    }

    func setActiveBridge(_ bridge: Bridge) {
        lock.withLock { activeBridge = bridge }
    }

    // MARK: - DPI bypass (tpws)

    func installTpws(path: String, version: String, sha256: String) {
        do {
            try tpws.install(from: path, version: version, sha256: sha256)
            log(.info, "tpws \(version) installed")
            if let strategy = lock.withLock({ tpwsStrategy }) { tpws.apply(strategy: strategy) }
        } catch {
            log(.error, "tpws install failed: \(error)")
        }
    }

    func applyTpws(strategy: [String]?) {
        lock.withLock { tpwsStrategy = strategy }
        let up = tpws.apply(strategy: strategy)
        lock.withLock { tpwsRunning = up }
        if let err = tpws.error { log(.warning, err) }
    }

    func setBypassDirect(_ on: Bool) {
        lock.withLock { bypassDirect = on }
    }

    /// Tries each strategy against known-blocked hosts; emits the first that works (or -1).
    func tuneBypass(hosts: [String]) {
        DispatchQueue.global().async { [weak self] in
            guard let self else { return }
            let hosts = hosts.isEmpty ? ["www.youtube.com", "discord.com"] : hosts
            var winner = -1
            for (index, strategy) in DPIStrategies.all.enumerated() {
                if hosts.contains(where: { self.tpws.probe(flags: strategy.flags, host: $0) }) {
                    winner = index
                    break
                }
            }
            // Restore the user's running strategy (probes bounced the service around).
            if let strategy = self.lock.withLock({ self.tpwsStrategy }) { self.tpws.apply(strategy: strategy) }
            self.emit(.bypassTuned(index: winner))
        }
    }

    /// Latency-tests each server concurrently (probes bind to reserved ports, so pf passes them
    /// untouched and the time reflects a direct TCP connect), then emits the results.
    func pingServers(subscription: UUID, targets: [PingTarget]) {
        DispatchQueue.global().async { [weak self] in
            let group = DispatchGroup()
            let resultLock = NSLock()
            var results: [Int: Int] = [:]
            for target in targets {
                group.enter()
                DispatchQueue.global().async {
                    defer { group.leave() }
                    let started = Date()
                    let ms: Int
                    if let addrs = try? SocketAddress.resolve(host: target.host, port: target.port),
                       let stream = try? TCPStream.connect(to: addrs, timeoutMs: 3000, bindPorts: PFRules.reservedPorts) {
                        stream.close()
                        ms = max(1, Int(Date().timeIntervalSince(started) * 1000))
                    } else {
                        ms = -1
                    }
                    resultLock.withLock { results[target.index] = ms }
                }
            }
            group.wait()
            self?.emit(.pingResults(subscription: subscription, latencies: results))
        }
    }

    init() {
        let ticker = Thread { [weak self] in
            var tick = 0
            while let self {
                Thread.sleep(forTimeInterval: PGConstants.statsInterval)
                self.emit(.stats(self.registry.changes()))
                // Refreshing the core run-state shells out to launchctl, so do it every ~10s, not 2s.
                tick += 1
                if tick % 5 == 0 {
                    let xrayUp = self.xray.running
                    let tpwsUp = self.tpws.running
                    self.lock.withLock { self.vpnRunning = xrayUp; self.tpwsRunning = tpwsUp }
                }
            }
        }
        ticker.start()

        anyConnect.onState = { [weak self] state in
            guard let self else { return }
            self.lock.withLock { self.anyConnectState = state }
            self.emit(.status(self.status))
        }
        anyConnect.onBypass = { [weak self] entries in
            guard let self else { return }
            // Re-validate before these reach pfctl, like every other bypass entry.
            let clean = PFRules.validNetworks(entries.joined(separator: ";"))
            self.lock.withLock { self.anyConnectBypass = clean }
            self.refreshBypass()
        }
    }

    func log(_ level: LogEntry.Level, _ text: String) {
        FileHandle.standardError.write(Data("[\(level.rawValue)] \(text)\n".utf8))
        emit(.log(LogEntry(level: level, text: text)))
    }

    // MARK: - Configuration

    func apply(_ newProfile: Profile) {
        let ruleSet = RuleSet(profile: newProfile)
        let (wasRunning, advancedChanged) = lock.withLock {
            let changed = profile.advanced != newProfile.advanced
            profile = newProfile
            rules = ruleSet
            refusedPorts.removeAll()
            return (running, changed)
        }
        let proxies = newProfile.proxies
        DispatchQueue.global().async { [weak self] in
            var ips: Set<IPAddr> = []
            for p in proxies {
                for addr in (try? SocketAddress.resolve(host: p.host, port: p.port)) ?? [] {
                    ips.insert(addr.ip)
                }
            }
            self?.lock.withLock { self?.proxyIPs = ips }
        }
        if wasRunning && advancedChanged {
            log(.info, "Interception settings changed, restarting")
            stop()
            try? start()
        }
    }

    // MARK: - Start / stop

    func start() throws {
        // Claim the slot under the lock, then open /dev/pf, bind the listeners and run pfctl WITHOUT
        // holding it — those block on syscalls and subprocesses, and the lock also guards `status`.
        let advanced: AdvancedSettings? = lock.withLock {
            if running { return nil }
            running = true                        // concurrent start()s now bail; stop() sees us
            return profile.advanced
        }
        guard let advanced else { return }

        let fd = pg_pf_open()
        guard fd >= 0 else {
            lock.withLock { running = false; lastError = "open /dev/pf (the engine must run as root)" }
            throw NetError.errno("open /dev/pf (the engine must run as root)")
        }
        var listeners: [Int32] = []
        let token: String?
        let userBypass: [String]
        let local: [String]
        do {
            listeners.append(try listen(ip: "127.0.0.1", port: advanced.listenPort))
            if advanced.captureIPv6 {
                listeners.append(try listen(ip: "::1", port: advanced.listenPort))
            }
            userBypass = PFRules.validNetworks(advanced.bypassNetworks)
            local = PFRules.localAddresses()
            let ruleText = PFRules.generate(
                listenPort: advanced.listenPort,
                captureIPv6: advanced.captureIPv6,
                blockQUIC: advanced.blockQUIC,
                bypass: userBypass + local,
                xrayUID: xray.serviceUID())
            token = try PF.enable(rules: ruleText)
        } catch {
            listeners.forEach { Darwin.close($0) }
            Darwin.close(fd)
            lock.withLock { running = false; lastError = "\(error)" }
            throw error
        }

        // Commit the live state in one short critical section; bail and undo if a stop() raced in.
        let gen: Int? = lock.withLock { () -> Int? in
            guard running else { return nil }
            pfFD = fd
            listenPort = advanced.listenPort
            generation += 1
            pfToken = token
            lastError = nil
            return generation
        }
        guard let gen else {
            PF.disable(token: token)
            listeners.forEach { Darwin.close($0) }
            Darwin.close(fd)
            return
        }
        Thread { [weak self] in
            self?.watchLocalAddresses(generation: gen, userBypass: userBypass, current: local)
        }.start()
        for lfd in listeners {
            let t = Thread { [weak self] in self?.acceptLoop(lfd, generation: gen) }
            t.start()
        }
        FileHandle.standardError.write(Data("[info] interception started on port \(advanced.listenPort)\n".utf8))
    }

    func stop() {
        let token: String?
        let fd: Int32
        lock.lock()
        guard running else {
            lock.unlock()
            return
        }
        running = false
        generation += 1
        token = pfToken
        pfToken = nil
        fd = pfFD
        pfFD = -1          // we own `fd` now; a later start() opens a fresh one
        lock.unlock()

        PF.disable(token: token)
        // Established relays keep working; natlook is no longer needed for them. Close our captured
        // fd after they drain — generation gating already stops new handlers from using it.
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
            if fd >= 0 { Darwin.close(fd) }
        }
        FileHandle.standardError.write(Data("[info] interception stopped\n".utf8))
    }

    /// Keeps the Mac's own addresses in the bypass table as networks come and go (Wi-Fi, VPN, DHCP).
    private func watchLocalAddresses(generation gen: Int, userBypass: [String], current: [String]) {
        lock.withLock { userBypassCache = userBypass; localBypassCache = current }
        var lastApplied: [String] = []
        while true {
            Thread.sleep(forTimeInterval: 3)
            guard lock.withLock({ generation == gen && running }) else { return }
            let now = PFRules.localAddresses()
            lock.withLock { localBypassCache = now }
            let full = fullBypass()
            if full != lastApplied, PF.replaceBypass(full) {
                lastApplied = full
            }
        }
    }

    private func fullBypass() -> [String] {
        lock.withLock { PFRules.defaultBypass + userBypassCache + localBypassCache + anyConnectBypass }
    }

    /// Re-applies the pf bypass table (used when AnyConnect adds/removes the concentrator + routes).
    private func refreshBypass() {
        if PF.replaceBypass(fullBypass()) {
            FileHandle.standardError.write(Data("[info] bypass updated (anyconnect: \(lock.withLock { anyConnectBypass }.joined(separator: ", ")))\n".utf8))
        }
    }

    private func listen(ip: String, port: UInt16) throws -> Int32 {
        let addr = SocketAddress(ip: IPAddr(ip)!, port: port)
        let fd = socket(addr.ip.isV4 ? AF_INET : AF_INET6, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else { throw NetError.errno("socket") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        if !addr.ip.isV4 {
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, socklen_t(MemoryLayout<Int32>.size))
        }
        guard addr.withSockaddr({ bind(fd, $0, $1) }) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NetError.errno("bind \(addr)", e)
        }
        guard Darwin.listen(fd, 1024) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NetError.errno("listen \(addr)", e)
        }
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        return fd
    }

    private func acceptLoop(_ lfd: Int32, generation gen: Int) {
        defer { Darwin.close(lfd) }
        var p = pollfd(fd: lfd, events: Int16(POLLIN), revents: 0)
        while lock.withLock({ generation == gen }) {
            guard poll(&p, 1, 500) > 0 else { continue }
            let cfd = accept(lfd, nil, nil)
            if cfd < 0 {
                if errno == EMFILE || errno == ENFILE {
                    usleep(100_000)
                }
                continue
            }
            let t = Thread { [weak self] in self?.handle(cfd) }
            t.stackSize = 256 * 1024
            t.start()
        }
    }

    // MARK: - Connection handling

    private func handle(_ cfd: Int32) {
        let client = TCPStream(fd: cfd)
        client.setBlocking()
        let (pf, cfg, ruleSet, proxyIPs) = lock.withLock { (pfFD, profile, rules, self.proxyIPs) }
        guard let src = SocketAddress.peer(of: cfd), let local = SocketAddress.local(of: cfd) else {
            client.close()
            return
        }
        var orig = sockaddr_storage()
        let rc = src.withSockaddr { s, _ in local.withSockaddr { d, _ in pg_natlook(pf, s, d, &orig) } }
        guard rc == 0, let dst = SocketAddress(storage: orig) else {
            log(.warning, "No pf state for \(src) (\(String(cString: strerror(rc)))), dropping")
            client.abort()
            return
        }

        var timing = StageTiming()
        let app = processes.identity(pid: processes.owner(localPort: src.port, remotePort: dst.port))
        timing.mark("lookup")

        var initial: [UInt8] = []
        var clientEOF = false
        if cfg.dns.sniffHostnames {
            (initial, clientEOF) = sniff(client, timeoutMs: cfg.dns.sniffTimeoutMs)
        }
        timing.mark("sniff \(initial.count)B")
        let hostname = cfg.dns.sniffHostnames ? Sniffer.hostname(from: initial) : nil
        let targetHost = hostname ?? dst.ip.description

        let bound = cfg.proxies.contains { $0.interfaceMAC != nil }
        let unavailable = bound ? cfg.unavailableRoutes(active: NetInterfaces.active()) : []
        let (bridge, vpnUp, bypass, tpwsUp) = lock.withLock { (activeBridge, vpnRunning, bypassDirect, tpwsRunning) }
        var rule = ruleSet.match(MatchRequest(app: app, hostname: hostname, ip: dst.ip, port: dst.port),
                                 activeBridge: bridge, vpnAvailable: vpnUp, dpiAvailable: tpwsUp,
                                 unavailable: unavailable, geoDB: geo)
        if proxyIPs.contains(dst.ip) {
            rule = Rule(name: "Proxy server", action: .direct)
        }
        let kind: RouteKind
        switch rule.action {
        case .direct: kind = .direct
        case .directDPI: kind = .direct
        case .block: kind = .block
        case .proxy, .vpn, .global: kind = .proxy
        case .chain: kind = .chain
        }
        let info = ConnInfo(
            id: registry.nextID(), app: app,
            target: ProxyTarget(host: targetHost, port: dst.port).authority,
            ip: dst.ip.description, port: dst.port,
            rule: rule.name, route: cfg.describe(rule.action), kind: kind,
            time: Date().timeIntervalSince1970)

        let timeoutMs = max(1, cfg.advanced.connectTimeoutSec) * 1000
        // The name goes to the proxy only when it really belongs to the dialed IP.
        let trustedHost = hostname.flatMap { cfg.dns.sendHostnameToProxy && hosts.resolves($0, to: dst.ip) ? $0 : nil }
        let proxyTarget = ProxyTarget(host: trustedHost ?? dst.ip.description, port: dst.port)
        timing.mark("dns")
        let upstream: TCPStream
        var leftover: [UInt8] = []
        do {
            switch rule.action {
            case .block:
                emit(.blocked(info))
                client.abort()
                return
            case .direct:
                if bypass && tpwsUp && !dst.ip.isPrivate {
                    // DPI bypass: hand the direct connection to tpws, which desyncs the ClientHello.
                    // Private/LAN destinations never need it, so they stay a plain direct connection.
                    let t = ProxyServer(host: "127.0.0.1", port: PGConstants.tpwsSocksPort, type: .socks5)
                    (upstream, leftover) = try ProxyClient.connect(through: [t], to: proxyTarget, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
                } else {
                    upstream = try TCPStream.connect(to: [dst], timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
                }
            case .proxy(let id):
                guard let proxy = cfg.proxy(id) else { throw NetError("proxy of rule \(rule.name) no longer exists") }
                if proxy.type == .https, dst.port != 443,
                   let forwarded = HTTPForward.rewrite(initial, host: proxyTarget.host, port: dst.port, proxy: proxy) {
                    // Plain HTTP: a forward-proxy request instead of CONNECT, which many proxies
                    // allow only to port 443.
                    upstream = try ProxyClient.open(proxy, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
                    initial = forwarded
                } else {
                    (upstream, leftover) = try connectRemembering(key: id, title: proxy.title, port: dst.port) {
                        try ProxyClient.connect(through: [proxy], to: proxyTarget, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
                    }
                }
            case .chain(let id):
                let chain = cfg.chainProxies(id)
                guard !chain.isEmpty else { throw NetError("proxy chain of rule \(rule.name) is empty") }
                (upstream, leftover) = try connectRemembering(key: id, title: cfg.describe(rule.action), port: dst.port) {
                    try ProxyClient.connect(through: chain, to: proxyTarget, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
                }
            case .vpn:
                // The VPN bridge is the local Xray SOCKS; its own outbound is passed by pf (xrayUID).
                let vpn = ProxyServer(host: "127.0.0.1", port: PGConstants.vpnSocksPort, type: .socks5)
                (upstream, leftover) = try ProxyClient.connect(through: [vpn], to: proxyTarget, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
            case .directDPI:
                // Per-rule DPI bypass: route this connection through tpws (resolved only when it's up).
                let t = ProxyServer(host: "127.0.0.1", port: PGConstants.tpwsSocksPort, type: .socks5)
                (upstream, leftover) = try ProxyClient.connect(through: [t], to: proxyTarget, timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
            case .global:
                // Resolved away in RuleSet.match; reached only if the bridge was unset — go direct.
                upstream = try TCPStream.connect(to: [dst], timeoutMs: timeoutMs, bindPorts: PFRules.reservedPorts)
            }
        } catch {
            timing.mark("connect")
            FileHandle.standardError.write(Data("[fail] \(app.name) -> \(info.target) via \(info.route) [\(timing)]: \(error)\n".utf8))
            emit(.failed(ConnFailed(info: info, error: "\(error)")))
            client.abort()
            return
        }
        timing.mark("connect")
        if timing.totalMs > 2000 {
            FileHandle.standardError.write(Data("[slow] \(app.name) -> \(info.target) via \(info.route) [\(timing)]\n".utf8))
        }

        client.setKeepAlive()
        upstream.setKeepAlive()
        let counter = registry.add(info.id)
        emit(.opened(info))
        // Diagnostics: a connection that got no answer at all after 8 s is logged with details.
        let sniffed = initial.count, eof = clientEOF, via = "\(info.route) as \(proxyTarget.authority)"
        DispatchQueue.global().asyncAfter(deadline: .now() + 8) {
            let t = counter.totals
            if t.received == 0 {
                FileHandle.standardError.write(Data("[stall] \(app.name) -> \(info.target) via \(via): sent \(t.sent)B (first \(sniffed)B, clientEOF \(eof)), received 0B after 8s\n".utf8))
            }
        }
        relay(client: client, upstream: upstream, initial: initial, leftover: leftover, clientEOF: clientEOF, counter: counter)
        let totals = counter.totals
        registry.remove(info.id)
        emit(.closed(ConnClosed(id: info.id, sent: totals.sent, received: totals.received, time: Date().timeIntervalSince1970)))
    }

    /// Runs a proxy connect, failing fast for ports this proxy refused recently and
    /// remembering new refusals (HTTP 403/405, SOCKS "not allowed") of non-443 ports.
    private func connectRemembering(key id: UUID, title: String, port: UInt16, _ connect: () throws -> (TCPStream, [UInt8])) throws -> (TCPStream, [UInt8]) {
        let key = "\(id)|\(port)"
        if let until = lock.withLock({ refusedPorts[key] }), until > Date() {
            throw NetError("\(title) does not allow port \(port) (refused earlier, retrying in \(Int(until.timeIntervalSinceNow / 60) + 1) min). Add a rule for port \(port) to route or block it.")
        }
        do {
            return try connect()
        } catch let refused as ProxyRefusedError where port != 443 && [2, 403, 405].contains(refused.code) {
            lock.withLock { refusedPorts[key] = Date().addingTimeInterval(Engine.refusalMemory) }
            log(.warning, "\(title) refuses port \(port) (code \(refused.code)); connections to this port will fail immediately for 10 minutes")
            throw refused
        }
    }

    /// Reads the client's first bytes (TLS ClientHello / HTTP request) without forwarding them yet.
    private func sniff(_ client: TCPStream, timeoutMs: Int) -> ([UInt8], Bool) {
        var data: [UInt8] = []
        var wait = timeoutMs
        while data.count < 16384 && client.waitReadable(timeoutMs: wait) {
            let chunk = (try? client.readSome(max: 16384 - data.count)) ?? []
            if chunk.isEmpty {
                return (data, true)
            }
            data += chunk
            // A post-quantum ClientHello spans several segments; wait for the whole record.
            guard Sniffer.tlsRecordComplete(data) == false else { break }
            wait = 1000
        }
        return (data, false)
    }

    private func relay(client: TCPStream, upstream: TCPStream, initial: [UInt8], leftover: [UInt8], clientEOF: Bool, counter: ConnCounter) {
        if !initial.isEmpty {
            guard (try? upstream.writeAll(initial)) != nil else {
                client.abort()
                upstream.close()
                return
            }
            counter.addSent(initial.count)
        }
        if !leftover.isEmpty {
            try? client.writeAll(leftover)
            counter.addReceived(leftover.count)
        }
        let done = DispatchSemaphore(value: 0)
        let down = Thread {
            Engine.pump(from: upstream, to: client, count: counter.addReceived)
            done.signal()
        }
        down.stackSize = 256 * 1024
        down.start()
        if clientEOF {
            upstream.shutdownWrite()
        } else {
            Engine.pump(from: client, to: upstream, count: counter.addSent)
        }
        done.wait()
        client.close()
        upstream.close()
    }

    private static func pump(from: TCPStream, to: TCPStream, count: (Int) -> Void) {
        let size = 32768
        let buf = UnsafeMutableRawPointer.allocate(byteCount: size, alignment: 16)
        defer { buf.deallocate() }
        while true {
            let n = from.read(into: buf, count: size)
            if n == 0 {
                to.shutdownWrite()
                return
            }
            if n < 0 || !to.write(UnsafeRawBufferPointer(start: buf, count: n)) {
                from.shutdownBoth()
                to.shutdownBoth()
                return
            }
            count(n)
        }
    }
}

/// Per-connection setup timings, written to the helper log for slow or failed connections.
struct StageTiming: CustomStringConvertible {
    private let start = Date()
    private var last = Date()
    private var stages: [(String, Int)] = []

    mutating func mark(_ name: String) {
        let now = Date()
        stages.append((name, Int(now.timeIntervalSince(last) * 1000)))
        last = now
    }

    var totalMs: Int { Int(last.timeIntervalSince(start) * 1000) }

    var description: String {
        stages.map { "\($0.0) \($0.1)ms" }.joined(separator: ", ") + ", total \(totalMs)ms"
    }
}

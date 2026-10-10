import Foundation
import PGCore

/// The DPI auto-tune, as a pipeline whose every stage can be told apart in the report:
/// DNS (system, then the profile's provider) -> TCP to the address -> plain HTTPS without bypass ->
/// each core and strategy. Hosts that fail an early stage never reach the strategies, so a DNS or
/// launch problem is never reported as "no strategy helped".
struct BypassTuner {
    var hosts: [String]
    var upstream: DNSUpstream
    var allowIPv6: Bool
    var engines: [DPIEngine]
    var dryRun: (DPIEngine, [String]) -> String?
    var isCancelled: () -> Bool
    var progress: (TuneProgress) -> Void
    var log: (String) -> Void

    static let maxHosts = 10
    static let fetchTimeoutSec = 6

    func run() -> TuneReport {
        var probes = hosts.map { HostProbe(host: $0) }
        var ips: [IPAddr?] = Array(repeating: nil, count: probes.count)
        var usedProvider = false
        func cancelledReport() -> TuneReport {
            TuneReport(engine: nil, strategyIndex: -1, cancelled: true, hosts: probes, launchErrors: [], dnsSource: nil)
        }

        // 1. DNS, every host at once: what apps get, and what the provider says.
        progress(TuneProgress(phase: .dns, total: probes.count))
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: probes.count) { i in
            let host = probes[i].host
            let system = DNSClient.systemLookup(host, timeoutMs: 4000)
            let provider = DNSClient.lookup(host, upstream: upstream, timeoutMs: 4000, bindPorts: PFRules.reservedPorts)
            let pick = TunePlan.address(system: system, provider: provider, allowIPv6: allowIPv6)
            lock.withLock {
                probes[i].systemDNS = system
                if let pick {
                    ips[i] = pick.ip
                    probes[i].address = pick.ip.description
                    probes[i].dnsSource = pick.fromSystem ? "System" : upstream.title
                    if !pick.fromSystem { usedProvider = true }
                } else {
                    probes[i].failure = TunePlan.dnsFailure(system: system, provider: provider)
                    probes[i].detail = "system: \(system.status.rawValue), \(upstream.title): \(provider.status.rawValue)"
                }
            }
        }
        for p in probes { log("DPI auto-tune: \(p.host) DNS system=\(p.systemDNS?.status.rawValue ?? "-") -> \(p.address ?? "no address")") }
        if isCancelled() { return cancelledReport() }

        // 2 + 3. TCP reachability and a plain HTTPS request, no bypass.
        progress(TuneProgress(phase: .direct, total: probes.count))
        DispatchQueue.concurrentPerform(iterations: probes.count) { i in
            guard let ip = ips[i] else { return }
            let host = probes[i].host
            if let s = try? TCPStream.connect(to: [SocketAddress(ip: ip, port: 443)], timeoutMs: 3000, bindPorts: PFRules.reservedPorts) {
                s.close()
            } else {
                lock.withLock { probes[i].failure = .tcpFailed }
                return
            }
            let direct = DPIProbeSession.fetchDirect(host: host, ip: ip, timeoutSec: Self.fetchTimeoutSec)
            lock.withLock {
                if case .http(_, let ms) = direct {
                    probes[i].ok = true
                    probes[i].directOK = true
                    probes[i].latencyMs = ms
                } else {
                    probes[i].detail = "direct: \(direct.failure?.rawValue ?? "failed")"
                }
            }
        }
        if isCancelled() { return cancelledReport() }

        // 4. Strategies on the hosts that are reachable but blocked. Several throwaway cores run at
        // once (own launchd label and port per slot), each serving every pending host in parallel.
        // Results are merged in strategy order, so "first strategy that works" stays deterministic.
        let pending = probes.indices.filter { ips[$0] != nil && !probes[$0].directOK && probes[$0].failure == nil }
        var wins: [(engine: DPIEngine, index: Int, hosts: Int)] = []
        var worked: [String: Set<Int>] = [:]          // "engine|index" -> host indices it opened
        var launchErrors: [EngineLaunchError] = []
        var triedAny: Set<Int> = []
        var lastFailure: [Int: ProbeFailure] = [:]
        let total = engines.reduce(0) { $0 + $1.strategies().count }
        var step = 0

        struct StrategyResult {
            var launchError: String?
            var opened: [Int: Int?] = [:]             // host index -> latency
            var failures: [Int: ProbeFailure] = [:]
        }

        if !pending.isEmpty {
            engineLoop: for engine in engines {
                let strategies = engine.strategies()
                for batchStart in stride(from: 0, to: strategies.count, by: DPIProbeSession.slots) {
                    if isCancelled() { break engineLoop }
                    let batch = Array(batchStart..<min(batchStart + DPIProbeSession.slots, strategies.count))
                    var results = [StrategyResult](repeating: StrategyResult(), count: batch.count)
                    DispatchQueue.concurrentPerform(iterations: batch.count) { slot in
                        let strategy = strategies[batch[slot]]
                        let n = lock.withLock { () -> Int in step += 1; return step }
                        progress(TuneProgress(phase: .strategy, engine: engine, strategy: strategy.label, step: n, total: total))
                        var result = StrategyResult()
                        let session = DPIProbeSession(engine: engine, flags: strategy.flags, slot: slot)
                        if let error = session.start(dryRun: { dryRun(engine, $0) }) {
                            result.launchError = error
                        } else if !isCancelled() {
                            let resultLock = NSLock()
                            DispatchQueue.concurrentPerform(iterations: pending.count) { k in
                                let i = pending[k]
                                guard let ip = ips[i] else { return }
                                let host = lock.withLock { probes[i].host }
                                let r = session.fetch(host: host, ip: ip, timeoutSec: Self.fetchTimeoutSec)
                                resultLock.withLock {
                                    if case .http(_, let ms) = r { result.opened[i] = ms }
                                    else if let f = r.failure { result.failures[i] = f }
                                }
                            }
                        }
                        session.stop()
                        lock.withLock { results[slot] = result }
                    }
                    var openedAll = false
                    for (slot, index) in batch.enumerated() {
                        let label = strategies[index].label
                        let r = results[slot]
                        if let error = r.launchError {
                            launchErrors.append(EngineLaunchError(engine: engine, strategy: label, message: error))
                            log("DPI auto-tune: \(engine.title) did not start with \(label): \(error)")
                            continue
                        }
                        for i in pending where r.opened[i] != nil || r.failures[i] != nil { triedAny.insert(i) }
                        for (i, f) in r.failures { lastFailure[i] = f }
                        for (i, ms) in r.opened where !probes[i].ok {
                            probes[i].ok = true
                            probes[i].engine = engine
                            probes[i].strategyIndex = index
                            probes[i].latencyMs = ms
                        }
                        worked["\(engine.rawValue)|\(index)"] = Set(r.opened.keys)
                        wins.append((engine, index, r.opened.count))
                        log("DPI auto-tune: \(engine.title) \(label) opened \(r.opened.count)/\(pending.count)")
                        if r.opened.count == pending.count { openedAll = true }
                    }
                    if openedAll { break engineLoop }
                }
            }
        }
        let cancelled = isCancelled()
        let winner = TuneReport.winner(wins)

        // Each opened host reports the winning strategy when it works there too, so the table matches
        // what will actually run.
        for i in pending {
            if let winner, worked["\(winner.engine.rawValue)|\(winner.index)"]?.contains(i) == true {
                probes[i].engine = winner.engine
                probes[i].strategyIndex = winner.index
            }
            if probes[i].ok {
                probes[i].failure = nil
            } else if cancelled {
                probes[i].failure = .cancelled
            } else if triedAny.contains(i) {
                probes[i].detail = [probes[i].detail, lastFailure[i].map { "bypass: \($0.rawValue)" }]
                    .compactMap { $0 }.joined(separator: ", ")
                probes[i].failure = .noStrategy
            } else if !launchErrors.isEmpty {
                probes[i].failure = .engineFailed
            }
        }
        return TuneReport(engine: winner?.engine, strategyIndex: winner?.index ?? -1, cancelled: cancelled,
                          hosts: probes, launchErrors: launchErrors, dnsSource: usedProvider ? upstream.title : nil)
    }
}

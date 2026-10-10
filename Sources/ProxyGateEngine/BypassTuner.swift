import Foundation
import PGCore

/// The DPI auto-tune, as a pipeline whose every stage can be told apart in the report:
/// DNS (system, then the profile's provider) -> TCP to the address -> plain HTTPS without bypass ->
/// each core and strategy. Hosts that fail an early stage never reach the strategies, so a DNS or
/// launch problem is never reported as "no strategy helped".
///
/// It probes the general test hosts and each `.directDPI` rule's hosts in one run (shared hosts are
/// probed once), then picks one strategy per core and, per rule, the core that opens it.
struct BypassTuner {
    /// Already sanitized (`TuneHosts.sanitize`).
    var hosts: [String]
    var rules: [TuneRuleInput]
    var upstream: DNSUpstream
    var allowIPv6: Bool
    /// Installed cores, the primary first (tie-break order).
    var engines: [DPIEngine]
    var dryRun: (DPIEngine, [String]) -> String?
    var isCancelled: () -> Bool
    var progress: (TuneProgress) -> Void
    var log: (String) -> Void

    static let maxHosts = TuneHosts.maxTotal
    static let fetchTimeoutSec = 6
    /// Probe fetches (curl processes) in flight at once across all cores and slots.
    static let maxFetches = 24

    /// Runs `body` for 0..<n on threads of its own and waits for all. The work blocks on DNS,
    /// sockets and curl, and nested concurrentPerform calls shrink to the CPU width (the per-host
    /// fetches inside a slot inside a core would end up nearly serial).
    static func parallel(_ n: Int, _ body: @escaping (Int) -> Void) {
        guard n > 0 else { return }
        let group = DispatchGroup()
        for i in 0..<n {
            group.enter()
            let thread = Thread {
                body(i)
                group.leave()
            }
            thread.stackSize = 512 * 1024
            thread.start()
        }
        group.wait()
    }

    func run() -> TuneReport {
        let fetchGate = DispatchSemaphore(value: Self.maxFetches)
        // Every unique host once: the general ones first, then the rules'.
        var names: [String] = []
        for h in hosts + rules.flatMap(\.hosts) where !names.contains(h) { names.append(h) }
        names = Array(names.prefix(Self.maxHosts))
        var probes = names.map { HostProbe(host: $0) }
        var ips: [IPAddr?] = Array(repeating: nil, count: probes.count)
        var usedProvider = false
        func cancelledReport() -> TuneReport {
            let general = probes.filter { hosts.contains($0.host) }
            return TuneReport(engine: nil, strategyIndex: -1, cancelled: true, hosts: general, launchErrors: [], dnsSource: nil)
        }

        // 1. DNS, every host at once: what apps get, and what the provider says.
        progress(TuneProgress(phase: .dns, total: probes.count))
        let lock = NSLock()
        Self.parallel(probes.count) { i in
            let host = names[i]
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
        Self.parallel(probes.count) { i in
            guard let ip = ips[i] else { return }
            let host = names[i]
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

        // 4. Strategies on the hosts that are reachable but blocked. Every installed core is tested
        // at the same time, each with several throwaway instances at once (own launchd label and
        // port per core and slot), each serving every pending host in parallel.
        let pending = probes.indices.filter { ips[$0] != nil && !probes[$0].directOK && probes[$0].failure == nil }
        var outcomes: [StrategyOutcome] = []
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
            Self.parallel(engines.count) { e in
                let engine = engines[e]
                let strategies = engine.strategies()
                for batchStart in stride(from: 0, to: strategies.count, by: DPIProbeSession.slots) {
                    if isCancelled() { return }
                    let batch = Array(batchStart..<min(batchStart + DPIProbeSession.slots, strategies.count))
                    var results = [StrategyResult](repeating: StrategyResult(), count: batch.count)
                    Self.parallel(batch.count) { slot in
                        let strategy = strategies[batch[slot]]
                        let n = lock.withLock { () -> Int in step += 1; return step }
                        progress(TuneProgress(phase: .strategy, engine: engine, strategy: strategy.label, step: n, total: total))
                        var result = StrategyResult()
                        let session = DPIProbeSession(engine: engine, flags: strategy.flags, slot: slot)
                        if let error = session.start(dryRun: { dryRun(engine, $0) }) {
                            result.launchError = error
                        } else if !isCancelled() {
                            let resultLock = NSLock()
                            Self.parallel(pending.count) { k in
                                let i = pending[k]
                                guard let ip = ips[i] else { return }
                                fetchGate.wait()
                                let r = session.fetch(host: names[i], ip: ip, timeoutSec: Self.fetchTimeoutSec)
                                fetchGate.signal()
                                resultLock.withLock {
                                    if case .http(_, let ms) = r { result.opened[i] = ms }
                                    else if let f = r.failure { result.failures[i] = f }
                                }
                            }
                        }
                        session.stop()
                        lock.withLock { results[slot] = result }
                    }
                    // Merge in strategy order, so ties stay deterministic whatever finished first.
                    var openedAll = false
                    lock.withLock {
                        for (slot, index) in batch.enumerated() {
                            let label = strategies[index].label
                            let r = results[slot]
                            if let error = r.launchError {
                                launchErrors.append(EngineLaunchError(engine: engine, strategy: label, message: error))
                                continue
                            }
                            for i in pending where r.opened[i] != nil || r.failures[i] != nil { triedAny.insert(i) }
                            for (i, f) in r.failures { lastFailure[i] = f }
                            var opened: [String: Int?] = [:]
                            for (i, ms) in r.opened { opened[names[i]] = ms }
                            outcomes.append(StrategyOutcome(engine: engine, index: index, opened: opened))
                            if r.opened.count == pending.count { openedAll = true }
                        }
                    }
                    for (slot, index) in batch.enumerated() {
                        let label = strategies[index].label
                        if let error = results[slot].launchError {
                            log("DPI auto-tune: \(engine.title) did not start with \(label): \(error)")
                        } else {
                            log("DPI auto-tune: \(engine.title) \(label) opened \(results[slot].opened.count)/\(pending.count)")
                        }
                    }
                    // This core already has a strategy that opens everything; the rest cannot beat it.
                    if openedAll { return }
                }
            }
        }
        let cancelled = isCancelled()

        // One strategy per core; the general hosts and each rule get the core that opens them best.
        let chosen = TuneChoice.strategies(outcomes)
        let general = TuneChoice.pick(hosts: hosts, outcomes: outcomes, chosen: chosen, order: engines)
        func outcome(_ engine: DPIEngine) -> StrategyOutcome? {
            chosen[engine].flatMap { index in outcomes.first { $0.engine == engine && $0.index == index } }
        }

        // Each blocked host reports what will actually run: the preferred core's chosen strategy if
        // it opens the host, else another core's chosen one. A host only a strategy that was not
        // chosen could open counts as not opened.
        func finalize(_ probe: HostProbe, index i: Int, prefer: DPIEngine?) -> HostProbe {
            var p = probe
            guard pending.contains(i) else { return p }
            let order = (prefer.map { [$0] } ?? []) + engines
            if let engine = order.first(where: { outcome($0)?.opened[p.host] != nil }), let o = outcome(engine) {
                p.ok = true
                p.engine = engine
                p.strategyIndex = o.index
                p.latencyMs = o.opened[p.host] ?? nil
                p.failure = nil
            } else if cancelled {
                p.failure = .cancelled
            } else if triedAny.contains(i) {
                let other = outcomes.contains { $0.opened[p.host] != nil }
                p.detail = [p.detail, lastFailure[i].map { "bypass: \($0.rawValue)" },
                            other ? "opens only with a strategy that was not chosen" : nil]
                    .compactMap { $0 }.joined(separator: ", ")
                p.failure = .noStrategy
            } else if !launchErrors.isEmpty {
                p.failure = .engineFailed
            }
            return p
        }

        let generalProbes = names.indices.filter { hosts.contains(names[$0]) }
            .map { finalize(probes[$0], index: $0, prefer: general?.engine) }

        var ruleResults: [RuleTuneResult] = []
        for rule in rules {
            let ruleHosts = rule.hosts.filter { names.contains($0) }
            guard !ruleHosts.isEmpty else { continue }
            let pick = TuneChoice.pick(hosts: ruleHosts, outcomes: outcomes, chosen: chosen, order: engines)
            let ruleProbes = ruleHosts.compactMap { h in names.firstIndex(of: h) }
                .map { finalize(probes[$0], index: $0, prefer: pick?.engine) }
            // ok: every host opens through the picked core or without bypass.
            let ok = ruleProbes.allSatisfy { $0.directOK || ($0.ok && $0.engine == pick?.engine) }
            ruleResults.append(RuleTuneResult(ruleID: rule.id, hosts: ruleProbes, engine: pick?.engine,
                                              strategyIndex: pick?.index ?? -1, ok: ok, latencyMs: pick?.latencyMs))
        }

        return TuneReport(engine: general?.engine, strategyIndex: general?.index ?? -1, cancelled: cancelled,
                          hosts: generalProbes, launchErrors: launchErrors, dnsSource: usedProvider ? upstream.title : nil,
                          rules: ruleResults, tpwsStrategyIndex: chosen[.tpws], byedpiStrategyIndex: chosen[.byedpi])
    }
}

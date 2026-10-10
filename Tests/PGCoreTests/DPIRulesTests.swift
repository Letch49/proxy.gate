import Foundation
import Testing
@testable import PGCore

@Test func probeHostsDerivedFromTargets() {
    // Geo categories, IPs, CIDRs, ranges and masks cannot be probed; "*.x.com" becomes "x.com".
    let hosts = TuneHosts.probeHosts(
        targetHosts: "geosite:youtube; geoip:ru; 192.0.2.1; 10.0.0.0/8; 10.0.0.1-10.0.0.9; 10.*; *.Example.com; youtu.be",
        testHosts: "")
    #expect(hosts == ["example.com", "youtu.be"])
    // Capped per rule, duplicates removed.
    #expect(TuneHosts.probeHosts(targetHosts: "a.com; *.a.com; b.com; c.com; d.com", testHosts: "") == ["a.com", "b.com", "c.com"])
    // A rule's own test hosts win over its targets.
    #expect(TuneHosts.probeHosts(targetHosts: "*.example.com", testHosts: "www.example.org") == ["www.example.org"])
    // Nothing probeable: no hosts.
    #expect(TuneHosts.probeHosts(targetHosts: "geosite:google; 10.0.0.0/8; localhost; api-?.x.com", testHosts: "").isEmpty)
    // The YouTube preset uses its own hosts.
    #expect(TuneHosts.probeHosts(for: Profile.youTubePreset()) == ["www.youtube.com", "redirector.googlevideo.com"])
}

@Test func testHostNormalization() {
    #expect(TuneHosts.normalize(" HTTPS://Www.Example.com:443/path?q ") == "www.example.com")
    #expect(TuneHosts.normalize("example.com.") == "example.com")
    #expect(TuneHosts.normalize("192.0.2.1") == nil)
    #expect(TuneHosts.normalize("1.2.3.4-1.2.3.5") == nil)
    #expect(TuneHosts.normalize("localhost") == nil)
    #expect(TuneHosts.normalize("*.example.com") == nil)
    #expect(TuneHosts.normalize("") == nil)
    #expect(TuneHosts.normalize("-flag.com") == nil)
    #expect(TuneHosts.parse("a.com; A.com, b.com\nbad host") == ["a.com", "b.com"])
}

@Test func tuneRequestSanitized() {
    let id = UUID()
    let junk = (0..<40).map { "h\($0).example.com" }
    let (general, rules) = TuneHosts.sanitize(
        general: ["a.com", "a.com", "-x", "192.0.2.1"] + junk,
        rules: [TuneRuleInput(id: id, hosts: ["a.com", "r1.com", "r2.com", "r3.com", "r4.com"]),
                TuneRuleInput(id: id, hosts: ["dup.com"]),               // same id twice: dropped
                TuneRuleInput(id: UUID(), hosts: ["not a host"])])        // nothing valid: dropped
    #expect(general.count == TuneHosts.maxGeneral)
    #expect(general.first == "a.com")
    #expect(rules.count == 1)
    #expect(rules[0].hosts == ["a.com", "r1.com", "r2.com"])           // per-rule cap
    // The unique total stays under the cap.
    let many = (0..<20).map { TuneRuleInput(id: UUID(), hosts: ["x\($0).com", "y\($0).com", "z\($0).com"]) }
    let capped = TuneHosts.sanitize(general: [], rules: many)
    let unique = Set(capped.general + capped.rules.flatMap(\.hosts))
    #expect(unique.count == TuneHosts.maxTotal)
    // An empty request falls back to the default test hosts.
    #expect(TuneHosts.sanitize(general: [], rules: []).general == ["instagram.com", "discord.com"])
}

@Test func tuneChoosesOneStrategyPerEngineAndAnEnginePerRule() {
    let outcomes = [
        StrategyOutcome(engine: .tpws, index: 0, opened: ["a.com": 100]),
        StrategyOutcome(engine: .tpws, index: 1, opened: ["a.com": 300, "b.com": 300]),
        StrategyOutcome(engine: .tpws, index: 2, opened: ["c.com": 50, "d.com": 50]),       // ties index 1: earlier wins
        StrategyOutcome(engine: .byedpi, index: 0, opened: [:]),
        StrategyOutcome(engine: .byedpi, index: 3, opened: ["a.com": 80, "c.com": 90]),
    ]
    let chosen = TuneChoice.strategies(outcomes)
    #expect(chosen == [.tpws: 1, .byedpi: 3])
    #expect(TuneChoice.strategies([StrategyOutcome(engine: .tpws, index: 0, opened: [:])]).isEmpty)

    // Most hosts wins.
    let b = TuneChoice.pick(hosts: ["a.com", "b.com"], outcomes: outcomes, chosen: chosen, order: [.tpws, .byedpi])
    #expect(b?.engine == .tpws && b?.index == 1 && b?.opened == 2)
    // Same count: lower latency wins, even over the primary core.
    let a = TuneChoice.pick(hosts: ["a.com"], outcomes: outcomes, chosen: chosen, order: [.tpws, .byedpi])
    #expect(a?.engine == .byedpi && a?.latencyMs == 80)
    // Only the other core opens it.
    #expect(TuneChoice.pick(hosts: ["c.com"], outcomes: outcomes, chosen: chosen, order: [.tpws, .byedpi])?.engine == .byedpi)
    // Opened only by a strategy that was not chosen: no pick.
    #expect(TuneChoice.pick(hosts: ["d.com"], outcomes: outcomes, chosen: chosen, order: [.tpws, .byedpi]) == nil)
    // Unknown latency on both: the order (primary first) decides.
    let flat = [StrategyOutcome(engine: .tpws, index: 0, opened: ["x.com": nil]),
                StrategyOutcome(engine: .byedpi, index: 0, opened: ["x.com": nil])]
    #expect(TuneChoice.pick(hosts: ["x.com"], outcomes: flat, chosen: [.tpws: 0, .byedpi: 0], order: [.byedpi, .tpws])?.engine == .byedpi)
}

@Test func dpiRoutingPicksTheCore() {
    let both: Set<DPIEngine> = [.tpws, .byedpi]
    #expect(DPIRouting.ruleCore(.byedpi, primary: .tpws, running: both) == .byedpi)
    #expect(DPIRouting.ruleCore(nil, primary: .tpws, running: both) == .tpws)
    #expect(DPIRouting.ruleCore(.byedpi, primary: .byedpi, running: [.tpws]) == .tpws)   // falls over to the running one
    #expect(DPIRouting.ruleCore(nil, primary: .tpws, running: []) == nil)               // plain direct

    #expect(DPIRouting.directCore(bypassOn: true, allDirect: true, primary: .byedpi, running: both, privateDestination: false) == .byedpi)
    #expect(DPIRouting.directCore(bypassOn: true, allDirect: false, primary: .tpws, running: both, privateDestination: false) == nil)
    #expect(DPIRouting.directCore(bypassOn: false, allDirect: true, primary: .tpws, running: both, privateDestination: false) == nil)
    #expect(DPIRouting.directCore(bypassOn: true, allDirect: true, primary: .tpws, running: [.byedpi], privateDestination: false) == nil)
    #expect(DPIRouting.directCore(bypassOn: true, allDirect: true, primary: .tpws, running: both, privateDestination: true) == nil)
    #expect(DPIEngine.byedpi.socksPort == PGConstants.byedpiSocksPort)
}

@Test func profileMigratesOldDPIKeys() throws {
    // An earlier build's profile: one strategy index for its one engine, the old default test hosts,
    // and the learned autohostlist (now ignored).
    let old = """
    {"name": "Old", "rules": [], "dpiEngine": "byedpi", "bypassStrategyIndex": 4,
     "dpiTestHosts": "\(Profile.legacyDpiTestHosts)",
     "bypassAutohostlist": true, "bypassHosts": ["example.com"]}
    """
    let p = try JSONDecoder().decode(Profile.self, from: Data(old.utf8))
    #expect(p.byedpiStrategyIndex == 4 && p.tpwsStrategyIndex == 0)
    #expect(p.dpiTestHosts == Profile.defaultDpiTestHosts)
    #expect(!p.bypassAllDirect)
    #expect(!p.youTubePresetOffered)

    // Without a learned list, earlier builds bypassed all direct traffic; that is kept.
    let wide = try JSONDecoder().decode(Profile.self, from: Data("""
    {"name": "Wide", "rules": [], "bypassAutohostlist": false, "bypassHosts": ["example.com"]}
    """.utf8))
    #expect(wide.bypassAllDirect)
    let empty = try JSONDecoder().decode(Profile.self, from: Data("""
    {"name": "Empty", "rules": [], "bypassAutohostlist": true, "bypassHosts": []}
    """.utf8))
    #expect(empty.bypassAllDirect)

    // A custom list and the new keys are kept as they are.
    let custom = """
    {"name": "New", "rules": [], "dpiEngine": "tpws", "tpwsStrategyIndex": 2, "byedpiStrategyIndex": 1,
     "bypassStrategyIndex": 5, "dpiTestHosts": "a.example.com", "bypassAllDirect": true}
    """
    let q = try JSONDecoder().decode(Profile.self, from: Data(custom.utf8))
    #expect(q.tpwsStrategyIndex == 2 && q.byedpiStrategyIndex == 1)
    #expect(q.dpiTestHosts == "a.example.com" && q.bypassAllDirect)

    // Out-of-range indices are clamped when read.
    var r = q
    r.tpwsStrategyIndex = 99
    #expect(r.strategyIndex(for: .tpws) == 0)
    #expect(r.strategyFlags(for: .byedpi) == ByeDpiStrategies.all[1].flags)

    // Round trip keeps everything, the rule fields included.
    var s = Profile.makeDefault()
    s.rules[0].dpiEngine = .byedpi
    s.rules[0].testHosts = "www.example.com"
    let back = try JSONDecoder().decode(Profile.self, from: JSONEncoder().encode(s))
    #expect(back == s)
}

@Test func ruleDecodesWithoutDPIFields() throws {
    let rule = try JSONDecoder().decode(Rule.self, from: Data(#"{"name": "x", "action": {"directDPI": {}}}"#.utf8))
    #expect(rule.action == .directDPI && rule.dpiEngine == nil && rule.testHosts.isEmpty)
}

@Test func youTubePresetSeededOnce() {
    let fresh = Profile.makeDefault()
    #expect(fresh.rules[0].name == "YouTube")
    #expect(fresh.rules[0].action == .directDPI && !fresh.rules[0].enabled)
    #expect(fresh.hasYouTubeRule && fresh.youTubePresetOffered)
    #expect(TuneHosts.probeHosts(for: fresh.rules[0]).count == 2)

    // An existing profile gets it once, at the top.
    var old = Profile(name: "Old", rules: [Rule(name: "Default", action: .global, isDefault: true)])
    #expect(old.offerYouTubePreset())
    #expect(old.rules.first?.name == "YouTube" && old.rules.count == 2)
    old.rules.removeFirst()                       // the user deletes it
    #expect(!old.offerYouTubePreset())
    #expect(!old.hasYouTubeRule)

    // Not added when a rule already targets YouTube.
    var own = Profile(name: "Own", rules: [Rule(name: "Mine", targetHosts: "*.YouTube.com", action: .vpn),
                                           Rule(name: "Default", action: .global, isDefault: true)])
    #expect(own.offerYouTubePreset())             // marks it offered
    #expect(own.rules.count == 2 && own.rules[0].name == "Mine")
}

@Test func verdictCountsRuleResults() {
    var open = HostProbe(host: "a.example.com")
    open.directOK = true
    var blocked = HostProbe(host: "b.example.com", strategyIndex: 1, engine: .byedpi, ok: true)
    blocked.latencyMs = 50
    let rule = RuleTuneResult(ruleID: UUID(), hosts: [blocked], engine: .byedpi, strategyIndex: 1, ok: true, latencyMs: 50)
    // The general hosts open directly, but a rule needed (and got) a core: found, not "not blocked".
    #expect(TuneReport(engine: nil, strategyIndex: -1, cancelled: false, hosts: [open], launchErrors: [],
                       dnsSource: nil, rules: [rule]).verdict == .found)
    // No general hosts and every rule host opens directly: not blocked.
    let fine = RuleTuneResult(ruleID: UUID(), hosts: [open], engine: nil, strategyIndex: -1, ok: true, latencyMs: nil)
    #expect(TuneReport(engine: nil, strategyIndex: -1, cancelled: false, hosts: [], launchErrors: [],
                       dnsSource: nil, rules: [fine]).verdict == .notBlocked)
}

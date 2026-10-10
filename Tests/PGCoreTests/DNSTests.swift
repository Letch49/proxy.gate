import Foundation
import Testing
@testable import PGCore

// No test here touches the network or the Mac's DNS settings: wire format, cache, validation and
// the auto-tune decisions are all pure.

private func u16(_ n: Int) -> [UInt8] { [UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }
private func u32(_ n: UInt32) -> [UInt8] { [UInt8(n >> 24), UInt8((n >> 16) & 0xFF), UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)] }

/// A response to `query` with answers / authority built by hand, names compressed to the question.
private func response(to query: [UInt8], rcode: UInt8 = 0, answers: [[UInt8]] = [], authority: [[UInt8]] = []) -> [UInt8] {
    var out = query
    out[2] = 0x81
    out[3] = 0x80 | rcode
    out[6...7] = ArraySlice(u16(answers.count))
    out[8...9] = ArraySlice(u16(authority.count))
    for rr in answers + authority { out += rr }
    return out
}

/// Resource record whose owner is a pointer to the question name (offset 12).
private func rr(type: Int, ttl: UInt32, data: [UInt8]) -> [UInt8] {
    [0xC0, 12] + u16(type) + u16(1) + u32(ttl) + u16(data.count) + data
}

private func soa(ttl: UInt32, minimum: UInt32) -> [UInt8] {
    let data: [UInt8] = [0xC0, 12, 0xC0, 12] + u32(1) + u32(2) + u32(3) + u32(4) + u32(minimum)
    return rr(type: 6, ttl: ttl, data: data)
}

@Test func dnsQueryRoundTrip() throws {
    let q = try #require(DNSMessage.query(name: "www.YouTube.com", type: .a, id: 0x1234))
    #expect(DNSMessage.id(of: q) == 0x1234)
    let question = try #require(DNSMessage.question(of: q))
    #expect(question.name == "www.youtube.com")
    #expect(question.type == 1)
    #expect(DNSMessage.query(name: "bad name", type: .a) == nil)
    #expect(DNSMessage.query(name: String(repeating: "a", count: 64) + ".com", type: .a) == nil)
}

@Test func dnsParsesAnswersWithCompressionAndCNAME() throws {
    let q = try #require(DNSMessage.query(name: "www.example.com", type: .a, id: 7))
    let cname = rr(type: 5, ttl: 300, data: [3] + Array("abc".utf8) + [0xC0, 16])
    let a1 = rr(type: 1, ttl: 120, data: [192, 0, 2, 1])
    let a2 = rr(type: 1, ttl: 60, data: [192, 0, 2, 2])
    let aaaa = rr(type: 28, ttl: 90, data: [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [1])
    let r = try #require(DNSMessage.parse(response(to: q, answers: [cname, a1, a2, aaaa])))
    #expect(r.rcode == 0)
    #expect(r.addresses.map(\.description) == ["192.0.2.1", "192.0.2.2", "2001:db8::1"])
    #expect(r.minTTL == 60)
    let o = DNSOutcome.from(r)
    #expect(o.status == .ok)
    #expect(o.ttl == 60)
}

@Test func dnsNegativeAnswersUseSOA() throws {
    let q = try #require(DNSMessage.query(name: "blocked.example", type: .a))
    let nx = try #require(DNSMessage.parse(response(to: q, rcode: 3, authority: [soa(ttl: 900, minimum: 60)])))
    #expect(nx.negativeTTL == 60)
    #expect(DNSOutcome.from(nx).status == .nxdomain)
    let empty = try #require(DNSMessage.parse(response(to: q, rcode: 0)))
    #expect(DNSOutcome.from(empty).status == .noData)
    let servfail = try #require(DNSMessage.parse(response(to: q, rcode: 2)))
    #expect(DNSOutcome.from(servfail).status == .failed)
}

@Test func dnsParserSurvivesJunk() {
    #expect(DNSMessage.parse([]) == nil)
    #expect(DNSMessage.parse([UInt8](repeating: 0xFF, count: 11)) == nil)
    // A name that points at itself must not loop forever.
    var loop: [UInt8] = [0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]
    loop += [0xC0, 12, 0, 1, 0, 1]
    #expect(DNSMessage.parse(loop) == nil)
    // Answer count larger than the data.
    var short: [UInt8] = [0, 1, 0x81, 0x80, 0, 0, 0, 5, 0, 0, 0, 0]
    short += [1, 0x61, 0]
    #expect(DNSMessage.parse(short) == nil)
    for seed in 0..<200 {
        var rng = SystemRandomNumberGenerator()
        let junk = (0..<(12 + seed % 60)).map { _ in UInt8.random(in: 0...255, using: &rng) }
        _ = DNSMessage.parse(junk)
        _ = DNSMessage.question(of: junk)
        _ = DNSMessage.reply(to: junk, rcode: 2)
    }
}

@Test func dnsReplyKeepsIDAndQuestion() throws {
    let q = try #require(DNSMessage.query(name: "corp.example", type: .aaaa, id: 0xBEEF))
    let refused = try #require(DNSMessage.reply(to: q, rcode: DNSMessage.rcodeRefused))
    let r = try #require(DNSMessage.parse(refused))
    #expect(r.id == 0xBEEF)
    #expect(r.rcode == 5)
    #expect(r.question?.name == "corp.example")
    #expect(r.answerCount == 0)
    // A response is not a query: the stub must not answer it.
    #expect(DNSMessage.question(of: refused) == nil)
}

@Test func dnsCacheHonorsTTLAndNegativeAnswers() throws {
    var clock = Date(timeIntervalSince1970: 1000)
    let cache = DNSCache(now: { clock })
    let q = try #require(DNSMessage.query(name: "www.example.com", type: .a, id: 1))
    let question = try #require(DNSMessage.question(of: q))
    let ok = response(to: q, answers: [rr(type: 1, ttl: 120, data: [192, 0, 2, 1])])
    let parsed = try #require(DNSMessage.parse(ok))
    let life = try #require(DNSCache.lifetime(of: parsed))
    #expect(life == 120)
    cache.put(question, message: ok, seconds: life)
    let hit = try #require(cache.get(question, id: 0x4242))
    #expect(DNSMessage.id(of: hit) == 0x4242)              // the asker's id, not the cached one
    clock.addTimeInterval(121)
    #expect(cache.get(question, id: 1) == nil)

    // TTLs are clamped, NXDOMAIN cached by SOA, failures never.
    let tiny = try #require(DNSMessage.parse(response(to: q, answers: [rr(type: 1, ttl: 0, data: [192, 0, 2, 1])])))
    #expect(DNSCache.lifetime(of: tiny) == DNSCache.minTTL)
    let huge = try #require(DNSMessage.parse(response(to: q, answers: [rr(type: 1, ttl: 999_999, data: [192, 0, 2, 1])])))
    #expect(DNSCache.lifetime(of: huge) == DNSCache.maxTTL)
    let nx = try #require(DNSMessage.parse(response(to: q, rcode: 3, authority: [soa(ttl: 50_000, minimum: 50_000)])))
    #expect(DNSCache.lifetime(of: nx) == DNSCache.maxNegativeTTL)
    let nxNoSOA = try #require(DNSMessage.parse(response(to: q, rcode: 3)))
    #expect(DNSCache.lifetime(of: nxNoSOA) == DNSCache.defaultNegativeTTL)
    let fail = try #require(DNSMessage.parse(response(to: q, rcode: 2)))
    #expect(DNSCache.lifetime(of: fail) == nil)
}

@Test func dnsCacheIsBounded() throws {
    let cache = DNSCache(capacity: 4)
    for i in 0..<10 {
        let q = try #require(DNSMessage.query(name: "h\(i).example.com", type: .a))
        cache.put(try #require(DNSMessage.question(of: q)), message: q, seconds: 60)
    }
    #expect(cache.count <= 4)
}

@Test func dnsOutcomeMergeAndSystemCodes() {
    let a = DNSOutcome(status: .ok, addresses: ["192.0.2.1"], ttl: 30)
    let none = DNSOutcome(status: .noData)
    #expect(DNSOutcome.merge(none, DNSOutcome(status: .ok, addresses: ["2001:db8::1"], ttl: 10)).status == .ok)
    #expect(DNSOutcome.merge(a, none).addresses == ["192.0.2.1"])
    #expect(DNSOutcome.merge(none, DNSOutcome(status: .nxdomain)).status == .nxdomain)
    #expect(DNSOutcome.merge(DNSOutcome(status: .timeout), DNSOutcome(status: .timeout)).status == .timeout)
    #expect(DNSOutcome.fromGAI(EAI_NONAME).status == .nxdomain)
    #expect(DNSOutcome.fromGAI(EAI_AGAIN).status == .timeout)
}

@Test func dnsDomainListIsStrict() {
    let r = DNSDomainList.parse("youtube.com; *.ytimg.com; GoogleVideo.com.; ../etc/passwd; local; printer.local; 1.0.0.127.in-addr.arpa; com; 10.0.0.1; a b.com; youtube.com")
    #expect(r.valid == ["youtube.com", "ytimg.com", "googlevideo.com"])
    #expect(r.invalid.count == 7)                       // the duplicate is dropped, not "invalid"
    #expect(DNSDomainList.covers(r.valid, host: "rr1.googlevideo.com"))
    #expect(DNSDomainList.covers(r.valid, host: "youtube.com"))
    #expect(!DNSDomainList.covers(r.valid, host: "notyoutube.com"))
    #expect(!DNSDomainList.covers(r.valid, host: "intranet.corp.example"))
    #expect(DNSDomainList.suggestion(for: "www.youtube.com") == "youtube.com")
    #expect(DNSDomainList.suggestion(for: "localhost") == nil)
    let many = (0..<100).map { "d\($0).example" }.joined(separator: ";")
    #expect(DNSDomainList.parse(many).valid.count == DNSDomainList.maxCount)
}

@Test func dnsProviderValidation() throws {
    let ok = try DNSProvider.custom(name: "Home", addresses: "192.0.2.53; 2001:db8::53", dohURL: "https://dns.example/dns-query").get()
    #expect(ok.ips.count == 2)
    #expect(ok.supportsDoH)
    #expect(ok.isValid)
    #expect(throws: DNSInputError.addresses) { try DNSProvider.custom(name: "X", addresses: "dns.example", dohURL: "").get() }
    #expect(throws: DNSInputError.addresses) { try DNSProvider.custom(name: "X", addresses: "192.0.2.1; junk", dohURL: "").get() }
    #expect(throws: DNSInputError.name) { try DNSProvider.custom(name: " ", addresses: "192.0.2.1", dohURL: "").get() }
    #expect(throws: DNSInputError.dohURL) { try DNSProvider.custom(name: "X", addresses: "192.0.2.1", dohURL: "http://dns.example/q").get() }

    #expect(DoHEndpoint("https://dns.example/dns-query")?.port == 443)
    #expect(DoHEndpoint("https://dns.example:8443/q")?.port == 8443)
    #expect(DoHEndpoint("https://dns.example")?.path == "/dns-query")
    #expect(DoHEndpoint("https://user:pw@dns.example/q") == nil)
    #expect(DoHEndpoint("https://dns.example/q?x=1") == nil)
    #expect(DoHEndpoint("https://dns.example/q\r\nX: y") == nil)

    // A provider that arrived over the socket with junk is rejected by the engine.
    let forged = DNSProvider(id: "x", name: "x", addresses: ["192.0.2.1", "not-an-ip"], dohURL: nil)
    #expect(!forged.isValid)
    for p in DNSProviders.builtIn { #expect(p.isValid) }
    #expect(DNSProviders.builtIn.first { $0.id == "google" }?.supportsDoH == true)
}

@Test func dnsSettingsSelectionAndDecoding() throws {
    var s = DNSSettings()
    #expect(s.provider.id == "google")
    #expect(s.upstream.transport == .doh)
    s.providerID = "deleted"
    #expect(s.provider.id == DNSProviders.builtIn[0].id)
    let plain = DNSProvider(id: "p", name: "Plain", addresses: ["192.0.2.53"], dohURL: nil)
    s.customProviders = [plain]
    s.providerID = "p"
    #expect(s.upstream.transport == .udp)                // no DoH: falls back to plain DNS
    #expect(s.upstream.title == "Plain (DNS)")

    // An old profile without the new keys keeps its values and gets the defaults.
    let old = #"{"sniffHostnames":false,"sendHostnameToProxy":true,"sniffTimeoutMs":500}"#
    let decoded = try JSONDecoder().decode(DNSSettings.self, from: Data(old.utf8))
    #expect(!decoded.sniffHostnames)
    #expect(decoded.sniffTimeoutMs == 500)
    #expect(decoded.providerID == "google")
    #expect(!decoded.resolveThroughProvider)
    #expect(decoded.resolveDomains == DNSSettings.defaultResolveDomains)
}

@Test func resolverFileMarker() {
    let body = ResolverFile.body(port: 52153)
    #expect(body.contains("nameserver 127.0.0.1\nport 52153\n"))
    #expect(ResolverFile.isOurs(body))
    #expect(!ResolverFile.isOurs("nameserver 10.0.0.1\n"))
}

@Test func dohHTTPFraming() {
    let req = String(decoding: DoHHTTP.request(host: "dns.example", port: 443, path: "/dns-query", body: [1, 2, 3]), as: UTF8.self)
    #expect(req.hasPrefix("POST /dns-query HTTP/1.1\r\nHost: dns.example\r\n"))
    #expect(req.contains("Content-Length: 3\r\n"))

    let head = Array("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\n".utf8)
    #expect(DoHHTTP.parse(head + [9, 9], complete: false) == .incomplete)
    #expect(DoHHTTP.parse(head + [9, 9, 9, 9], complete: false) == .complete(status: 200, body: [9, 9, 9, 9]))
    #expect(DoHHTTP.parse(head + [9], complete: true) == .invalid)

    let chunkedHead = Array("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".utf8)
    let chunks = Array("2\r\n".utf8) + [7, 8] + Array("\r\n1\r\n".utf8) + [9] + Array("\r\n0\r\n\r\n".utf8)
    #expect(DoHHTTP.parse(chunkedHead + chunks, complete: false) == .complete(status: 200, body: [7, 8, 9]))
    #expect(DoHHTTP.parse(chunkedHead + Array(chunks.prefix(6)), complete: false) == .incomplete)

    #expect(DoHHTTP.parse(Array("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".utf8), complete: false) == .complete(status: 403, body: []))
    #expect(DoHHTTP.parse(Array("garbage\r\n\r\n".utf8), complete: true) == .invalid)
}

@Test func curlOutcomeClassification() {
    #expect(CurlOutcome.classify(exitCode: 0, output: "200 0.120 0.300") == .http(code: 200, ms: 300))
    #expect(CurlOutcome.classify(exitCode: 0, output: "403 0.1 0.2") == .http(code: 403, ms: 200))
    // TCP up, handshake never finished: the DPI signature.
    #expect(CurlOutcome.classify(exitCode: 28, output: "000 0.000000 6.0") == .tlsTimeout)
    #expect(CurlOutcome.classify(exitCode: 28, output: "000 0.2 6.0") == .timeout)
    #expect(CurlOutcome.classify(exitCode: 35, output: "000 0 0.1") == .tlsError)
    #expect(CurlOutcome.classify(exitCode: 56, output: "") == .tlsError)
    #expect(CurlOutcome.classify(exitCode: 60, output: "000 0 0.1") == .certError)
    #expect(CurlOutcome.classify(exitCode: 7, output: "000 0 0") == .connectFailed)
    #expect(CurlOutcome.classify(exitCode: 97, output: "000 0 0") == .proxyFailed)
    #expect(CurlOutcome.classify(exitCode: 0, output: "000 0 0") == .other(0))
    #expect(CurlOutcome.tlsTimeout.failure == .tlsTimeout)
    #expect(CurlOutcome.connectFailed.failure == .tcpFailed)
}

private func host(_ name: String, ok: Bool = false, direct: Bool = false, failure: ProbeFailure? = nil) -> HostProbe {
    var p = HostProbe(host: name, ok: ok)
    p.directOK = direct
    p.failure = failure
    return p
}

private func report(_ hosts: [HostProbe], engine: DPIEngine? = nil, index: Int = -1, cancelled: Bool = false) -> TuneReport {
    TuneReport(engine: engine, strategyIndex: index, cancelled: cancelled, hosts: hosts, launchErrors: [], dnsSource: nil)
}

@Test func tuneVerdictSeparatesCauses() {
    #expect(report([host("a", ok: true)], engine: .tpws, index: 0).verdict == .found)
    #expect(report([host("a", ok: true, direct: true)]).verdict == .notBlocked)
    // DNS failures are never reported as "no strategy helped".
    #expect(report([host("a", failure: .dnsNotFound), host("b", failure: .dnsTimeout)]).verdict == .dnsProblem)
    #expect(report([host("a", failure: .dnsNotFound), host("b", ok: true, direct: true)]).verdict == .dnsProblem)
    #expect(report([host("a", failure: .engineFailed), host("b", failure: .dnsNotFound)]).verdict == .engineProblem)
    #expect(report([host("a", failure: .tcpFailed)]).verdict == .ipBlocked)
    #expect(report([host("a", failure: .noStrategy), host("b", failure: .dnsNotFound)]).verdict == .noStrategy)
    #expect(report([host("a", failure: .noStrategy)], cancelled: true).verdict == .cancelled)
}

@Test func tuneWinnerAndPlan() {
    let w = TuneReport.winner([(.tpws, 0, 1), (.tpws, 2, 2), (.byedpi, 1, 2), (.byedpi, 3, 0)])
    #expect(w?.engine == .tpws && w?.index == 2)       // ties keep the engine tried first
    #expect(TuneReport.winner([(.tpws, 0, 0)]) == nil)

    #expect(TunePlan.engines(active: .byedpi, installed: [.tpws, .byedpi]) == [.byedpi, .tpws])
    #expect(TunePlan.engines(active: .byedpi, installed: [.tpws]) == [.tpws])
    #expect(TunePlan.engines(active: .tpws, installed: []).isEmpty)

    let sys = DNSOutcome(status: .ok, addresses: ["2001:db8::1", "192.0.2.1"])
    let pick = TunePlan.address(system: sys, provider: nil, allowIPv6: false)
    #expect(pick?.ip.description == "192.0.2.1" && pick?.fromSystem == true)
    // A sinkhole answer (0.0.0.0) counts as broken: the provider's address is used.
    let sinkhole = DNSOutcome(status: .ok, addresses: ["0.0.0.0"])
    let viaProvider = TunePlan.address(system: sinkhole, provider: DNSOutcome(status: .ok, addresses: ["192.0.2.9"]), allowIPv6: true)
    #expect(viaProvider?.ip.description == "192.0.2.9" && viaProvider?.fromSystem == false)
    #expect(TunePlan.address(system: DNSOutcome(status: .ok, addresses: ["2001:db8::1"]), provider: nil, allowIPv6: false) == nil)
    #expect(TunePlan.dnsFailure(system: DNSOutcome(status: .nxdomain), provider: DNSOutcome(status: .timeout)) == .dnsNotFound)
    #expect(TunePlan.dnsFailure(system: DNSOutcome(status: .timeout), provider: DNSOutcome(status: .timeout)) == .dnsTimeout)

    var h = HostProbe(host: "www.example.com")
    h.systemDNS = DNSOutcome(status: .nxdomain)
    #expect(h.appsCannotResolve)
}

@Test func dnsCheckDetectsRewrittenPlainDNS() {
    let doh = DNSOutcome(status: .ok, addresses: ["192.0.2.1"])
    #expect(DNSCheckReport.differs(DNSOutcome(status: .ok, addresses: ["198.51.100.1"]), doh))
    #expect(!DNSCheckReport.differs(DNSOutcome(status: .ok, addresses: ["192.0.2.1", "192.0.2.2"]), doh))
    #expect(DNSCheckReport.differs(DNSOutcome(status: .nxdomain), doh))
    #expect(!DNSCheckReport.differs(DNSOutcome(status: .timeout), DNSOutcome(status: .timeout)))
}

@Test func tuneReportCodableRoundTrip() throws {
    var h = HostProbe(host: "www.example.com", strategyIndex: 1, engine: .byedpi, ok: true, latencyMs: 80)
    h.systemDNS = DNSOutcome(status: .nxdomain)
    h.dnsSource = "Google (DoH)"
    let r = TuneReport(engine: .byedpi, strategyIndex: 1, cancelled: false, hosts: [h],
                       launchErrors: [EngineLaunchError(engine: .tpws, strategy: "x", message: "invalid option")], dnsSource: "Google (DoH)")
    let msg = EngineMessage.bypassTuned(r)
    let back = try JSONDecoder().decode(EngineMessage.self, from: JSONEncoder().encode(msg))
    guard case .bypassTuned(let decoded) = back else { Issue.record("wrong case"); return }
    #expect(decoded.hosts == [h])
    #expect(decoded.verdict == .found)
}

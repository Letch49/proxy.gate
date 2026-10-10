import Foundation
import Testing
@testable import PGCore

private func be16(_ n: Int) -> [UInt8] { [UInt8(n >> 8), UInt8(n & 0xFF)] }

private func clientHello(sni: String) -> [UInt8] {
    let name = Array(sni.utf8)
    let entry: [UInt8] = [0] + be16(name.count) + name
    let list = be16(entry.count) + entry
    let alpn: [UInt8] = be16(16) + be16(4) + [0, 2, 0x68, 0x32]
    let sniExt = be16(0) + be16(list.count) + list
    let extensions = alpn + sniExt
    let body: [UInt8] = [3, 3] + [UInt8](repeating: 7, count: 32) + [0] + be16(2) + [0x13, 0x01] + [1, 0] + be16(extensions.count) + extensions
    let handshake: [UInt8] = [1, 0] + be16(body.count) + body
    return [0x16, 3, 1] + be16(handshake.count) + handshake
}

private func app(_ name: String, bundle: String? = nil, bundles: [String] = []) -> AppIdentity {
    var a = AppIdentity(pid: 1, name: name)
    a.bundleID = bundle
    a.bundleNames = bundles
    return a
}

@Test func globMatching() {
    #expect(globMatch("*.ru", "ya.ru"))
    #expect(globMatch("192.168.*.*", "192.168.1.5"))
    #expect(globMatch("co?ex", "codex"))
    #expect(!globMatch("*.ru", "ya.com"))
    #expect(globMatch("*", ""))
}

@Test func ipParsing() {
    #expect(IPAddr("192.0.2.10")?.bytes == [192, 0, 2, 10])
    #expect(IPAddr("::ffff:1.2.3.4")?.isV4 == true)
    #expect(IPAddr("[2001:db8::1]")?.description == "2001:db8::1")
    #expect(IPAddr("example.com") == nil)
    #expect(IPAddr("10.0.0.0")!.sharesPrefix(with: IPAddr("10.200.1.1")!, bits: 8))
    #expect(!IPAddr("10.0.0.0")!.sharesPrefix(with: IPAddr("11.0.0.1")!, bits: 8))
}

@Test func sniffing() {
    let hello = clientHello(sni: "Ab.ChatGPT.com")
    #expect(Sniffer.hostname(from: hello) == "ab.chatgpt.com")
    #expect(Sniffer.tlsRecordComplete(hello) == true)
    #expect(Sniffer.tlsRecordComplete(Array(hello.prefix(20))) == false)
    #expect(Sniffer.hostname(from: Array("GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n".utf8)) == "example.com")
    #expect(Sniffer.hostname(from: Array("GET / HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n".utf8)) == nil)
    #expect(Sniffer.hostname(from: Array("GET / HTTP/1.1\r\nHost: evil\r\nX: y\r\n\r\n".utf8)) == "evil")
    #expect(Sniffer.hostname(from: [0x16, 3, 1]) == nil)
}

@Test func ruleMatching() {
    var profile = Profile.makeDefault()
    let proxy = ProxyServer(host: "192.0.2.10", port: 3128, type: .https)
    profile.proxies = [proxy]
    profile.rules[profile.rules.count - 1].action = .proxy(proxy.id)
    profile.rules.insert(Rule(name: "uv", applications: "uv", action: .direct), at: 0)
    profile.rules.insert(Rule(name: "New", targetHosts: "*.local; *.ru; 10.0.0.0-10.255.255.255; 192.168.0.0/16", action: .direct), at: 1)
    profile.rules.insert(Rule(name: "Chrome ssh", applications: "Google Chrome", targetPorts: "22; 8000-9000", action: .block), at: 2)
    let rules = RuleSet(profile: profile, computerName: "mac")

    func match(_ a: AppIdentity, _ host: String?, _ ip: String, _ port: UInt16) -> String {
        rules.match(MatchRequest(app: a, hostname: host, ip: IPAddr(ip)!, port: port)).name
    }

    let chrome = app("Google Chrome Helper", bundle: "com.google.Chrome.helper", bundles: ["Google Chrome", "Google Chrome Helper"])
    #expect(match(app("uv"), "pypi.org", "151.101.0.223", 443) == "uv")
    #expect(match(chrome, "ya.ru", "5.255.255.242", 443) == "New")
    #expect(match(chrome, nil, "10.1.2.3", 443) == "New")
    #expect(match(chrome, nil, "192.168.3.3", 80) == "New")
    #expect(match(chrome, "github.com", "140.82.121.4", 8080) == "Chrome ssh")
    #expect(match(chrome, "github.com", "140.82.121.4", 443) == "Default")
    #expect(match(app("codex"), "localhost", "127.0.0.1", 80) == "Local networks — direct")

    profile.rules[1].enabled = false
    #expect(RuleSet(profile: profile).match(MatchRequest(app: chrome, hostname: "ya.ru", ip: IPAddr("5.255.255.242")!, port: 443)).name == "Default")
}

/// The same target grammar (host wildcards, IP masks, ranges, CIDR) works for any action.
@Test func universalHostTargets() throws {
    var profile = Profile.makeDefault()
    profile.rules.insert(Rule(name: "mask", targetHosts: "10.*", action: .block), at: 0)
    profile.rules.insert(Rule(name: "range", targetHosts: "203.0.113.10-203.0.113.200", action: .direct), at: 1)
    profile.rules.insert(Rule(name: "cidr", targetHosts: "192.168.0.0/16", action: .direct), at: 2)
    profile.rules.insert(Rule(name: "glob", targetHosts: "*.example.com", action: .direct), at: 3)
    let rules = RuleSet(profile: profile, computerName: "mac")
    let a = app("curl")
    func name(_ host: String?, _ ip: String) -> String {
        rules.match(MatchRequest(app: a, hostname: host, ip: IPAddr(ip)!, port: 443)).name
    }
    #expect(name(nil, "10.255.1.2") == "mask")          // 10.* mask on the IP
    #expect(name(nil, "11.0.0.1") == "Default")         // mask does not over-match
    #expect(name(nil, "203.0.113.50") == "range")       // inside the range
    #expect(name(nil, "203.0.113.250") == "Default")    // just past the range
    #expect(name(nil, "192.168.9.9") == "cidr")         // CIDR
    #expect(name("www.example.com", "1.2.3.4") == "glob")
    #expect(name("example.com", "1.2.3.4") == "glob")   // *.example.com also covers the bare host
}

@Test func dpiBypassListMatchesDomainAndSubdomains() throws {
    let list = DPIBypassList(["youtube.com", "*.discord.gg", "  Rutracker.ORG "])
    #expect(list.matches("youtube.com"))
    #expect(list.matches("www.youtube.com"))          // subdomain of a bare entry
    #expect(list.matches("a.b.discord.gg"))           // "*." entry
    #expect(list.matches("rutracker.org"))            // trimmed + case-insensitive
    #expect(!list.matches("notyoutube.com"))          // not a suffix boundary
    #expect(!list.matches("discord.gg.evil.com"))
    #expect(!list.matches(nil))
    #expect(DPIBypassList([]).isEmpty)
}

@Test func byedpiFlagAllowlist() throws {
    #expect(!ByeDpiStrategies.valid(["-f1+s", "-t8"]))         // no fake packets in the macOS build
    #expect(!ByeDpiStrategies.valid(["-f-1", "-t5"]))
    #expect(ByeDpiStrategies.valid(["-s0+sm"]))
    #expect(ByeDpiStrategies.valid(["-s", "1", "-d", "3+s"]))   // separate value tokens
    #expect(!ByeDpiStrategies.valid(["-i0.0.0.0"]))             // listen ip not allowed
    #expect(!ByeDpiStrategies.valid(["-p", "8080"]))           // port not allowed
    #expect(!ByeDpiStrategies.valid(["-l/etc/passwd"]))        // fake-data file not allowed
    #expect(!ByeDpiStrategies.valid(["-H:evil"]))              // hostlist not allowed
    #expect(!ByeDpiStrategies.valid(["-f1+s; rm -rf /"]))      // junk rejected
    // Every shipped preset must pass its own allowlist.
    for s in ByeDpiStrategies.all { #expect(ByeDpiStrategies.valid(s.flags)) }
}

@Test func vpncScriptLocate() throws {
    // Homebrew openconnect 9.x path (etc/vpnc/) wins when present.
    let present: Set<String> = ["/opt/homebrew/etc/vpnc/vpnc-script", "/opt/homebrew/etc/vpnc-script"]
    #expect(VpncScript.locate(isExecutable: { present.contains($0) }) == "/opt/homebrew/etc/vpnc/vpnc-script")
    // Falls back to the older flat path when only it is executable.
    #expect(VpncScript.locate(isExecutable: { $0 == "/opt/homebrew/etc/vpnc-script" }) == "/opt/homebrew/etc/vpnc-script")
    // Intel Homebrew subdir.
    #expect(VpncScript.locate(isExecutable: { $0 == "/usr/local/etc/vpnc/vpnc-script" }) == "/usr/local/etc/vpnc/vpnc-script")
    // Nothing executable -> nil, so the caller fails closed and does not start openconnect.
    #expect(VpncScript.locate(isExecutable: { _ in false }) == nil)
    // The default list covers both Homebrew 9.x layouts and keeps the legacy paths.
    #expect(VpncScript.candidates.contains("/opt/homebrew/etc/vpnc/vpnc-script"))
    #expect(VpncScript.candidates.contains("/usr/local/etc/vpnc/vpnc-script"))
    #expect(VpncScript.candidates.contains("/etc/vpnc/vpnc-script"))
}

@Test func dnsSafeWrapperStripsDnsForEveryEvent() throws {
    let body = VpncScript.dnsSafeWrapperBody(realScript: "/opt/homebrew/etc/vpnc/vpnc-script")
    #expect(body.hasPrefix("#!/bin/sh"))
    for v in ["INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS", "CISCO_DEF_DOMAIN", "CISCO_SPLIT_DNS"] {
        #expect(body.contains(v))
    }
    #expect(body.contains("unset INTERNAL_IP4_DNS INTERNAL_IP6_DNS CISCO_DEF_DOMAIN CISCO_SPLIT_DNS"))
    #expect(body.contains("exec '/opt/homebrew/etc/vpnc/vpnc-script' \"$@\""))
    // Unconditional: no branch on openconnect's reason, so connect/reconnect/attempt-reconnect/
    // disconnect all strip DNS before the real script runs.
    #expect(!body.contains("reason"))
    #expect(!body.contains("if "))
    #expect(!body.contains("case "))
    // A single quote in the path is escaped so the shell sees the exact path.
    let quoted = VpncScript.dnsSafeWrapperBody(realScript: "/tmp/a'b/vpnc-script")
    #expect(quoted.contains("'/tmp/a'\\''b/vpnc-script'"))
}

struct StubGeo: GeoMatching {
    let ruDomains: Set<String>
    func matches(token: String, host: String?, ip: IPAddr) -> Bool {
        token == "geosite:category-ru" && (host.map(ruDomains.contains) ?? false)
    }
}

@Test func geoTokensMatchViaDatabase() throws {
    var profile = Profile.makeDefault()
    profile.rules.insert(Rule(name: "RU", targetHosts: "geosite:category-ru; *.example.com", action: .direct), at: 0)
    let rules = RuleSet(profile: profile)
    let geo = StubGeo(ruDomains: ["vk.com"])
    func name(_ host: String, geo g: GeoMatching?) -> String {
        rules.match(MatchRequest(app: AppIdentity(pid: 1, name: "x"), hostname: host, ip: IPAddr("1.2.3.4")!, port: 443),
                    activeBridge: .direct, geoDB: g).name
    }
    #expect(name("vk.com", geo: geo) == "RU")        // geosite hit
    #expect(name("www.example.com", geo: geo) == "RU") // plain host entry still works (OR)
    #expect(name("google.com", geo: geo) == "Default") // no geo, no host match
    #expect(name("vk.com", geo: nil) == "Default")     // no geo DB -> token never matches
}

@Test func ruleShadowDetectsCoveredTargets() throws {
    let rules = [
        Rule(name: "AnyConnect routes", targetHosts: "10.0.0.0/8; 172.16.0.0/12", action: .direct, dynamic: true),
        Rule(name: "Local", targetHosts: "localhost; 127.0.0.1; 10.0.0.0/8; 192.168.0.0/16", action: .direct, locked: true),
    ]
    let shadowed = RuleShadow.shadowedHosts(in: rules, ruleIndex: 1)
    #expect(shadowed.contains("10.0.0.0/8"))       // covered by the dynamic route above
    #expect(!shadowed.contains("192.168.0.0/16"))  // not covered
    #expect(!shadowed.contains("localhost"))
    // A narrower target under a broader earlier CIDR is also shadowed.
    let rules2 = [Rule(name: "a", targetHosts: "10.0.0.0/8", action: .direct),
                  Rule(name: "b", targetHosts: "10.5.0.0/16", action: .proxy(UUID()))]
    #expect(RuleShadow.shadowedHosts(in: rules2, ruleIndex: 1).contains("10.5.0.0/16"))

    // Ranges on both sides: a /8 covers the equivalent range, and a range covers a sub-CIDR.
    let rules3 = [
        Rule(name: "ac", targetHosts: "10.0.0.0/8", action: .direct, dynamic: true),
        Rule(name: "net", targetHosts: "10.0.0.0-10.255.255.255; 192.0.0.0-192.255.255.255", action: .direct),
    ]
    let s3 = RuleShadow.shadowedHosts(in: rules3, ruleIndex: 1)
    #expect(s3.contains("10.0.0.0-10.255.255.255"))
    #expect(!s3.contains("192.0.0.0-192.255.255.255"))
    let rules4 = [
        Rule(name: "range", targetHosts: "10.0.0.0-10.255.255.255", action: .direct),
        Rule(name: "sub", targetHosts: "10.5.0.0/16", action: .direct),
    ]
    #expect(RuleShadow.shadowedHosts(in: rules4, ruleIndex: 1).contains("10.5.0.0/16"))
}

@Test func malformedTargetsDoNotCrash() throws {
    // Separator-only tokens used to trap on parts[0]; now they're dropped safely.
    #expect(PFRules.validNetworks("/; -; ; 10.0.0.0/8") == ["10.0.0.0/8"])
    #expect(PFRules.validNetworks("/") == [])
    var profile = Profile.makeDefault()
    profile.rules.insert(Rule(name: "P", targetPorts: "-; /; 443", action: .direct), at: 0)
    let rules = RuleSet(profile: profile)  // compiles parsePorts on "-"/"/" without trapping
    _ = rules.match(MatchRequest(app: AppIdentity(pid: 1, name: "x"), hostname: "a.com", ip: IPAddr("1.2.3.4")!, port: 443))
    #expect(RuleShadow.shadowedHosts(in: [Rule(name: "a", targetHosts: "10.0.0.0/8"), Rule(name: "b", targetHosts: "/; -; 10.5.0.0/16")], ruleIndex: 1).contains("10.5.0.0/16"))
}

@Test func bridgeResolution() throws {
    let proxyID = UUID()
    var profile = Profile.makeDefault()
    profile.proxies = [{ var p = ProxyServer(host: "10.0.0.1", port: 3128, type: .https); p.id = proxyID; return p }()]
    profile.rules.insert(Rule(name: "torrent", applications: "qbittorrent", action: .vpn), at: 0)
    profile.rules.insert(Rule(name: "work", targetHosts: "*.corp", action: .proxy(proxyID)), at: 1)
    profile.rules[profile.rules.count - 1].action = .global  // Default = Global
    let rules = RuleSet(profile: profile)

    func act(_ app: String, _ host: String, bridge: Bridge, vpn: Bool) -> RuleAction {
        rules.match(MatchRequest(app: AppIdentity(pid: 1, name: app), hostname: host, ip: IPAddr("1.2.3.4")!, port: 443),
                    activeBridge: bridge, vpnAvailable: vpn).action
    }

    // "Только VPN": core up -> vpn; core down -> block (never leaks to direct)
    #expect(act("qbittorrent", "x.com", bridge: .direct, vpn: true) == .vpn)
    #expect(act("qbittorrent", "x.com", bridge: .direct, vpn: false) == .block)
    // "Только Proxy" rule is independent of the bridge
    #expect(act("curl", "a.corp", bridge: .vpn, vpn: true) == .proxy(proxyID))
    // Default "Global" follows the active bridge
    #expect(act("curl", "other.com", bridge: .vpn, vpn: true) == .vpn)
    #expect(act("curl", "other.com", bridge: .proxy(proxyID), vpn: false) == .proxy(proxyID))
    #expect(act("curl", "other.com", bridge: .direct, vpn: false) == .direct)
    // Global -> VPN but core down -> falls back to direct
    #expect(act("curl", "other.com", bridge: .vpn, vpn: false) == .direct)
}

@Test func rulesSkipProxiesOfDownInterfaces() throws {
    var profile = Profile.makeDefault()
    var office = ProxyServer(host: "10.0.0.1", port: 3128, type: .https)
    office.interfaceMAC = "00:e0:4c:15:09:ee"
    let anywhere = ProxyServer(host: "vpn", port: 1080, type: .socks5)
    profile.proxies = [office, anywhere]
    var chain = ProxyChain(name: "c")
    chain.proxyIDs = [anywhere.id, office.id]
    profile.chains = [chain]
    profile.rules.insert(Rule(name: "Office", targetHosts: "*.corp", action: .proxy(office.id)), at: 0)
    profile.rules.insert(Rule(name: "Corp", targetHosts: "*.corp", action: .proxy(anywhere.id)), at: 1)
    profile.rules[profile.rules.count - 1].action = .chain(chain.id)
    let rules = RuleSet(profile: profile)
    let request = MatchRequest(app: AppIdentity(pid: 1, name: "curl"), hostname: "git.corp", ip: IPAddr("10.1.1.1")!, port: 443)
    let other = MatchRequest(app: AppIdentity(pid: 1, name: "curl"), hostname: "example.com", ip: IPAddr("1.1.1.1")!, port: 443)

    let up = profile.unavailableRoutes(active: ["00:e0:4c:15:09:ee": "en8"])
    #expect(up.isEmpty)
    #expect(rules.match(request, unavailable: up).name == "Office")
    #expect(rules.match(other, unavailable: up).action == .chain(chain.id))

    let down = profile.unavailableRoutes(active: [:])
    #expect(down == [office.id, chain.id])
    #expect(rules.match(request, unavailable: down).name == "Corp")
    let fallback = rules.match(other, unavailable: down)
    #expect(fallback.name == "Default" && fallback.action == .direct)
}

@Test func subscriptionParsesAndAssembles() throws {
    let json = """
    [
      {"remarks":"Авто","routing":{"balancers":[{"tag":"B"}]},
       "outbounds":[{"protocol":"vless","tag":"p","streamSettings":{"network":"tcp","security":"reality"}}],
       "inbounds":[{"protocol":"socks","port":1}]},
      {"remarks":"🇳🇱 NL",
       "outbounds":[{"protocol":"vless","streamSettings":{"network":"grpc","security":"reality"}}]}
    ]
    """
    let summaries = XraySubscription.summaries(json)
    #expect(summaries.count == 2)
    #expect(summaries[0].name == "Авто" && summaries[0].balancer && summaries[0].transport == "VLESS · REALITY")
    #expect(summaries[1].balancer == false)

    let assembled = try #require(XraySubscription.assemble(json, index: 0, socksPort: 52140))
    let obj = try JSONSerialization.jsonObject(with: Data(assembled.utf8)) as! [String: Any]
    let inbounds = obj["inbounds"] as! [[String: Any]]
    #expect(inbounds.count == 1)
    #expect(inbounds[0]["port"] as? Int == 52140)
    #expect(inbounds[0]["protocol"] as? String == "socks")
    // provider outbounds and routing are preserved untouched
    #expect((obj["outbounds"] as! [[String: Any]]).count == 1)
    #expect(obj["routing"] != nil)
    #expect(XraySubscription.assemble(json, index: 9, socksPort: 52140) == nil)
}

@Test func assembleGeoSplitInjectsDirectRouting() throws {
    let json = #"[{"remarks":"Авто","outbounds":[{"protocol":"vless","tag":"proxy"},{"protocol":"freedom","tag":"direct"}],"routing":{"rules":[{"type":"field","inboundTag":["socks"],"outboundTag":"proxy"}]}}]"#
    let on = try #require(XraySubscription.assemble(json, index: 0, socksPort: 52140, routeLocalDirect: true))
    let obj = try JSONSerialization.jsonObject(with: Data(on.utf8)) as! [String: Any]
    let rules = (obj["routing"] as! [String: Any])["rules"] as! [[String: Any]]
    // Two geo-direct rules are prepended ahead of the provider's own rule.
    #expect(rules.count == 3)
    #expect((rules[0]["domain"] as? [String])?.contains("geosite:category-ru") == true)
    #expect((rules[1]["ip"] as? [String])?.contains("geoip:ru") == true)
    #expect(rules[0]["outboundTag"] as? String == "direct")

    let off = try #require(XraySubscription.assemble(json, index: 0, socksPort: 52140))
    let offRules = ((try JSONSerialization.jsonObject(with: Data(off.utf8)) as! [String: Any])["routing"] as! [String: Any])["rules"] as! [[String: Any]]
    #expect(offRules.count == 1)
}

@Test func subscriptionUsageParses() throws {
    let u = try #require(SubscriptionUsage("upload=0; download=716628321; total=0; expire=4942897060"))
    #expect(u.download == 716628321)
    #expect(u.unlimited)
    #expect(u.fraction == nil)
    #expect(u.expire != nil)
}

@Test func oldProfileDecodesWithoutSubscriptions() throws {
    let json = #"{"name":"P","rules":[{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","name":"Default","enabled":true,"applications":"","targetHosts":"","targetPorts":"","action":{"direct":{}},"isDefault":true}]}"#
    let p = try JSONDecoder().decode(Profile.self, from: Data(json.utf8))
    #expect(p.subscriptions.isEmpty)
    #expect(p.activeSubscriptionID == nil)
    #expect(p.activeVPNConfig() == nil)
}

@Test func oldProfilesDecodeWithoutInterface() throws {
    let json = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","host":"p","port":1,"type":"SOCKS5","useAuth":false,"username":"","password":""}"#
    let proxy = try JSONDecoder().decode(ProxyServer.self, from: Data(json.utf8))
    #expect(proxy.interfaceMAC == nil)
}

@Test func activeInterfacesHaveMACs() {
    for (mac, name) in NetInterfaces.active() {
        #expect(mac.split(separator: ":").count == 6)
        #expect(!name.isEmpty)
    }
}

@Test func removingProxyResetsRules() {
    var profile = Profile.makeDefault()
    let proxy = ProxyServer(host: "p", port: 1, type: .socks5)
    profile.proxies = [proxy]
    var chain = ProxyChain(name: "c")
    chain.proxyIDs = [proxy.id]
    profile.chains = [chain]
    profile.rules[1].action = .proxy(proxy.id)
    profile.removeProxy(proxy.id)
    #expect(profile.rules[1].action == .direct)
    #expect(profile.chains[0].proxyIDs.isEmpty)
}

@Test func pfRules() {
    #expect(PFRules.validNetworks("10.0.0.0/8; bad; 1.2.3.4; ::1/200; fd00::/8") == ["10.0.0.0/8", "1.2.3.4", "fd00::/8"])
    let text = PFRules.generate(listenPort: 18765, captureIPv6: false, blockQUIC: false, bypass: ["10.0.0.0/8"])
    #expect(text.contains("-> 127.0.0.1 port 18765"))
    #expect(text.contains("table <pg_bypass> persist"))
    #expect(PFRules.localAddresses().contains("127.0.0.1"))
    #expect(text.contains("10.0.0.0/8"))
    #expect(!text.contains("inet6"))
    #expect(!text.contains("udp"))
}

@Test func formatting() {
    #expect(ByteFormat.short(503) == "503 B")
    #expect(ByteFormat.short(5939) == "5.80 KB")
    #expect(ByteFormat.log(30059) == "30059 bytes (29.4 KB)")
    #expect(ByteFormat.duration(56) == "00:56")
    #expect(ByteFormat.duration(3723) == "01:02:03")
}

@Test func patternValidation() {
    #expect(Patterns.hostKind("example.com") == .domain)
    #expect(Patterns.hostKind("*.ru") == .wildcard)
    #expect(Patterns.hostKind("10.0.0.1") == .ip)
    #expect(Patterns.hostKind("10.0.0.0-10.255.255.255") == .range)
    #expect(Patterns.hostKind("10.255.0.0-10.0.0.0") == .invalid)
    #expect(Patterns.hostKind("10.0.0.0/8") == .cidr)
    #expect(Patterns.hostKind("10.0.0.0/40") == .invalid)
    #expect(Patterns.hostKind("bad host!") == .invalid)
    #expect(Patterns.portKind("443") == .port)
    #expect(Patterns.portKind("8000-9000") == .portRange)
    #expect(Patterns.portKind("9000-8000") == .invalid)
    #expect(Patterns.join(["Google Chrome", "uv"]) == "\"Google Chrome\"; uv")
    #expect(Patterns.split("\"Google Chrome\"; uv") == ["Google Chrome", "uv"])
    #expect(Patterns.baseDomain("ab.chatgpt.com") == "chatgpt.com")
    #expect(Patterns.baseDomain("a.b.co.uk") == "b.co.uk")
    #expect(Patterns.baseDomain("1.2.3.4") == "1.2.3.4")
}

@Test func ruleTransferRoundTrip() throws {
    var source = Profile.makeDefault()
    var proxy = ProxyServer(host: "192.0.2.10", port: 3128, type: .https)
    proxy.useAuth = true
    proxy.username = "me"
    proxy.password = "hunter2"
    source.proxies = [proxy]
    source.rules.insert(Rule(name: "Work", applications: "\"Google Chrome\"", targetHosts: "*.corp; 10.0.0.0/8", action: .proxy(proxy.id)), at: 0)
    let text = RuleTransfer.export(source.rules, from: source)
    #expect(text.hasPrefix("proxygate:"))
    #expect(!String(decoding: Data(base64Encoded: String(text.dropFirst(10)))!, as: UTF8.self).contains("hunter2"))

    // Into an empty profile: the proxy is created, without credentials.
    var target = Profile.makeDefault()
    let wrapped = text.enumerated().map { $0.offset % 40 == 39 ? "\($0.element)\n" : "\($0.element)" }.joined()
    #expect(try RuleTransfer.importRules(wrapped, into: &target) == 3)  // Localhost + Docker + Work, not Default
    #expect(target.proxies.count == 1 && !target.proxies[0].useAuth)
    let work = target.rules.first { $0.name == "Work" }!
    #expect(work.action == .proxy(target.proxies[0].id))
    #expect(target.rules.last!.isDefault)

    // Into a profile that already has the proxy: it is reused.
    var again = source
    try RuleTransfer.importRules(text, into: &again)
    #expect(again.proxies.count == 1)

    #expect(throws: NetError.self) { try RuleTransfer.decode("hello") }
    #expect(throws: NetError.self) { try RuleTransfer.decode(Data("{}".utf8).base64EncodedString()) }
}

import Foundation

/// How a DNS provider is reached: classic DNS over UDP port 53, or DNS-over-HTTPS (RFC 8484).
public enum DNSTransport: String, Codable, Sendable, CaseIterable {
    case udp
    case doh
}

/// A public or user-defined DNS resolver. `addresses` are always IP literals, so reaching the
/// resolver never depends on the (possibly broken) system DNS; a DoH URL's host name is used only
/// for TLS SNI and certificate checks.
public struct DNSProvider: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var name: String
    public var addresses: [String]
    /// "https://host/path" for DoH, nil when the provider is plain DNS only.
    public var dohURL: String?
    public var builtIn = false

    public init(id: String, name: String, addresses: [String], dohURL: String?, builtIn: Bool = false) {
        self.id = id
        self.name = name
        self.addresses = addresses
        self.dohURL = dohURL
        self.builtIn = builtIn
    }

    public var supportsDoH: Bool { dohURL.flatMap(DoHEndpoint.init) != nil }

    /// Valid IPs, IPv4 first (IPv6 may be unreachable on many networks).
    public var ips: [IPAddr] {
        let all = addresses.compactMap { IPAddr($0.trimmingCharacters(in: .whitespaces)) }
        return all.filter(\.isV4) + all.filter { !$0.isV4 }
    }

    /// Validates user input for a custom provider. Returns the provider or a short English reason
    /// (a localization key in the app).
    public static func custom(name: String, addresses: String, dohURL: String) -> Result<DNSProvider, DNSInputError> {
        let name = name.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, name.count <= 40 else { return .failure(.name) }
        let parts = splitList(addresses)
        let ips = parts.compactMap { IPAddr($0) }
        guard !ips.isEmpty, ips.count == parts.count, ips.count <= 4 else { return .failure(.addresses) }
        let url = dohURL.trimmingCharacters(in: .whitespaces)
        if !url.isEmpty, DoHEndpoint(url) == nil { return .failure(.dohURL) }
        return .success(DNSProvider(id: UUID().uuidString, name: name, addresses: ips.map(\.description),
                                    dohURL: url.isEmpty ? nil : url))
    }

    /// Engine-side re-check of a provider that arrived over the control socket.
    public var isValid: Bool {
        !ips.isEmpty && ips.count == addresses.count && addresses.count <= 4
            && (dohURL == nil || DoHEndpoint(dohURL!) != nil) && name.count <= 40
    }
}

public enum DNSInputError: String, Error, Sendable {
    case name = "Enter a name."
    case addresses = "Enter one to four IP addresses."
    case dohURL = "DoH address must look like https://host/dns-query."
}

public enum DNSProviders {
    public static let builtIn: [DNSProvider] = [
        DNSProvider(id: "google", name: "Google", addresses: ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888"],
                    dohURL: "https://dns.google/dns-query", builtIn: true),
        DNSProvider(id: "cloudflare", name: "Cloudflare", addresses: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"],
                    dohURL: "https://cloudflare-dns.com/dns-query", builtIn: true),
        // Plain DNS only: its DoH endpoint answers HTTP/1.1 with 505, and our DoH client is HTTP/1.1.
        DNSProvider(id: "quad9", name: "Quad9", addresses: ["9.9.9.9", "149.112.112.112"],
                    dohURL: nil, builtIn: true),
    ]
}

/// The resolver a lookup actually goes to: a provider plus the transport it is used with.
public struct DNSUpstream: Codable, Hashable, Sendable {
    public var provider: DNSProvider
    public var transport: DNSTransport

    public init(provider: DNSProvider, transport: DNSTransport) {
        self.provider = provider
        self.transport = provider.supportsDoH ? transport : .udp
    }

    /// "Google (DoH)", "Quad9 (DNS)".
    public var title: String { "\(provider.name) (\(transport == .doh ? "DoH" : "DNS"))" }
}

/// A DoH endpoint split into the parts the client needs. Only https, a plain host name (an IP
/// literal is allowed too), an optional port and a conservative path; anything else is rejected.
public struct DoHEndpoint: Hashable, Sendable {
    public let host: String
    public let port: UInt16
    public let path: String

    public init?(_ text: String) {
        guard text.count <= 200, let url = URL(string: text), url.scheme == "https",
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
              let host = url.host?.lowercased(), DNSName.isValid(host) || IPAddr(host) != nil else { return nil }
        let path = url.path.isEmpty ? "/dns-query" : url.path
        guard path.hasPrefix("/"),
              path.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "/-._~".contains($0)) }) else { return nil }
        let port = url.port ?? 443
        guard (1...65535).contains(port) else { return nil }
        self.host = host
        self.port = UInt16(port)
        self.path = path
    }
}

/// Host-name rules shared by the DNS list, the resolver files and the diagnostics input.
public enum DNSName {
    public static func isValid(_ name: String) -> Bool {
        let name = name.hasSuffix(".") ? String(name.dropLast()) : name
        guard !name.isEmpty, name.utf8.count <= 253 else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-" else { return false }
            return label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") }
        }
    }

    /// `name` equals `domain` or is a subdomain of it.
    public static func isWithin(_ name: String, domain: String) -> Bool {
        let n = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return n == domain || n.hasSuffix("." + domain)
    }
}

/// The list of domains whose names apps resolve through the chosen provider. Each entry becomes a
/// file name under /etc/resolver, so the rules are strict: a registrable-looking domain of at least
/// two labels, no wildcards in the middle, never `local` or reverse zones (mDNS and PTR stay system).
public enum DNSDomainList {
    public static let maxCount = 64

    public static func parse(_ text: String) -> (valid: [String], invalid: [String]) {
        var valid: [String] = []
        var invalid: [String] = []
        for raw in splitList(text) {
            var d = raw.lowercased()
            if d.hasPrefix("*.") { d.removeFirst(2) }
            if d.hasSuffix(".") { d.removeLast() }
            if isAllowed(d) {
                if !valid.contains(d) { valid.append(d) }
            } else {
                invalid.append(raw)
            }
        }
        if valid.count > maxCount {
            invalid += valid[maxCount...]
            valid = Array(valid[..<maxCount])
        }
        return (valid, invalid)
    }

    public static func isAllowed(_ domain: String) -> Bool {
        guard DNSName.isValid(domain), !domain.contains("_"), IPAddr(domain) == nil,
              domain.split(separator: ".").count >= 2 else { return false }
        return !(domain == "local" || domain.hasSuffix(".local") || domain.hasSuffix(".arpa"))
    }

    public static func covers(_ domains: [String], host: String) -> Bool {
        domains.contains { DNSName.isWithin(host, domain: $0) }
    }

    /// A short domain to add for a host the system DNS cannot resolve: the last two labels
    /// (`www.youtube.com` -> `youtube.com`). Good enough for the common case; the user can edit.
    public static func suggestion(for host: String) -> String? {
        let labels = host.lowercased().split(separator: ".")
        guard labels.count >= 2 else { return nil }
        let d = labels.suffix(2).joined(separator: ".")
        return isAllowed(d) ? d : nil
    }
}

/// Contents of the /etc/resolver files ProxyGate writes. The marker on the first line is how we
/// recognise our own files: anything without it belongs to the user and is never touched.
public enum ResolverFile {
    public static let directory = "/etc/resolver"
    public static let marker = "# Managed by ProxyGate. Removed when ProxyGate stops."

    public static func body(port: UInt16) -> String {
        "\(marker)\nnameserver 127.0.0.1\nport \(port)\ntimeout 5\n"
    }

    public static func isOurs(_ contents: String) -> Bool {
        contents.hasPrefix(marker)
    }
}

// MARK: - Wire format (RFC 1035)

public enum DNSRecordType: UInt16, Codable, Sendable {
    case a = 1
    case cname = 5
    case soa = 6
    case aaaa = 28
}

public struct DNSQuestion: Hashable, Sendable {
    public var name: String
    public var type: UInt16
    public var qclass: UInt16
}

public struct DNSResponse: Sendable {
    public var id: UInt16
    public var rcode: UInt8
    public var truncated: Bool
    public var question: DNSQuestion?
    public var addresses: [IPAddr] = []
    /// Smallest TTL of the answer records, nil when there are none.
    public var minTTL: UInt32?
    /// Negative-caching TTL from the authority SOA (RFC 2308), nil when absent.
    public var negativeTTL: UInt32?
    public var answerCount: Int
}

public enum DNSMessage {
    public static let rcodeNoError: UInt8 = 0
    public static let rcodeServFail: UInt8 = 2
    public static let rcodeNXDomain: UInt8 = 3
    public static let rcodeRefused: UInt8 = 5

    /// A recursive query for one name. `id` 0 is what DoH recommends (cache friendly).
    public static func query(name: String, type: DNSRecordType, id: UInt16 = 0) -> [UInt8]? {
        guard DNSName.isValid(name) else { return nil }
        var out: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        let trimmed = name.hasSuffix(".") ? String(name.dropLast()) : name
        for label in trimmed.split(separator: ".") {
            out.append(UInt8(label.utf8.count))
            out += Array(label.utf8)
        }
        out += [0, UInt8(type.rawValue >> 8), UInt8(type.rawValue & 0xFF), 0, 1]
        return out
    }

    public static func id(of message: [UInt8]) -> UInt16? {
        message.count >= 12 ? UInt16(message[0]) << 8 | UInt16(message[1]) : nil
    }

    public static func withID(_ message: [UInt8], _ id: UInt16) -> [UInt8] {
        guard message.count >= 2 else { return message }
        var m = message
        m[0] = UInt8(id >> 8)
        m[1] = UInt8(id & 0xFF)
        return m
    }

    /// The single question of a query, or nil for anything malformed (including responses).
    public static func question(of query: [UInt8]) -> DNSQuestion? {
        guard query.count >= 12, query.count <= 4096, query[2] & 0x80 == 0,
              count(query, at: 4) == 1 else { return nil }
        var reader = Reader(bytes: query, offset: 12)
        guard let name = reader.name(), let type = reader.u16(), let qclass = reader.u16() else { return nil }
        return DNSQuestion(name: name.lowercased(), type: type, qclass: qclass)
    }

    /// A reply carrying only the query's question and the given rcode (empty NOERROR, SERVFAIL,
    /// REFUSED). Built from the query, so the id and question match what the client sent.
    public static func reply(to query: [UInt8], rcode: UInt8) -> [UInt8]? {
        guard question(of: query) != nil else { return nil }
        var reader = Reader(bytes: query, offset: 12)
        guard reader.name() != nil, reader.u16() != nil, reader.u16() != nil else { return nil }
        var out = Array(query[0..<reader.offset])
        out[2] = 0x80 | (query[2] & 0x79)        // QR, keep opcode and RD
        out[3] = 0x80 | (rcode & 0x0F)            // RA + rcode
        for i in 6..<12 { out[i] = 0 }            // no answer/authority/additional
        return out
    }

    public static func parse(_ message: [UInt8]) -> DNSResponse? {
        guard message.count >= 12, message[2] & 0x80 != 0 else { return nil }
        let qd = count(message, at: 4), an = count(message, at: 6), ns = count(message, at: 8)
        var reader = Reader(bytes: message, offset: 12)
        var question: DNSQuestion?
        for i in 0..<qd {
            guard let name = reader.name(), let type = reader.u16(), let qclass = reader.u16() else { return nil }
            if i == 0 { question = DNSQuestion(name: name.lowercased(), type: type, qclass: qclass) }
        }
        var response = DNSResponse(id: id(of: message) ?? 0, rcode: message[3] & 0x0F,
                                   truncated: message[2] & 0x02 != 0, question: question, answerCount: an)
        for _ in 0..<an {
            guard let rr = reader.record() else { return nil }
            response.minTTL = min(response.minTTL ?? rr.ttl, rr.ttl)
            if (rr.type == DNSRecordType.a.rawValue && rr.data.count == 4)
                || (rr.type == DNSRecordType.aaaa.rawValue && rr.data.count == 16) {
                response.addresses.append(IPAddr(bytes: rr.data))
            }
        }
        for _ in 0..<ns {
            guard let rr = reader.record() else { break }
            if rr.type == DNSRecordType.soa.rawValue, rr.data.count >= 4 {
                let tail = rr.data.suffix(4)
                let minimum = tail.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
                response.negativeTTL = min(rr.ttl, minimum)
            }
        }
        return response
    }

    private static func count(_ m: [UInt8], at i: Int) -> Int { Int(m[i]) << 8 | Int(m[i + 1]) }

    struct Record {
        var type: UInt16
        var ttl: UInt32
        var data: [UInt8]
    }

    struct Reader {
        let bytes: [UInt8]
        var offset: Int

        mutating func u16() -> UInt16? {
            guard offset + 2 <= bytes.count else { return nil }
            defer { offset += 2 }
            return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }

        mutating func u32() -> UInt32? {
            guard let hi = u16(), let lo = u16() else { return nil }
            return UInt32(hi) << 16 | UInt32(lo)
        }

        /// Reads a possibly compressed name; pointer loops and overruns return nil.
        mutating func name() -> String? {
            var labels: [String] = []
            var cursor = offset
            var jumped = false
            var hops = 0
            while true {
                guard cursor < bytes.count else { return nil }
                let len = Int(bytes[cursor])
                if len == 0 {
                    if !jumped { offset = cursor + 1 }
                    break
                }
                if len & 0xC0 == 0xC0 {
                    guard cursor + 1 < bytes.count, hops < 32 else { return nil }
                    let target = (len & 0x3F) << 8 | Int(bytes[cursor + 1])
                    if !jumped { offset = cursor + 2 }
                    jumped = true
                    hops += 1
                    cursor = target
                    continue
                }
                guard len <= 63, cursor + 1 + len <= bytes.count else { return nil }
                labels.append(String(decoding: bytes[(cursor + 1)...(cursor + len)], as: UTF8.self))
                cursor += 1 + len
                guard labels.count <= 127 else { return nil }
            }
            return labels.joined(separator: ".")
        }

        mutating func record() -> Record? {
            guard name() != nil, let type = u16(), u16() != nil, let ttl = u32(), let len = u16(),
                  offset + Int(len) <= bytes.count else { return nil }
            defer { offset += Int(len) }
            return Record(type: type, ttl: ttl, data: Array(bytes[offset..<(offset + Int(len))]))
        }
    }
}

// MARK: - Lookup results

/// What a single lookup produced, in the terms the UI shows.
public enum DNSStatus: String, Codable, Sendable {
    /// Addresses returned.
    case ok
    /// The name does not exist (NXDOMAIN), or the system resolver reports "not found".
    case nxdomain
    /// The name exists but has no address of the asked type.
    case noData
    /// No answer in time.
    case timeout
    /// Any other failure: refused, SERVFAIL, TLS or HTTP error from DoH.
    case failed
}

public struct DNSOutcome: Codable, Sendable, Hashable {
    public var status: DNSStatus
    public var addresses: [String]
    public var ttl: UInt32?
    public var detail: String?

    public init(status: DNSStatus, addresses: [String] = [], ttl: UInt32? = nil, detail: String? = nil) {
        self.status = status
        self.addresses = addresses
        self.ttl = ttl
        self.detail = detail
    }

    public var ips: [IPAddr] { addresses.compactMap(IPAddr.init) }

    public static func from(_ response: DNSResponse) -> DNSOutcome {
        switch response.rcode {
        case DNSMessage.rcodeNoError:
            if response.addresses.isEmpty { return DNSOutcome(status: .noData, ttl: response.negativeTTL) }
            return DNSOutcome(status: .ok, addresses: response.addresses.map(\.description), ttl: response.minTTL)
        case DNSMessage.rcodeNXDomain:
            return DNSOutcome(status: .nxdomain, ttl: response.negativeTTL)
        case DNSMessage.rcodeServFail:
            return DNSOutcome(status: .failed, detail: "SERVFAIL")
        case DNSMessage.rcodeRefused:
            return DNSOutcome(status: .failed, detail: "REFUSED")
        default:
            return DNSOutcome(status: .failed, detail: "rcode \(response.rcode)")
        }
    }

    /// Merges the A and AAAA lookups of one name: any address wins, otherwise the A result tells
    /// the story (it is the one apps need first).
    public static func merge(_ a: DNSOutcome, _ aaaa: DNSOutcome) -> DNSOutcome {
        if a.status == .ok || aaaa.status == .ok {
            let ttls = [a, aaaa].filter { $0.status == .ok }.compactMap(\.ttl)
            return DNSOutcome(status: .ok, addresses: a.addresses + aaaa.addresses, ttl: ttls.min())
        }
        if a.status == .noData, aaaa.status == .nxdomain { return aaaa }
        return a
    }

    /// getaddrinfo cannot tell NXDOMAIN from "no data", both are EAI_NONAME; EAI_AGAIN is a
    /// temporary failure, which on a dead resolver is effectively a timeout.
    public static func fromGAI(_ code: Int32) -> DNSOutcome {
        switch code {
        case EAI_NONAME: return DNSOutcome(status: .nxdomain)
        case EAI_AGAIN: return DNSOutcome(status: .timeout)
        case EAI_NODATA: return DNSOutcome(status: .noData)
        default: return DNSOutcome(status: .failed, detail: String(cString: gai_strerror(code)))
        }
    }
}

/// One row of a DNS check: which resolver answered and how.
public struct DNSCheck: Codable, Sendable, Hashable {
    /// "System" for the Mac's resolver, otherwise `DNSUpstream.title`.
    public var source: String
    public var system: Bool
    public var outcome: DNSOutcome
    public var ms: Int?

    public init(source: String, system: Bool, outcome: DNSOutcome, ms: Int?) {
        self.source = source
        self.system = system
        self.outcome = outcome
        self.ms = ms
    }
}

public struct DNSCheckReport: Codable, Sendable {
    public var host: String
    public var checks: [DNSCheck]
    /// Plain DNS and DoH of the same provider returned disjoint addresses: plain DNS may be rewritten
    /// on the way.
    public var plainDiffers: Bool

    public init(host: String, checks: [DNSCheck], plainDiffers: Bool) {
        self.host = host
        self.checks = checks
        self.plainDiffers = plainDiffers
    }

    public static func differs(_ a: DNSOutcome, _ b: DNSOutcome) -> Bool {
        guard a.status == .ok, b.status == .ok else { return a.status != b.status && (a.status == .ok || b.status == .ok) }
        return Set(a.addresses).isDisjoint(with: Set(b.addresses))
    }
}

/// Status of the app-facing DNS (resolver files + local stub), reported by the engine.
public struct SystemDNSState: Codable, Sendable, Hashable {
    public var active = false
    public var domains: [String] = []
    public var upstream: String?
    /// Domains skipped because the user already has their own /etc/resolver file for them.
    public var conflicts: [String] = []
    public var answered = 0
    public var failed = 0
    public var lastError: String?

    public init() {}
}

// MARK: - Cache

/// Response cache for the stub, keyed by question. Honors record TTLs (clamped), caches negative
/// answers by their SOA TTL, and briefly remembers upstream failures so a dead resolver is not
/// hammered by retries.
public final class DNSCache: @unchecked Sendable {
    public static let minTTL: UInt32 = 10
    /// Cached replies go out with their original TTLs (not counted down), so keep them short: a
    /// client never holds an answer more than this past its real expiry.
    public static let maxTTL: UInt32 = 300
    public static let defaultNegativeTTL: UInt32 = 30
    public static let maxNegativeTTL: UInt32 = 300

    private let lock = NSLock()
    private var entries: [String: (message: [UInt8], expires: Date)] = [:]
    private let capacity: Int
    private let now: () -> Date

    public init(capacity: Int = 2048, now: @escaping () -> Date = Date.init) {
        self.capacity = capacity
        self.now = now
    }

    public static func key(_ q: DNSQuestion) -> String { "\(q.name)|\(q.type)|\(q.qclass)" }

    /// Seconds a response may be cached, nil for "don't cache".
    public static func lifetime(of response: DNSResponse) -> UInt32? {
        if response.truncated { return nil }
        switch response.rcode {
        case DNSMessage.rcodeNoError where response.answerCount > 0:
            return min(max(response.minTTL ?? minTTL, minTTL), maxTTL)
        case DNSMessage.rcodeNoError, DNSMessage.rcodeNXDomain:
            return min(response.negativeTTL ?? defaultNegativeTTL, maxNegativeTTL)
        default:
            return nil
        }
    }

    /// A cached response with `id` patched in, or nil.
    public func get(_ q: DNSQuestion, id: UInt16) -> [UInt8]? {
        let key = Self.key(q)
        return lock.withLock {
            guard let e = entries[key] else { return nil }
            if e.expires <= now() {
                entries[key] = nil
                return nil
            }
            return DNSMessage.withID(e.message, id)
        }
    }

    public func put(_ q: DNSQuestion, message: [UInt8], seconds: UInt32) {
        guard seconds > 0 else { return }
        lock.withLock {
            if entries.count >= capacity {
                let t = now()
                entries = entries.filter { $0.value.expires > t }
                if entries.count >= capacity { entries.removeAll() }
            }
            entries[Self.key(q)] = (message, now().addingTimeInterval(TimeInterval(seconds)))
        }
    }

    public func removeAll() { lock.withLock { entries.removeAll() } }

    public var count: Int { lock.withLock { entries.count } }
}

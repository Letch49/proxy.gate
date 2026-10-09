import Darwin
import Foundation
import PGCore

/// Matches `geosite:…` / `geoip:…` rule targets against Xray's bundled geosite.dat / geoip.dat
/// (v2fly protobuf). Builds a cheap category→byte-range index on first use and parses a category's
/// entries only when it is first needed, so memory stays bounded.
final class GeoDB: GeoMatching, @unchecked Sendable {
    private let lock = NSLock()
    private var siteIndex: [String: [UInt8]]?   // CATEGORY → raw GeoSite entry bytes
    private var ipIndex: [String: [UInt8]]?      // COUNTRY → raw GeoIP entry bytes
    private var siteCache: [String: [SiteRule]] = [:]
    private var ipCache: [String: [(IPAddr, Int)]] = [:]

    enum SiteRule { case full(String), suffix(String), plain(String), regex(NSRegularExpression) }

    func matches(token: String, host: String?, ip: IPAddr) -> Bool {
        let parts = token.split(separator: ":", maxSplits: 1)
        guard parts.count == 2 else { return false }
        let kind = parts[0].lowercased(), name = parts[1].uppercased()
        if kind == "geosite" {
            guard let host = host?.lowercased() else { return false }
            return siteRules(name).contains { $0.matches(host) }
        }
        if kind == "geoip" {
            return ipRanges(name).contains { ip.sharesPrefix(with: $0.0, bits: $0.1) }
        }
        return false
    }

    // MARK: - geosite

    private func siteRules(_ category: String) -> [SiteRule] {
        lock.withLock {
            if let cached = siteCache[category] { return cached }
            if siteIndex == nil { siteIndex = buildIndex(PGConstants.supportDir + "/geosite.dat") }
            let rules = (siteIndex?[category]).map(parseSite) ?? []
            siteCache[category] = rules
            return rules
        }
    }

    private func parseSite(_ bytes: [UInt8]) -> [SiteRule] {
        var out: [SiteRule] = []
        var r = PBReader(bytes)
        while let (field, wire) = r.key() {
            guard field == 2, wire == 2, let domain = r.bytes() else { r.skip(wire); continue }
            var d = PBReader(domain)
            var type = 0, value = ""
            while let (f, w) = d.key() {
                if f == 1, w == 0 { type = Int(d.varint() ?? 0) }
                else if f == 2, w == 2 { value = d.string() ?? "" }
                else { d.skip(w) }
            }
            guard !value.isEmpty else { continue }
            switch type {
            case 0: out.append(.plain(value.lowercased()))
            case 1: if let re = try? NSRegularExpression(pattern: value, options: [.caseInsensitive]) { out.append(.regex(re)) }
            case 3: out.append(.full(value.lowercased()))
            default: out.append(.suffix(value.lowercased()))   // Domain (suffix) is the common case
            }
        }
        return out
    }

    // MARK: - geoip

    private func ipRanges(_ country: String) -> [(IPAddr, Int)] {
        lock.withLock {
            if let cached = ipCache[country] { return cached }
            if ipIndex == nil { ipIndex = buildIndex(PGConstants.supportDir + "/geoip.dat") }
            let ranges = (ipIndex?[country]).map(parseIP) ?? []
            ipCache[country] = ranges
            return ranges
        }
    }

    private func parseIP(_ bytes: [UInt8]) -> [(IPAddr, Int)] {
        var out: [(IPAddr, Int)] = []
        var r = PBReader(bytes)
        while let (field, wire) = r.key() {
            guard field == 2, wire == 2, let cidr = r.bytes() else { r.skip(wire); continue }
            var c = PBReader(cidr)
            var ipBytes: [UInt8] = []
            var prefix = 0
            while let (f, w) = c.key() {
                if f == 1, w == 2 { ipBytes = c.bytes() ?? [] }
                else if f == 2, w == 0 { prefix = Int(c.varint() ?? 0) }
                else { c.skip(w) }
            }
            if ipBytes.count == 4 || ipBytes.count == 16 { out.append((IPAddr(bytes: ipBytes), prefix)) }
        }
        return out
    }

    // MARK: - top-level index (COUNTRY/CATEGORY → entry bytes)

    private func buildIndex(_ path: String) -> [String: [UInt8]] {
        guard let data = FileManager.default.contents(atPath: path) else { return [:] }
        var index: [String: [UInt8]] = [:]
        var r = PBReader([UInt8](data))
        while let (field, wire) = r.key() {
            guard field == 1, wire == 2, let entry = r.bytes() else { r.skip(wire); continue }
            var e = PBReader(entry)
            while let (f, w) = e.key() {
                if f == 1, w == 2 { index[(e.string() ?? "").uppercased()] = entry; break }
                e.skip(w)
            }
        }
        return index
    }
}

extension GeoDB.SiteRule {
    func matches(_ host: String) -> Bool {
        switch self {
        case .full(let v): return host == v
        case .suffix(let v): return host == v || host.hasSuffix("." + v)
        case .plain(let v): return host.contains(v)
        case .regex(let re): return re.firstMatch(in: host, range: NSRange(host.startIndex..., in: host)) != nil
        }
    }
}

/// Minimal protobuf wire reader (varint + length-delimited; others skipped).
private struct PBReader {
    let buf: [UInt8]
    var pos = 0
    init(_ buf: [UInt8]) { self.buf = buf }

    mutating func varint() -> UInt64? {
        var result: UInt64 = 0, shift: UInt64 = 0
        while pos < buf.count {
            let b = buf[pos]; pos += 1
            result |= UInt64(b & 0x7F) << shift
            if b & 0x80 == 0 { return result }
            shift += 7
            if shift > 63 { return nil }
        }
        return nil
    }

    mutating func key() -> (field: Int, wire: Int)? {
        guard pos < buf.count, let k = varint() else { return nil }
        return (Int(k >> 3), Int(k & 0x7))
    }

    mutating func bytes() -> [UInt8]? {
        guard let len = varint(), pos + Int(len) <= buf.count else { return nil }
        let slice = Array(buf[pos..<pos + Int(len)])
        pos += Int(len)
        return slice
    }

    mutating func string() -> String? { bytes().map { String(decoding: $0, as: UTF8.self) } }

    mutating func skip(_ wire: Int) {
        switch wire {
        case 0: _ = varint()
        case 2: _ = bytes()
        case 5: pos += 4
        case 1: pos += 8
        default: pos = buf.count
        }
    }
}

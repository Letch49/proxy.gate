import Foundation

/// Extracts the target hostname from the first bytes a client sends.
public enum Sniffer {
    public static func hostname(from data: [UInt8]) -> String? {
        guard let name = tlsServerName(data) ?? httpHost(data) else { return nil }
        return sanitize(name)
    }

    /// For a TLS record, whether the whole first record has arrived. nil if not TLS.
    public static func tlsRecordComplete(_ d: [UInt8]) -> Bool? {
        guard let first = d.first, first == 0x16 else { return nil }
        guard d.count >= 5 else { return false }
        return d.count >= 5 + be16(d, 3)
    }

    public static func tlsServerName(_ d: [UInt8]) -> String? {
        guard d.count > 9, d[0] == 0x16, d[5] == 0x01 else { return nil }
        var i = 9 + 2 + 32  // record + handshake headers, version, random
        guard i < d.count else { return nil }
        i += 1 + Int(d[i])  // session id
        guard i + 2 <= d.count else { return nil }
        i += 2 + be16(d, i)  // cipher suites
        guard i < d.count else { return nil }
        i += 1 + Int(d[i])  // compression methods
        guard i + 2 <= d.count else { return nil }
        let end = min(d.count, i + 2 + be16(d, i))
        i += 2
        while i + 4 <= end {
            let type = be16(d, i), len = be16(d, i + 2)
            i += 4
            if type == 0 {  // server_name
                var j = i + 2
                let listEnd = min(i + len, d.count)
                while j + 3 <= listEnd {
                    let nameType = d[j], nameLen = be16(d, j + 1)
                    j += 3
                    if nameType == 0, j + nameLen <= d.count {
                        return String(bytes: d[j..<(j + nameLen)], encoding: .ascii)
                    }
                    j += nameLen
                }
                return nil
            }
            i += len
        }
        return nil
    }

    private static let httpMethods = ["GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "]

    public static func httpHost(_ d: [UInt8]) -> String? {
        let text = String(decoding: d.prefix(8192), as: UTF8.self)
        guard httpMethods.contains(where: { text.hasPrefix($0) }) else { return nil }
        for line in text.components(separatedBy: "\r\n").dropFirst() {
            if line.isEmpty { break }
            guard line.lowercased().hasPrefix("host:") else { continue }
            var value = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("[") {
                if let close = value.firstIndex(of: "]") {
                    value = String(value[value.index(after: value.startIndex)..<close])
                }
            } else if let colon = value.lastIndex(of: ":") {
                value = String(value[..<colon])
            }
            return value
        }
        return nil
    }

    /// Only DNS names (no IP literals, no header injection).
    static func sanitize(_ name: String) -> String? {
        let lower = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard !lower.isEmpty, lower.count <= 253, IPAddr(lower) == nil else { return nil }
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-._")
        guard lower.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        return lower
    }

    private static func be16(_ d: [UInt8], _ i: Int) -> Int {
        Int(d[i]) << 8 | Int(d[i + 1])
    }
}

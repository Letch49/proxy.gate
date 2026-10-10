import Foundation

/// A code directory hash (cdhash) pins the exact signed build of the app that may drive the engine.
/// Builds are ad hoc signed (no Team ID), so the cdhash is the only stable code identity we have.
public enum CDHash {
    public static let argument = "--client-cdhash"

    /// Returns the lowercase form of a 40 hex digit cdhash, or nil for anything else.
    public static func normalize(_ text: String) -> String? {
        let lower = text.lowercased()
        guard lower.utf8.count == 40, lower.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            return nil
        }
        return lower
    }

    /// Lowercase hex of a raw 20 byte cdhash, or nil if the length is wrong.
    public static func hex(_ data: Data) -> String? {
        guard data.count == 20 else { return nil }
        return data.map { String(format: "%02x", $0) }.joined()
    }

    /// The cdhashes a helper's ProgramArguments pin. Junk values are skipped, not trusted.
    public static func pinned(in arguments: [String]) -> Set<String> {
        var result = Set<String>()
        var index = arguments.startIndex
        while index < arguments.endIndex {
            if arguments[index] == argument, index + 1 < arguments.endIndex,
               let hash = normalize(arguments[index + 1]) {
                result.insert(hash)
                index += 2
            } else {
                index += 1
            }
        }
        return result
    }

    /// A code signing requirement that matches any of the given cdhashes, or nil if there are none.
    /// Inputs must already be normalized, so nothing untrusted reaches the requirement language.
    public static func requirement(for hashes: Set<String>) -> String? {
        let valid = hashes.compactMap(normalize).sorted()
        guard !valid.isEmpty else { return nil }
        return valid.map { "cdhash H\"\($0)\"" }.joined(separator: " or ")
    }
}

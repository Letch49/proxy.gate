import Darwin
import Foundation

/// Where the downloaded cores come from and how their upstream checksums are read. Shared so the
/// app fetches exactly what the engine will accept, and the engine decides the expected hash on its
/// own instead of taking one from the socket client.
public enum CoreReleases {
    // MARK: - Shared checks

    /// A release tag as it may go into a URL or a version file: an optional `v`, then 1 to 4
    /// dot-separated groups of digits (Xray `v25.10.15`, zapret `v71.4`, ByeDPI `0.16.6`).
    public static func isValidTag(_ tag: String) -> Bool {
        var body = Substring(tag)
        if body.hasPrefix("v") { body = body.dropFirst() }
        let groups = body.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...4).contains(groups.count) else { return false }
        return groups.allSatisfy { group in
            (1...6).contains(group.utf8.count) && group.utf8.allSatisfy { (0x30...0x39).contains($0) }
        }
    }

    /// 64 hex digits, either case.
    public static func isSHA256Hex(_ text: String) -> Bool {
        text.utf8.count == 64 && text.utf8.allSatisfy { byte in
            (0x30...0x39).contains(byte) || (0x41...0x46).contains(byte) || (0x61...0x66).contains(byte)
        }
    }

    /// True on Apple Silicon, also when this process runs under Rosetta, so the app and the engine
    /// pick the same build whatever architecture each was compiled for.
    public static var isAppleSilicon: Bool {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        return sysctlbyname("hw.optional.arm64", &value, &size, nil, 0) == 0 && value == 1
    }

    // MARK: - Xray

    public static func xrayAssetName(arm64: Bool) -> String {
        arm64 ? "Xray-macos-arm64-v8a.zip" : "Xray-macos-64.zip"
    }

    /// The release's `.dgst` file for this Mac's zip; nil for a tag that fails `isValidTag`.
    public static func xrayChecksumURL(tag: String, arm64: Bool) -> URL? {
        guard isValidTag(tag) else { return nil }
        return URL(string: "https://github.com/XTLS/Xray-core/releases/download/\(tag)/\(xrayAssetName(arm64: arm64)).dgst")
    }

    /// The SHA2-256 value of a `.dgst` file (lines like `SHA2-256= <hex>`), lowercased.
    /// nil when the line is missing or the value is not a SHA256.
    public static func parseDgst(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).uppercased()
            guard key == "SHA2-256" || key == "SHA256" else { continue }
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces).lowercased()
            return isSHA256Hex(value) ? value : nil
        }
        return nil
    }

    // MARK: - tpws (zapret)

    /// Path suffix of the macOS tpws build inside the zapret tarball and its `sha256sum.txt`.
    public static let tpwsBinarySuffix = "binaries/mac64/tpws"

    public static func tpwsChecksumURL(tag: String) -> URL? {
        guard isValidTag(tag) else { return nil }
        return URL(string: "https://github.com/bol-van/zapret/releases/download/\(tag)/sha256sum.txt")
    }

    public struct SumEntry: Equatable, Sendable {
        public let sha256: String
        public let path: String
    }

    /// Entries of a `sha256sum` listing (`<hex>  <path>` or `<hex> *<path>`). Malformed lines, and
    /// paths that are absolute or climb with `..`, are skipped.
    public static func sumEntries(_ text: String) -> [SumEntry] {
        text.split(whereSeparator: \.isNewline).compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard let gap = line.firstIndex(where: { $0 == " " || $0 == "\t" }) else { return nil }
            let hex = String(line[..<gap])
            var path = line[gap...].drop(while: { $0 == " " || $0 == "\t" })
            if path.hasPrefix("*") { path = path.dropFirst() }
            guard isSHA256Hex(hex), !path.isEmpty, !path.hasPrefix("/"),
                  !path.split(separator: "/").contains("..") else { return nil }
            return SumEntry(sha256: hex.lowercased(), path: String(path))
        }
    }

    /// The tpws entry of zapret's `sha256sum.txt`. nil when it is missing, or when several matching
    /// lines disagree on the hash.
    public static func tpwsEntry(inSumFile text: String) -> SumEntry? {
        let matches = sumEntries(text).filter {
            $0.path == tpwsBinarySuffix || $0.path.hasSuffix("/" + tpwsBinarySuffix)
        }
        guard let first = matches.first, matches.allSatisfy({ $0.sha256 == first.sha256 }) else { return nil }
        return first
    }

    // MARK: - ByeDPI

    /// A pinned ByeDPI build. The macOS fork publishes no checksums, so each tarball hash was
    /// verified by hand and is the trust anchor even on a TLS-inspecting network.
    public struct ByeDpiBuild: Equatable, Sendable {
        public let version: String
        public let arm64: Bool
        public let url: String
        public let tarballSHA256: String
        /// The single archive member that is the ciadpi binary; a plain file name.
        public let member: String
    }

    public static let byedpiVersion = "0.16.6"

    public static let byedpiBuilds: [ByeDpiBuild] = [
        ByeDpiBuild(version: "0.16.6", arm64: true,
                    url: "https://github.com/ollesss/byedpi_macos/releases/download/v0.16.6/byedpi-darwin-arm64.tar.gz",
                    tarballSHA256: "f2a2287f9d1fd4493d82516591a46a97c94fbab015d8a626805598d99f3dd3de",
                    member: "ciadpi-arm"),
        ByeDpiBuild(version: "0.16.6", arm64: false,
                    url: "https://github.com/ollesss/byedpi_macos/releases/download/v0.16.6/byedpi-darwin-amd64.tar.gz",
                    tarballSHA256: "615f4fb1758878a2459467bde290a15908a28dc02965ec9e43e3cdc55a0ab592",
                    member: "ciadpi-x64"),
    ]

    public static func byedpiBuild(version: String, arm64: Bool) -> ByeDpiBuild? {
        byedpiBuilds.first { $0.version == version && $0.arm64 == arm64 }
    }
}

import Foundation
import PGCore

/// Downloads the Xray core release from GitHub (as the app, over the normal network) and verifies
/// it against the release's published checksum. The verified zip path is then handed to the engine,
/// which installs it with root privileges (see ClientCommand.installXray).
enum XrayDownloader {
    struct Release {
        let version: String
        let zipURL: URL
        let dgstURL: URL
    }

    struct Prepared {
        let zipPath: String
        let version: String
        let sha256: String
    }

    #if arch(arm64)
    private static let assetName = "Xray-macos-arm64-v8a.zip"
    #else
    private static let assetName = "Xray-macos-64.zip"
    #endif

    /// Looks up the latest release and the asset for this Mac's architecture.
    static func latest() async throws -> Release {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/XTLS/Xray-core/releases/latest")!)
        request.setValue("ProxyGate", forHTTPHeaderField: "User-Agent")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        try check(response)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = json["tag_name"] as? String,
              let assets = json["assets"] as? [[String: Any]] else {
            throw NetError("unexpected GitHub response")
        }
        func url(_ name: String) -> URL? {
            assets.first { ($0["name"] as? String) == name }
                .flatMap { $0["browser_download_url"] as? String }
                .flatMap(URL.init(string:))
        }
        guard let zip = url(assetName), let dgst = url(assetName + ".dgst") else {
            throw NetError("release \(tag) has no \(assetName)")
        }
        return Release(version: tag, zipURL: zip, dgstURL: dgst)
    }

    /// Downloads the zip and its checksum, verifies locally, and returns the path to hand to the engine.
    /// `onProgress` reports the download fraction (0...1), or nil when the size is unknown.
    static func prepare(_ release: Release, onProgress: @escaping (Double?) -> Void = { _ in }) async throws -> Prepared {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-xray-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let zipPath = dir.appendingPathComponent(assetName)

        let (bytes, response) = try await URLSession.shared.bytes(from: release.zipURL)
        try check(response)
        let total = response.expectedContentLength
        try? FileManager.default.removeItem(at: zipPath)
        FileManager.default.createFile(atPath: zipPath.path, contents: nil)
        let handle = try FileHandle(forWritingTo: zipPath)
        defer { try? handle.close() }
        var buffer = Data(); buffer.reserveCapacity(1 << 16)
        var written: Int64 = 0
        for try await byte in bytes {
            buffer.append(byte)
            if buffer.count >= 1 << 16 {
                handle.write(buffer)
                written += Int64(buffer.count)
                buffer.removeAll(keepingCapacity: true)
                onProgress(total > 0 ? Double(written) / Double(total) : nil)
            }
        }
        if !buffer.isEmpty { handle.write(buffer) }
        try handle.close()

        let (dgstData, dgstResponse) = try await URLSession.shared.data(from: release.dgstURL)
        try check(dgstResponse)
        guard let expected = parseSHA256(String(decoding: dgstData, as: UTF8.self)) else {
            throw NetError("no SHA2-256 in the release checksum file")
        }
        let actual = try sha256(of: zipPath)
        guard actual.caseInsensitiveCompare(expected) == .orderedSame else {
            throw NetError("downloaded Xray archive is corrupt (checksum mismatch)")
        }
        return Prepared(zipPath: zipPath.path, version: release.version, sha256: expected)
    }

    private static func parseSHA256(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            // Lines look like "SHA2-256= <hex>".
            if line.uppercased().contains("SHA2-256") {
                return line.split(whereSeparator: { $0 == " " || $0 == "=" }).last.map(String.init)
            }
        }
        return nil
    }

    private static func sha256(of file: URL) throws -> String {
        let r = Shell.run("/usr/bin/shasum", ["-a", "256", file.path])
        guard let hex = r.output.split(separator: " ").first else {
            throw NetError("could not hash the download")
        }
        return String(hex)
    }

    private static func check(_ response: URLResponse) throws {
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetError("download failed (HTTP \(http.statusCode))")
        }
    }
}

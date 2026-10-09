import Foundation
import PGCore

/// Downloads the tpws DPI-bypass binary from the zapret project's GitHub releases, verifies it
/// against the release's `sha256sum.txt`, and hands the extracted binary to the engine to install.
/// tpws ships as the `mac64` build (x86_64 — runs under Rosetta on Apple Silicon).
enum TpwsDownloader {
    struct Prepared {
        let binaryPath: String
        let version: String
        let sha256: String
    }

    static func prepare() async throws -> Prepared {
        var request = URLRequest(url: URL(string: "https://api.github.com/repos/bol-van/zapret/releases/latest")!)
        request.setValue("ProxyGate", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        try check(response)
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = json["tag_name"] as? String,
              let assets = json["assets"] as? [[String: Any]] else {
            throw NetError("unexpected GitHub response")
        }
        func url(_ match: (String) -> Bool) -> URL? {
            assets.first { ($0["name"] as? String).map(match) ?? false }
                .flatMap { $0["browser_download_url"] as? String }.flatMap(URL.init(string:))
        }
        guard let tarURL = url({ $0.hasSuffix(".tar.gz") && !$0.contains("openwrt") }),
              let sumURL = url({ $0 == "sha256sum.txt" }) else {
            throw NetError("zapret release \(tag) has no macOS archive")
        }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-tpws-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tarPath = dir.appendingPathComponent("zapret.tar.gz")

        let (tarTmp, tarResp) = try await URLSession.shared.download(from: tarURL)
        try check(tarResp)
        try? FileManager.default.removeItem(at: tarPath)
        try FileManager.default.moveItem(at: tarTmp, to: tarPath)
        let (sumData, sumResp) = try await URLSession.shared.data(from: sumURL)
        try check(sumResp)

        _ = try run("/usr/bin/tar", ["-xzf", tarPath.path, "-C", dir.path])

        // sha256sum.txt lines: "<hex>  zapret-vXX/binaries/mac64/tpws"
        let sums = String(decoding: sumData, as: UTF8.self)
        guard let line = sums.split(whereSeparator: \.isNewline).first(where: { $0.hasSuffix("/binaries/mac64/tpws") }),
              let expected = line.split(separator: " ").first.map(String.init),
              let relPath = line.split(separator: " ").last.map(String.init) else {
            throw NetError("tpws checksum not found in the release")
        }
        let binary = dir.appendingPathComponent(relPath)
        guard FileManager.default.fileExists(atPath: binary.path) else {
            throw NetError("tpws binary missing from the archive")
        }
        let actual = try sha256(of: binary)
        guard actual.caseInsensitiveCompare(expected) == .orderedSame else {
            throw NetError("downloaded tpws is corrupt (checksum mismatch)")
        }
        return Prepared(binaryPath: binary.path, version: tag, sha256: expected)
    }

    private static func sha256(of file: URL) throws -> String {
        let r = Shell.run("/usr/bin/shasum", ["-a", "256", file.path])
        guard let hex = r.output.split(separator: " ").first else {
            throw NetError("could not hash tpws")
        }
        return String(hex)
    }

    @discardableResult
    private static func run(_ tool: String, _ args: [String]) throws -> String {
        let r = Shell.run(tool, args)
        guard r.status == 0 else { throw NetError("\(tool) failed: \(r.output)") }
        return r.output
    }

    private static func check(_ response: URLResponse) throws {
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetError("download failed (HTTP \(http.statusCode))")
        }
    }
}

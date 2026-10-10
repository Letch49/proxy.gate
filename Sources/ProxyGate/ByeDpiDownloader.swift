import Foundation
import PGCore

/// Downloads the ByeDPI (ciadpi) macOS release tarball and hands it to the engine to install.
///
/// ByeDPI upstream ships no macOS build, so the tarball comes from a fork that publishes no
/// checksums. Its SHA256 is pinned in `CoreReleases.byedpiBuilds` (verified by hand) as the trust
/// anchor, shared with the engine. The app checks the pin here only to fail early; the engine
/// re-checks a staged copy against the same pin and extracts the binary itself.
enum ByeDpiDownloader {
    struct Prepared {
        let tarballPath: String
        let version: String
    }

    static func prepare() async throws -> Prepared {
        let version = CoreReleases.byedpiVersion
        guard let build = CoreReleases.byedpiBuild(version: version, arm64: CoreReleases.isAppleSilicon),
              let url = URL(string: build.url) else { throw NetError("no ByeDPI build for this Mac") }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-byedpi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tarPath = dir.appendingPathComponent("byedpi.tar.gz")

        let (tmp, resp) = try await URLSession.shared.download(from: url)
        if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetError("ByeDPI download failed (HTTP \(http.statusCode))")
        }
        try? FileManager.default.removeItem(at: tarPath)
        try FileManager.default.moveItem(at: tmp, to: tarPath)

        let tarHash = try sha256(of: tarPath)
        guard tarHash.caseInsensitiveCompare(build.tarballSHA256) == .orderedSame else {
            throw NetError("downloaded ByeDPI does not match the expected checksum (blocked for safety)")
        }
        return Prepared(tarballPath: tarPath.path, version: version)
    }

    private static func sha256(of file: URL) throws -> String {
        let r = Shell.run("/usr/bin/shasum", ["-a", "256", file.path])
        guard let hex = r.output.split(separator: " ").first else { throw NetError("could not hash ByeDPI") }
        return String(hex)
    }
}

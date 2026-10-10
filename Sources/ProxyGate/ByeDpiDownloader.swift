import Foundation
import PGCore

/// Downloads the ByeDPI (ciadpi) macOS binary and hands it to the engine to install.
///
/// ByeDPI upstream ships no macOS build, so the binary comes from the `ollesss/byedpi_macos` fork,
/// which publishes no checksums. We therefore PIN the SHA256 of each release tarball here (verified
/// by hand) as the trust anchor: the download must match the pin before we extract it, even under a
/// TLS-inspecting network. After extraction we hash the inner binary and pass that to the engine,
/// which verifies it again before installing.
enum ByeDpiDownloader {
    struct Prepared {
        let binaryPath: String
        let version: String
        let sha256: String
    }

    private struct Build {
        let url: String
        let tarballSHA256: String
        let innerName: String
    }

    private static let version = "0.16.6"
    private static let base = "https://github.com/ollesss/byedpi_macos/releases/download/v0.16.6"
    private static let arm64 = Build(
        url: base + "/byedpi-darwin-arm64.tar.gz",
        tarballSHA256: "f2a2287f9d1fd4493d82516591a46a97c94fbab015d8a626805598d99f3dd3de",
        innerName: "ciadpi-arm")
    private static let x86 = Build(
        url: base + "/byedpi-darwin-amd64.tar.gz",
        tarballSHA256: "615f4fb1758878a2459467bde290a15908a28dc02965ec9e43e3cdc55a0ab592",
        innerName: "ciadpi-x64")

    static func prepare() async throws -> Prepared {
        let build = machineIsARM() ? arm64 : x86
        guard let url = URL(string: build.url) else { throw NetError("bad ByeDPI url") }

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("proxygate-byedpi-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let tarPath = dir.appendingPathComponent("byedpi.tar.gz")

        let (tmp, resp) = try await URLSession.shared.download(from: url)
        if let http = resp as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetError("ByeDPI download failed (HTTP \(http.statusCode))")
        }
        try? FileManager.default.removeItem(at: tarPath)
        try FileManager.default.moveItem(at: tmp, to: tarPath)

        // Trust anchor: the tarball must match the pinned hash before we unpack it.
        let tarHash = try sha256(of: tarPath)
        guard tarHash.caseInsensitiveCompare(build.tarballSHA256) == .orderedSame else {
            throw NetError("downloaded ByeDPI does not match the expected checksum (blocked for safety)")
        }

        _ = try run("/usr/bin/tar", ["-xzf", tarPath.path, "-C", dir.path])
        let binary = dir.appendingPathComponent(build.innerName)
        guard FileManager.default.fileExists(atPath: binary.path) else {
            throw NetError("ByeDPI binary missing from the archive")
        }
        let binHash = try sha256(of: binary)
        return Prepared(binaryPath: binary.path, version: version, sha256: binHash)
    }

    private static func machineIsARM() -> Bool {
        Shell.run("/usr/bin/uname", ["-m"]).output.trimmingCharacters(in: .whitespacesAndNewlines) == "arm64"
    }

    private static func sha256(of file: URL) throws -> String {
        let r = Shell.run("/usr/bin/shasum", ["-a", "256", file.path])
        guard let hex = r.output.split(separator: " ").first else { throw NetError("could not hash ByeDPI") }
        return String(hex)
    }

    @discardableResult
    private static func run(_ tool: String, _ args: [String]) throws -> String {
        let r = Shell.run(tool, args)
        guard r.status == 0 else { throw NetError("\(tool) failed: \(r.output)") }
        return r.output
    }
}

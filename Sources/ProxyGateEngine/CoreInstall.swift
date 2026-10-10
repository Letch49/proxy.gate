import CryptoKit
import Darwin
import Foundation
import PGCore

/// Safe handling of a core the app downloaded. The socket client only names a file; the engine
/// copies it into a root-only staging dir without following symlinks, hashes that copy, checks it
/// against a hash it obtained itself, and works only on the copy from then on.
enum CoreInstall {
    /// Upper bound for any downloaded core or archive.
    static let maxBytes = 200 << 20
    private static let stagingPrefix = ".staging-"

    struct Staged {
        let path: String
        let sha256: String
    }

    /// A fresh root-owned 0700 dir inside the support dir (same volume, so `rename` into place is
    /// atomic). Leftovers from an interrupted install older than an hour are swept first.
    static func makeStagingDir() throws -> String {
        let fm = FileManager.default
        try fm.createDirectory(atPath: PGConstants.supportDir, withIntermediateDirectories: true)
        // The cores (service user) must traverse the support dir to read their files.
        _ = chmod(PGConstants.supportDir, 0o755)
        sweepStale()
        let dir = PGConstants.supportDir + "/" + stagingPrefix + UUID().uuidString
        try makeDir(dir)
        return dir
    }

    static func makeDir(_ path: String) throws {
        guard mkdir(path, 0o700) == 0 else { throw NetError("cannot create staging dir (errno \(errno))") }
    }

    static func remove(_ dir: String) {
        try? FileManager.default.removeItem(atPath: dir)
    }

    private static func sweepStale() {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: PGConstants.supportDir) else { return }
        let cutoff = Date().addingTimeInterval(-3600)
        for name in names where name.hasPrefix(stagingPrefix) {
            let path = PGConstants.supportDir + "/" + name
            if let date = (try? fm.attributesOfItem(atPath: path))?[.modificationDate] as? Date, date < cutoff {
                remove(path)
            }
        }
    }

    /// Copies the client's file into `dir/name` and hashes the copy. The last path component must
    /// not be a symlink and the file must be regular and at most `maxBytes`.
    static func stage(_ clientPath: String, in dir: String, name: String) throws -> Staged {
        guard clientPath.hasPrefix("/"), !clientPath.contains("\0"), clientPath.utf8.count < Int(PATH_MAX) else {
            throw NetError("rejected download path")
        }
        // O_NONBLOCK so a FIFO cannot hang the engine before the regular-file check.
        let src = open(clientPath, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard src >= 0 else { throw NetError("cannot open the download (errno \(errno))") }
        defer { close(src) }
        var info = stat()
        guard fstat(src, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw NetError("the download is not a regular file")
        }
        guard info.st_size <= off_t(maxBytes) else { throw NetError("the download is too large") }

        let destPath = dir + "/" + name
        let dst = open(destPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard dst >= 0 else { throw NetError("cannot create the staged copy (errno \(errno))") }
        defer { close(dst) }

        var hasher = SHA256()
        var buffer = [UInt8](repeating: 0, count: 1 << 16)
        var total = 0
        while true {
            let n = buffer.withUnsafeMutableBytes { read(src, $0.baseAddress, $0.count) }
            if n == 0 { break }
            if n < 0 {
                if errno == EINTR { continue }
                throw NetError("cannot read the download (errno \(errno))")
            }
            total += n
            // The file may grow after fstat; cap what we take.
            guard total <= maxBytes else { throw NetError("the download is too large") }
            hasher.update(data: buffer[0..<n])
            var offset = 0
            while offset < n {
                let w = buffer.withUnsafeBytes { write(dst, $0.baseAddress! + offset, n - offset) }
                if w < 0 {
                    if errno == EINTR { continue }
                    throw NetError("cannot write the staged copy (errno \(errno))")
                }
                offset += w
            }
        }
        let hex = hasher.finalize().map { String(format: "%02x", $0) }.joined()
        return Staged(path: destPath, sha256: hex)
    }

    /// Moves a verified staged file into place: regular file only, root:wheel, `mode`, quarantine
    /// cleared, then an atomic `rename` over the old copy. Call only after the hash check passed.
    static func place(_ staged: String, at dest: String, mode: mode_t) throws {
        var info = stat()
        guard lstat(staged, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            throw NetError("extracted core is not a regular file")
        }
        guard chown(staged, 0, 0) == 0, chmod(staged, mode) == 0 else {
            throw NetError("cannot set core permissions (errno \(errno))")
        }
        // A downloaded file can carry a quarantine xattr that stops launchd from running it.
        _ = removexattr(staged, "com.apple.quarantine", XATTR_NOFOLLOW)
        guard rename(staged, dest) == 0 else { throw NetError("cannot install the core (errno \(errno))") }
    }

    /// Fetches a small upstream checksum file, synchronously with a timeout. This drops trust in
    /// the local client but still rests on TLS to the release host: a TLS-inspecting network could
    /// serve both a forged file and a matching checksum (open item, no pinning yet).
    static func fetchText(_ url: URL, maxBytes: Int = 1 << 20) throws -> String {
        guard url.scheme == "https" else { throw NetError("checksum URL must be https") }
        // curl binds a source port from the reserved range, which pf passes, so the fetch goes
        // straight out instead of back into the engine and through the user's rules.
        let ports = "\(PFRules.reservedPorts.lowerBound)-\(PFRules.reservedPorts.upperBound)"
        let result = Shell.run("/usr/bin/curl", [
            "-sfL", "--proto", "=https", "--proto-redir", "=https",
            "--connect-timeout", "20", "--max-time", "40", "--max-filesize", String(maxBytes),
            "--local-port", ports, "-A", "ProxyGate", url.absoluteString,
        ])
        guard result.status == 0 else { throw NetError("checksum download failed (curl \(result.status))") }
        guard result.output.utf8.count <= maxBytes else { throw NetError("checksum file is too large") }
        return result.output
    }
}

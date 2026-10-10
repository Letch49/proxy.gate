import Darwin
import Foundation
import PGCore

/// Points chosen domains at the engine's DNS stub with per-domain /etc/resolver files. The Mac's
/// DNS servers, network services and search domains are never modified, so there is nothing to
/// restore after sleep, a network change or a crash; the files only add scoped resolvers. Files
/// without our marker belong to the user and are left alone (reported as conflicts).
enum SystemDNS {
    static let directory = ResolverFile.directory

    /// Makes the set of our resolver files equal `domains`. Returns the domains applied and those
    /// skipped because a user file already exists.
    static func apply(domains: [String], port: UInt16) -> (applied: [String], conflicts: [String], error: String?) {
        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: directory, isDirectory: &isDir) {
            do {
                try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: 0o755])
            } catch {
                return ([], [], "cannot create \(directory): \(error)")
            }
        } else if !isDir.boolValue {
            return ([], [], "\(directory) is not a directory")
        }
        let wanted = Set(domains.filter(DNSDomainList.isAllowed))
        var applied: [String] = []
        var conflicts: [String] = []
        var changed = false
        let body = ResolverFile.body(port: port)
        for domain in wanted.sorted() {
            let path = directory + "/" + domain
            switch state(of: path) {
            case .foreign:
                conflicts.append(domain)
                continue
            case .ours(let contents) where contents == body:
                applied.append(domain)
                continue
            case .ours, .missing:
                break
            }
            do {
                try body.write(toFile: path, atomically: true, encoding: .utf8)
                chmod(path, 0o644)
                applied.append(domain)
                changed = true
            } catch {
                return (applied, conflicts, "cannot write \(path): \(error)")
            }
        }
        for name in ourFiles() where !wanted.contains(name) {
            unlink(directory + "/" + name)
            changed = true
        }
        if changed { flushCache() }
        return (applied, conflicts, nil)
    }

    /// Removes every resolver file we wrote (on disable, app disconnect, engine start and exit).
    static func clear() {
        let ours = ourFiles()
        for name in ours { unlink(directory + "/" + name) }
        if !ours.isEmpty { flushCache() }
    }

    private enum FileState { case missing, ours(String), foreign }

    private static func state(of path: String) -> FileState {
        var st = stat()
        guard lstat(path, &st) == 0 else { return .missing }
        // A symlink or anything that is not a plain file is never ours to follow or replace.
        guard st.st_mode & S_IFMT == S_IFREG, st.st_size < 4096,
              let contents = try? String(contentsOfFile: path, encoding: .utf8),
              ResolverFile.isOurs(contents) else { return .foreign }
        return .ours(contents)
    }

    private static func ourFiles() -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        return names.filter { name in
            guard DNSDomainList.isAllowed(name) else { return false }
            if case .ours = state(of: directory + "/" + name) { return true }
            return false
        }
    }

    /// Stale positive or negative answers would hide the change until their TTL ran out.
    private static func flushCache() {
        Shell.run("/usr/bin/dscacheutil", ["-flushcache"])
        Shell.run("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }
}

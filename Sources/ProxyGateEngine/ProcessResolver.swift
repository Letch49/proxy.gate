import CSys
import Foundation
import PGCore

/// Maps a client socket to the process that owns it.
final class ProcessResolver: @unchecked Sendable {
    private let lock = NSLock()
    /// Recently seen pids, checked first: most connections come from a handful of apps.
    private var recent: [Int32] = []
    private var cache: [String: AppIdentity] = [:]

    func owner(localPort: UInt16, remotePort: UInt16) -> Int32 {
        let hints = lock.withLock { recent }
        let pid = hints.withUnsafeBufferPointer {
            pg_find_tcp_owner(localPort, remotePort, $0.baseAddress, Int32($0.count))
        }
        if pid > 0 {
            lock.withLock {
                recent.removeAll { $0 == pid }
                recent.insert(pid, at: 0)
                if recent.count > 32 {
                    recent.removeLast()
                }
            }
        }
        return pid
    }

    func identity(pid: Int32) -> AppIdentity {
        guard pid > 0 else { return AppIdentity(pid: -1, name: "unknown") }
        var buf = [CChar](repeating: 0, count: 4096)
        guard pg_pid_path(pid, &buf, UInt32(buf.count)) > 0 else {
            return AppIdentity(pid: pid, name: "pid \(pid)")
        }
        let path = String(cString: buf)
        if var cached = lock.withLock({ cache[path] }) {
            cached.pid = pid
            return cached
        }
        var identity = AppIdentity(pid: pid, name: (path as NSString).lastPathComponent)
        identity.path = path

        var bundles: [URL] = []
        var url = URL(fileURLWithPath: path).deletingLastPathComponent()
        while url.path != "/" && !url.path.isEmpty {
            if ["app", "appex", "xpc"].contains(url.pathExtension) {
                bundles.insert(url, at: 0)
            }
            url.deleteLastPathComponent()
        }
        identity.bundleNames = bundles.map { $0.deletingPathExtension().lastPathComponent }
        if let inner = bundles.last {
            identity.bundleID = Bundle(url: inner)?.bundleIdentifier
        }
        if let outer = bundles.first, bundles.count > 1 {
            identity.outerBundleID = Bundle(url: outer)?.bundleIdentifier
        }
        lock.withLock {
            if cache.count > 2000 { cache.removeAll() }
            cache[path] = identity
        }
        return identity
    }
}

import Darwin
import Foundation
import PGCore

/// Dedicated unprivileged account the bundled cores (Xray, tpws) run as. A real low-numbered uid is
/// required: pf's `user` match rejects nobody (uid -2), and a known uid is what lets pf pass a core's
/// own outbound untouched to avoid a redirect loop.
enum ServiceUser {
    static let name = "_proxygate"
    private static let lock = NSLock()
    private static var cachedUID: UInt32?

    /// uid the cores run as, creating the account on first use (engine is root).
    static func uid() -> UInt32 {
        lock.withLock {
            if let uid = cachedUID { return uid }
            let uid = ensure()
            cachedUID = uid
            return uid
        }
    }

    static var gid: gid_t { gid_t(uid()) }

    private static func ensure() -> UInt32 {
        if let pw = getpwnam(name) { return UInt32(pw.pointee.pw_uid) }
        var id: UInt32 = 440
        while id < 600, getpwuid(uid_t(id)) != nil || getgrgid(gid_t(id)) != nil { id += 1 }
        let dscl = "/usr/bin/dscl"
        func d(_ args: [String]) { _ = shell(dscl, args) }
        d([".", "-create", "/Groups/\(name)"])
        d([".", "-create", "/Groups/\(name)", "PrimaryGroupID", "\(id)"])
        d([".", "-create", "/Groups/\(name)", "RealName", "ProxyGate helper"])
        d([".", "-create", "/Users/\(name)"])
        d([".", "-create", "/Users/\(name)", "UniqueID", "\(id)"])
        d([".", "-create", "/Users/\(name)", "PrimaryGroupID", "\(id)"])
        d([".", "-create", "/Users/\(name)", "UserShell", "/usr/bin/false"])
        d([".", "-create", "/Users/\(name)", "NFSHomeDirectory", "/var/empty"])
        d([".", "-create", "/Users/\(name)", "RealName", "ProxyGate helper"])
        d([".", "-create", "/Users/\(name)", "IsHidden", "1"])
        FileHandle.standardError.write(Data("[engine] created service user \(name) (uid \(id))\n".utf8))
        return id
    }

    @discardableResult
    static func shell(_ tool: String, _ args: [String]) -> (status: Int32, output: String) {
        Shell.run(tool, args)
    }
}

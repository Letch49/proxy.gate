import Foundation
import PGCore

/// Shared LaunchDaemon mechanics for the bundled cores (Xray, tpws): writing the plist safely,
/// (re)bootstrapping around launchd's races, checking liveness, and pre-creating the log so launchd
/// can open it as the service user.
enum LaunchdJob {
    static func running(_ label: String) -> Bool {
        // `launchctl print` exits 0 only while loaded; "state = running" means a live pid.
        let r = Shell.run("/bin/launchctl", ["print", "system/\(label)"])
        return r.status == 0 && r.output.contains("state = running")
    }

    /// Boots the job out and waits for launchd to actually drop it, so a following bootstrap
    /// doesn't race (EIO / "already loaded").
    static func bootout(_ label: String) {
        _ = Shell.run("/bin/launchctl", ["bootout", "system/\(label)"])
        for _ in 0..<15 {
            if Shell.run("/bin/launchctl", ["print", "system/\(label)"]).status != 0 { return }
            usleep(200_000)
        }
    }

    /// Builds a LaunchDaemon plist from a dictionary — never string interpolation, since the args
    /// (tpws strategy flags) are untrusted — and writes it root-owned.
    static func writePlist(_ dict: [String: Any], to path: String) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: URL(fileURLWithPath: path))
        _ = Shell.run("/usr/sbin/chown", ["root:wheel", path])
        _ = Shell.run("/bin/chmod", ["644", path])
    }

    /// launchd opens the std paths as the job's user; `_proxygate` can't create a file in /var/log,
    /// so pre-create the log (0600 — it can hold connection targets) and hand it over.
    static func prepareLog(_ path: String) {
        _ = Shell.run("/usr/bin/touch", [path])
        _ = Shell.run("/usr/sbin/chown", ["\(ServiceUser.name):\(ServiceUser.name)", path])
        _ = Shell.run("/bin/chmod", ["600", path])
    }

    /// Bootstraps the plist, retrying around launchd races, then confirms the job actually came up
    /// (bootstrap can succeed while the spawn then fails); surfaces the reason from `logPath`.
    static func bootstrap(label: String, plistPath: String, logPath: String) throws {
        bootout(label)
        var r = Shell.run("/bin/launchctl", ["bootstrap", "system", plistPath])
        var attempt = 0
        while r.status != 0 && attempt < 5 {
            attempt += 1
            usleep(400_000)
            bootout(label)
            r = Shell.run("/bin/launchctl", ["bootstrap", "system", plistPath])
        }
        if r.status != 0 {
            throw NetError("launchctl bootstrap failed: \(r.output.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        for _ in 0..<10 {
            usleep(200_000)
            if running(label) { return }
        }
        let tail = (try? String(contentsOfFile: logPath, encoding: .utf8))?
            .split(separator: "\n").suffix(4).joined(separator: " ") ?? ""
        throw NetError("the core did not start. \(tail.isEmpty ? "See \(logPath)." : tail)")
    }
}

import Foundation

/// Pure helpers for driving openconnect's `vpnc-script` safely: finding the real script across the
/// packaging layouts, and building the wrapper that keeps the pushed DNS off the system interfaces.
/// Kept here (no Foundation FS/root calls) so it can be unit-tested without touching the machine.
public enum VpncScript {
    /// Candidate `vpnc-script` locations, most specific first. openconnect 9.x from Homebrew installs
    /// it under `etc/vpnc/` (Apple Silicon `/opt/homebrew`, Intel `/usr/local`); older builds and the
    /// system package use the flat `etc/` path or `/etc/vpnc/`.
    public static let candidates = [
        "/opt/homebrew/etc/vpnc/vpnc-script",
        "/usr/local/etc/vpnc/vpnc-script",
        "/opt/homebrew/etc/vpnc-script",
        "/usr/local/etc/vpnc-script",
        "/etc/vpnc/vpnc-script",
    ]

    /// The first candidate that is an executable file, or nil when none is usable.
    public static func locate(_ list: [String] = candidates, isExecutable: (String) -> Bool) -> String? {
        list.first(where: isExecutable)
    }

    /// A `/bin/sh` wrapper that runs `realScript` for EVERY openconnect event (connect, reconnect,
    /// attempt-reconnect, disconnect) with the DNS variables stripped, so the pushed resolvers and
    /// search domain are never written onto the system network service. The unset is unconditional
    /// and happens before the real script runs, so no event path can re-add them. Routes and the utun
    /// device are untouched. `realScript` is single-quoted to survive spaces.
    public static func dnsSafeWrapperBody(realScript: String) -> String {
        let quoted = "'" + realScript.replacingOccurrences(of: "'", with: "'\\''") + "'"
        return """
        #!/bin/sh
        # Strip the pushed DNS before the real script runs, so it never lands on the system.
        unset INTERNAL_IP4_DNS INTERNAL_IP6_DNS CISCO_DEF_DOMAIN CISCO_SPLIT_DNS
        exec \(quoted) "$@"

        """
    }
}

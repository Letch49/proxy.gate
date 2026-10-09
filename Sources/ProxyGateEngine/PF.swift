import Foundation
import PGCore

/// Loads / unloads our anchor through pfctl.
enum PF {
    private static let pfctl = "/sbin/pfctl"

    @discardableResult
    static func run(_ args: [String], input: String? = nil) -> (status: Int32, output: String) {
        Shell.run(pfctl, args, input: input)
    }

    /// Loads the rules and enables pf. Returns the enable token to release later.
    static func enable(rules: String) throws -> String? {
        // Our anchor is evaluated through the stock `com.apple/*` anchors of /etc/pf.conf.
        let nat = run(["-s", "nat"]).output
        if !nat.contains("rdr-anchor \"com.apple/*\"") {
            let r = run(["-f", "/etc/pf.conf"])
            if r.status != 0 {
                throw NetError("pfctl -f /etc/pf.conf failed: \(r.output)")
            }
        }
        let load = run(["-a", PFRules.anchor, "-f", "-"], input: rules)
        if load.status != 0 {
            throw NetError("pfctl rejected the rules: \(load.output)")
        }
        let enable = run(["-E"])
        guard let match = enable.output.range(of: #"Token : (\d+)"#, options: .regularExpression) else {
            return nil
        }
        return enable.output[match].components(separatedBy: " ").last
    }

    /// Replaces the bypass table of the loaded anchor.
    @discardableResult
    static func replaceBypass(_ entries: [String]) -> Bool {
        run(["-a", PFRules.anchor, "-t", "pg_bypass", "-T", "replace"] + entries).status == 0
    }

    static func disable(token: String?) {
        flushAnchor()
        if let token {
            run(["-X", token])
        }
    }

    static func flushAnchor() {
        run(["-a", PFRules.anchor, "-F", "rules"])
        run(["-a", PFRules.anchor, "-F", "nat"])
        run(["-a", PFRules.anchor, "-F", "Tables"])
    }
}

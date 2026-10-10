import Foundation

/// A tpws DPI-bypass strategy: a label and the command-line flags passed to tpws.
public struct DPIStrategy: Sendable, Hashable, Identifiable {
    public let label: String
    public let flags: [String]
    public var id: String { flags.joined(separator: " ") }

    public init(label: String, flags: [String]) {
        self.label = label
        self.flags = flags
    }
}

/// Candidate strategies in rough order of effectiveness (first that works usually wins). Mirrors the
/// set zapret clients auto-tune over.
public enum DPIStrategies {
    public static let all: [DPIStrategy] = [
        DPIStrategy(label: "Split at SNI + disorder", flags: ["--split-pos=1,midsld", "--disorder"]),
        DPIStrategy(label: "TLS-record split (SNI)", flags: ["--tlsrec=sni"]),
        DPIStrategy(label: "TLS-record split (midsld) + disorder", flags: ["--tlsrec=midsld", "--disorder"]),
        DPIStrategy(label: "Split + disorder", flags: ["--split-pos=1", "--disorder"]),
        DPIStrategy(label: "TLS split at SNI + disorder", flags: ["--split-tls=sni", "--disorder"]),
        DPIStrategy(label: "Disorder", flags: ["--disorder"]),
    ]

    public static func at(_ index: Int) -> DPIStrategy {
        all.indices.contains(index) ? all[index] : all[0]
    }
}

/// Which core desyncs the ClientHello. Both work at the socket payload level on macOS (split,
/// disorder, oob, TLS-record split); fake packets need raw sockets the macOS builds don't use.
public enum DPIEngine: String, Codable, Sendable, CaseIterable {
    case tpws
    case byedpi

    public var title: String { self == .byedpi ? "ByeDPI" : "tpws" }

    public func strategies() -> [DPIStrategy] { self == .byedpi ? ByeDpiStrategies.all : DPIStrategies.all }

    /// Loopback SOCKS port the core listens on.
    public var socksPort: UInt16 { self == .byedpi ? PGConstants.byedpiSocksPort : PGConstants.tpwsSocksPort }

    /// Label of the strategy at `index`, "" when out of range.
    public func strategyLabel(_ index: Int) -> String {
        strategies().indices.contains(index) ? strategies()[index].label : ""
    }
}

/// Which DPI core, if any, a connection goes through. Pure, so the engine's routing is testable.
public enum DPIRouting {
    /// A `.directDPI` rule: its own core, else the primary; when that one is down, the other running
    /// core; nil (plain direct) when none runs.
    public static func ruleCore(_ ruleEngine: DPIEngine?, primary: DPIEngine, running: Set<DPIEngine>) -> DPIEngine? {
        let wanted = ruleEngine ?? primary
        if running.contains(wanted) { return wanted }
        return DPIEngine.allCases.first { running.contains($0) }
    }

    /// A plain `.direct` route: through the primary core only when bypass is on, "all direct traffic"
    /// is on and that core runs. Private/LAN destinations never need it.
    public static func directCore(bypassOn: Bool, allDirect: Bool, primary: DPIEngine, running: Set<DPIEngine>,
                                  privateDestination: Bool) -> DPIEngine? {
        guard bypassOn, allDirect, !privateDestination, running.contains(primary) else { return nil }
        return primary
    }
}

/// ciadpi (ByeDPI) desync presets. Flags use ciadpi's own syntax: `-s` split, `-d` disorder, `-o`
/// oob, `-q` disorder+oob, `-r` tls-record split; positions like `1+s` (at SNI), `0+sm` (middle of
/// SNI). The macOS build has no fake packets (`-f`) and no md5sig (`-S`), so none are offered: a
/// preset with them makes ciadpi exit at once with "invalid option".
public enum ByeDpiStrategies {
    public static let all: [DPIStrategy] = [
        DPIStrategy(label: "Disorder at SNI", flags: ["-d1+s"]),
        DPIStrategy(label: "Split + disorder at SNI", flags: ["-s1", "-d3+s"]),
        DPIStrategy(label: "TLS-record split + disorder", flags: ["-r1+s", "-d1+s"]),
        DPIStrategy(label: "OOB at SNI", flags: ["-o1+s"]),
        DPIStrategy(label: "Disorder + OOB at SNI", flags: ["-q1+s"]),
        DPIStrategy(label: "Split in middle of SNI", flags: ["-s0+sm"]),
        DPIStrategy(label: "TLS-record split at SNI", flags: ["-r1+s"]),
    ]

    /// Strict allowlist for ciadpi flags, so a hostile control-socket client can't smuggle options
    /// like `-i 0.0.0.0` (open proxy), `-l`/`-H` (read a file) or `-E`/`-D` onto the command line.
    /// Only the desync flags are permitted, each with a position/number/trigger-shaped value. `-f` and
    /// `-S` are left out on purpose: the macOS build lacks them.
    static let allowedFlags: Set<Character> = ["s", "d", "o", "q", "t", "r", "A", "L", "K", "N"]

    public static func valid(_ flags: [String]) -> Bool {
        let value = try? NSRegularExpression(pattern: "^[-+]?[0-9A-Za-z][0-9A-Za-z,:+]*$")
        func isValue(_ s: String) -> Bool {
            guard let value, !s.isEmpty else { return false }
            return value.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
        }
        for tok in flags {
            if tok.hasPrefix("-"), let second = tok.dropFirst().first, second.isLetter {
                guard allowedFlags.contains(second) else { return false }
                let rest = String(tok.dropFirst(2))
                if !rest.isEmpty, !isValue(rest) { return false }
            } else if !isValue(tok) {
                return false
            }
        }
        return true
    }
}

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

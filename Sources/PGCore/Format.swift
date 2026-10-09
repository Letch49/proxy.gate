import Foundation

public enum ByteFormat {
    /// "503 B", "5.80 KB", "35.6 KB", "1.21 MB".
    public static func short(_ bytes: UInt64) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        let units = ["KB", "MB", "GB", "TB"]
        var value = Double(bytes) / 1024
        var unit = 0
        while value >= 1024 && unit < units.count - 1 {
            value /= 1024
            unit += 1
        }
        let format = value < 10 ? "%.2f %@" : value < 100 ? "%.1f %@" : "%.0f %@"
        return String(format: format, value, units[unit])
    }

    public static func rate(_ bytesPerSecond: Double) -> String {
        short(UInt64(max(0, bytesPerSecond))) + "/s"
    }

    /// "503 bytes", "4440 bytes (4.33 KB)" like the Proxifier log.
    public static func log(_ bytes: UInt64) -> String {
        bytes < 1024 ? "\(bytes) bytes" : "\(bytes) bytes (\(short(bytes)))"
    }

    /// "00:56", "01:02:03".
    public static func duration(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds))
        if s >= 3600 {
            return String(format: "%02d:%02d:%02d", s / 3600, s / 60 % 60, s % 60)
        }
        return String(format: "%02d:%02d", s / 60, s % 60)
    }
}

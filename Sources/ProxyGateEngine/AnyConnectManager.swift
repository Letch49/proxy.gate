import Darwin
import Foundation
import PGCore

/// Drives the Cisco AnyConnect tunnel via `openconnect` (installed by the app through Homebrew).
/// Runs as root (needed for the utun device and routes). The second factor is out-of-band (a push
/// the user approves on their phone), so after the password is sent we just wait for the server.
final class AnyConnectManager: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var serverHost: String?

    /// Called on every state change, and with the pf-bypass entries (concentrator + split routes)
    /// the engine should keep out of redirection while the tunnel is up.
    var onState: (AnyConnectState) -> Void = { _ in }
    var onBypass: ([String]) -> Void = { _ in }

    static func binaryPath() -> String? {
        ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect",
         "/opt/homebrew/sbin/openconnect", "/usr/local/sbin/openconnect", "/usr/bin/openconnect"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private static func vpncScript() -> String? {
        ["/opt/homebrew/etc/vpnc-script", "/usr/local/etc/vpnc-script", "/etc/vpnc/vpnc-script"]
            .first { FileManager.default.fileExists(atPath: $0) }
    }

    /// host[:port] or https URL, no leading "-" (would be read as an option), no shell/space chars.
    static func isSafeServer(_ s: String) -> Bool {
        guard !s.isEmpty, !s.hasPrefix("-"), s.count <= 253 else { return false }
        return s.range(of: #"^(https?://)?[A-Za-z0-9._~-]+(:\d{1,5})?(/[A-Za-z0-9._~/-]*)?$"#, options: .regularExpression) != nil
    }

    static func isSafeUser(_ s: String) -> Bool {
        guard !s.isEmpty, !s.hasPrefix("-"), s.count <= 128 else { return false }
        return s.range(of: #"^[A-Za-z0-9._@\\-]+$"#, options: .regularExpression) != nil
    }

    var connected: Bool { lock.withLock { process?.isRunning ?? false } }

    func connect(server rawServer: String, user: String, password: String) {
        disconnect()
        let server = rawServer.trimmingCharacters(in: .whitespaces)
        guard let bin = Self.binaryPath() else {
            emit(.init(phase: .error, server: server, message: "openconnect is not installed (install it in Settings)"))
            return
        }
        // Reject anything that could be parsed as an openconnect option (argument injection → root).
        guard Self.isSafeServer(server), Self.isSafeUser(user) else {
            emit(.init(phase: .error, server: server, message: "invalid server or username"))
            return
        }
        let host = URL(string: server)?.host ?? server.components(separatedBy: "/").first ?? server
        lock.withLock { serverHost = host }
        emit(.init(phase: .authenticating, server: server))
        // Let openconnect reach the concentrator directly, not through our own redirect.
        if let addrs = try? SocketAddress.resolve(host: host, port: 443) {
            onBypass(addrs.map { "\($0.ip)/\($0.ip.isV4 ? 32 : 128)" })
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        var args = ["--protocol=anyconnect", "--user=\(user)", "--passwd-on-stdin", "--non-inter"]
        if let script = Self.vpncScript() { args += ["--script", script] }
        // "--" stops option parsing so the server can never be read as an option flag.
        args += ["--", server]
        p.arguments = args
        // Force English output (its messages are localized) and give vpnc-script a PATH for route/ifconfig.
        p.environment = ["LC_ALL": "C", "LANG": "C", "PATH": "/sbin:/usr/sbin:/bin:/usr/bin"]
        let inPipe = Pipe(), outPipe = Pipe()
        p.standardInput = inPipe
        p.standardOutput = outPipe
        p.standardError = outPipe
        do { try p.run() } catch {
            emit(.init(phase: .error, server: server, message: "\(error)"))
            return
        }
        inPipe.fileHandleForWriting.write(Data((password + "\n").utf8))
        try? inPipe.fileHandleForWriting.close()
        lock.withLock { process = p }
        emit(.init(phase: .awaitingApproval, server: server,
                   message: "Approve the sign-in on your phone (Telegram)…"))
        Thread { [weak self] in self?.readOutput(outPipe.fileHandleForReading, server: server) }.start()
        p.terminationHandler = { [weak self] _ in self?.handleExit(server: server) }
    }

    func disconnect() {
        let p = lock.withLock { () -> Process? in let p = process; process = nil; return p }
        if let p, p.isRunning { p.interrupt(); usleep(300_000); if p.isRunning { p.terminate() } }
        onBypass([])
        if p != nil { emit(.init(phase: .idle)) }
    }

    // MARK: - Output

    private func readOutput(_ handle: FileHandle, server: String) {
        var buffer = ""
        while true {
            let data = handle.availableData
            if data.isEmpty { break }
            buffer += String(decoding: data, as: UTF8.self)
            while let nl = buffer.firstIndex(of: "\n") {
                let line = String(buffer[..<nl])
                buffer.removeSubrange(..<buffer.index(after: nl))
                parse(line: line, server: server)
            }
        }
    }

    private func parse(line: String, server: String) {
        FileHandle.standardError.write(Data("[anyconnect] \(line)\n".utf8))
        // "Configured as <ip>, with SSL connected and DTLS connected" — the tunnel is up; this
        // is the client's address on the utun. The split-include routes are added just after, so
        // capture them (by that interface) a moment later.
        if line.contains("Configured as"), let r = line.range(of: #"\d+\.\d+\.\d+\.\d+"#, options: .regularExpression) {
            let clientIP = String(line[r])
            emit(.init(phase: .connected, server: server))
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) { [weak self] in
                guard let self, self.connected else { return }
                let routes = self.captureRoutes(clientIP: clientIP)
                self.onBypass(self.serverBypass() + routes)
                self.emit(.init(phase: .connected, server: server, routes: routes))
            }
        }
        if line.contains("Login failed") || line.contains("Authentication failed")
            || line.contains("Cookie was rejected") || line.contains("Failed to obtain") {
            emit(.init(phase: .error, server: server, message: line))
        }
    }

    private func handleExit(server: String) {
        let stillWanted = lock.withLock { process != nil }
        lock.withLock { process = nil }
        onBypass([])
        if stillWanted { emit(.init(phase: .error, server: server, message: "openconnect exited")) }
    }

    /// Split-include subnets: every route on the tunnel's utun interface (the one holding `clientIP`).
    /// The route gateway is the server's peer address, not `clientIP`, so we match by interface.
    private func captureRoutes(clientIP: String) -> [String] {
        guard let iface = tunnelInterface(clientIP: clientIP) else { return [] }
        let skip: Set<String> = ["default", "224.0.0/4", "255.255.255.255/32", clientIP, clientIP + "/32"]
        let out = ServiceUser.shell("/usr/sbin/netstat", ["-rn", "-f", "inet"]).output
        var routes: [String] = []
        for line in out.split(separator: "\n") {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard let dest = cols.first, cols.last == iface, !skip.contains(dest),
                  !dest.hasPrefix("link#"), dest.first?.isNumber == true else { continue }
            routes.append(normalizeRoute(dest))
        }
        return Array(Set(routes)).sorted()
    }

    /// The utun interface whose assigned address is `clientIP`.
    private func tunnelInterface(clientIP: String) -> String? {
        let out = ServiceUser.shell("/sbin/ifconfig", []).output
        var current: String?
        for line in out.split(separator: "\n") {
            if !line.hasPrefix("\t"), !line.hasPrefix(" "), let name = line.split(separator: ":").first {
                current = String(name)
            } else if line.contains("inet \(clientIP) "), let current, current.hasPrefix("utun") {
                return current
            }
        }
        return nil
    }

    /// netstat abbreviates routes ("10/8", "172.16", "10.50.0.0/23"); expand the base to four octets
    /// and, when the prefix is missing, derive it from how many octets were given.
    private func normalizeRoute(_ dest: String) -> String {
        let slash = dest.split(separator: "/", maxSplits: 1).map(String.init)
        var parts = slash[0].split(separator: ".").map(String.init)
        let given = parts.count
        while parts.count < 4 { parts.append("0") }
        let bits = slash.count == 2 ? (Int(slash[1]) ?? 32) : [8, 16, 24, 32][max(0, min(3, given - 1))]
        return parts.joined(separator: ".") + "/\(bits)"
    }

    private func serverBypass() -> [String] {
        guard let host = lock.withLock({ serverHost }), let addrs = try? SocketAddress.resolve(host: host, port: 443) else { return [] }
        return addrs.map { "\($0.ip)/\($0.ip.isV4 ? 32 : 128)" }
    }

    private func emit(_ state: AnyConnectState) { onState(state) }
}

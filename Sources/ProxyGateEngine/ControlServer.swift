import Darwin
import Foundation
import PGCore

/// Unix-socket endpoint the app talks to. One client at a time; when it goes away,
/// interception stops (quitting the app must never leave traffic redirected).
final class ControlServer: @unchecked Sendable {
    private let path: String
    private let allowedUIDs: Set<uid_t>
    /// nil means no cdhash was pinned (manual dev run): uid-only auth.
    private let identity: ClientIdentity?
    /// Accept-loop only. A stale app retries every second; one warning a minute is enough.
    private var lastRejectLog = Date.distantPast
    private let engine: Engine
    private let lock = NSLock()
    private var current: LineChannel?
    private let sendQueue = DispatchQueue(label: "proxygate.control.send")

    init(path: String, allowedUIDs: Set<uid_t>, identity: ClientIdentity?, engine: Engine) {
        self.path = path
        self.allowedUIDs = allowedUIDs
        self.identity = identity
        self.engine = engine
        engine.emit = { [weak self] message in self?.send(message) }
    }

    func send(_ message: EngineMessage) {
        sendQueue.async { [weak self] in
            guard let channel = self?.lock.withLock({ self?.current }) else { return }
            channel.send(message)
        }
    }

    func run() throws {
        let lfd = try UnixSocket.listen(path: path, mode: 0o666)
        while true {
            let cfd = accept(lfd, nil, nil)
            if cfd < 0 { continue }
            var uid: uid_t = 0
            var gid: gid_t = 0
            guard getpeereid(cfd, &uid, &gid) == 0, uid == 0 || allowedUIDs.contains(uid) else {
                Darwin.close(cfd)
                continue
            }
            // Root can do anything anyway; any other uid must also be the pinned app build, so another
            // process of the same user can neither drive the engine nor kick the app off the socket.
            if uid != 0, let identity, !identity.accepts(fd: cfd) {
                if Date().timeIntervalSince(lastRejectLog) > 60 {
                    lastRejectLog = Date()
                    engine.log(.warning, "Rejected a control client (uid \(uid)): code signature does not match the app")
                }
                Darwin.close(cfd)
                continue
            }
            let channel = LineChannel(fd: cfd)
            let previous = lock.withLock {
                let p = current
                current = channel
                return p
            }
            previous?.shutdown()
            Thread { [weak self] in self?.serve(channel) }.start()
        }
    }

    private func serve(_ channel: LineChannel) {
        let decoder = JSONDecoder()
        channel.readLines { line in
            guard let command = try? decoder.decode(ClientCommand.self, from: line) else {
                engine.log(.warning, "Malformed command from app")
                return
            }
            switch command {
            case .hello:
                send(.status(engine.status))
            case .config(let profile):
                engine.apply(profile)
                send(.status(engine.status))
            case .start:
                do {
                    try engine.start()
                } catch {
                    engine.log(.error, "Cannot start interception: \(error)")
                }
                send(.status(engine.status))
            case .stop:
                engine.stop()
                send(.status(engine.status))
            case .installXray(let zipPath, let version):
                engine.installXray(zipPath: zipPath, version: version)
                send(.status(engine.status))
            case .xrayConfig(let json):
                engine.applyXray(config: json)
                send(.status(engine.status))
            case .activeBridge(let bridge):
                engine.setActiveBridge(bridge)
            case .pingServers(let subscription, let targets):
                engine.pingServers(subscription: subscription, targets: targets)
            case .installTpws(let path, let version):
                engine.installTpws(path: path, version: version)
                send(.status(engine.status))
            case .tpwsStrategy(let strategy):
                engine.applyTpws(strategy: strategy)
                send(.status(engine.status))
            case .installByedpi(let tarballPath, let version):
                engine.installByedpi(tarballPath: tarballPath, version: version)
                send(.status(engine.status))
            case .byedpiStrategy(let strategy):
                engine.applyByedpi(strategy: strategy)
                send(.status(engine.status))
            case .bypassDirect(let on):
                engine.setBypassDirect(on)
            case .tuneBypass(let hosts, let rules):
                engine.tuneBypass(hosts: hosts, rules: rules)
            case .cancelTune:
                engine.cancelTune()
            case .checkDNS(let host):
                engine.checkDNS(host: host)
            case .anyConnectConnect(let server, let user, let password):
                engine.anyConnect.connect(server: server, user: user, password: password)
            case .anyConnectDisconnect:
                engine.anyConnect.disconnect()
            }
        }
        let wasCurrent = lock.withLock {
            guard current === channel else { return false }
            current = nil
            return true
        }
        if wasCurrent {
            engine.stop()
            engine.cancelTune()
            // The resolver files point at our stub; without the app nobody manages them.
            engine.releaseDNS()
        }
        sendQueue.sync {}
        channel.close()
    }
}

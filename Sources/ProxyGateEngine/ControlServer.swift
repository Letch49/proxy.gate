import Darwin
import Foundation
import PGCore

/// Unix-socket endpoint the app talks to. One client at a time; when it goes away,
/// interception stops (quitting the app must never leave traffic redirected).
final class ControlServer: @unchecked Sendable {
    private let path: String
    private let allowedUIDs: Set<uid_t>
    private let engine: Engine
    private let lock = NSLock()
    private var current: LineChannel?
    private let sendQueue = DispatchQueue(label: "proxygate.control.send")

    init(path: String, allowedUIDs: Set<uid_t>, engine: Engine) {
        self.path = path
        self.allowedUIDs = allowedUIDs
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
            case .installXray(let zipPath, let version, let sha256):
                engine.installXray(zipPath: zipPath, version: version, sha256: sha256)
                send(.status(engine.status))
            case .xrayConfig(let json):
                engine.applyXray(config: json)
                send(.status(engine.status))
            case .activeBridge(let bridge):
                engine.setActiveBridge(bridge)
            case .pingServers(let subscription, let targets):
                engine.pingServers(subscription: subscription, targets: targets)
            case .installTpws(let path, let version, let sha256):
                engine.installTpws(path: path, version: version, sha256: sha256)
                send(.status(engine.status))
            case .tpwsStrategy(let strategy):
                engine.applyTpws(strategy: strategy)
                send(.status(engine.status))
            case .bypassDirect(let on):
                engine.setBypassDirect(on)
            case .tuneBypass(let hosts):
                engine.tuneBypass(hosts: hosts)
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
        }
        sendQueue.sync {}
        channel.close()
    }
}

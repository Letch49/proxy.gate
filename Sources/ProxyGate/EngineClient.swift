import Foundation
import PGCore

/// Connection to the privileged engine. Reconnects forever; messages are delivered
/// to the main queue in batches so bursts of connections don't flood the UI.
final class EngineClient: @unchecked Sendable {
    var onConnection: ((Bool) -> Void)?
    var onMessages: (([EngineMessage]) -> Void)?

    private let socketPath: String
    private let lock = NSLock()
    private var channel: LineChannel?
    private var pending: [EngineMessage] = []
    private var flushScheduled = false
    private let sendQueue = DispatchQueue(label: "proxygate.client.send")

    init(socketPath: String = ProcessInfo.processInfo.environment["PROXYGATE_SOCKET"] ?? PGConstants.socketPath) {
        self.socketPath = socketPath
    }

    func start() {
        Thread { [weak self] in self?.loop() }.start()
    }

    func send(_ command: ClientCommand) {
        sendQueue.async { [weak self] in
            guard let channel = self?.lock.withLock({ self?.channel }) else { return }
            channel.send(command)
        }
    }

    private func loop() {
        let decoder = JSONDecoder()
        while true {
            guard let fd = try? UnixSocket.connect(path: socketPath) else {
                Thread.sleep(forTimeInterval: 2)
                continue
            }
            let channel = LineChannel(fd: fd)
            lock.withLock { self.channel = channel }
            DispatchQueue.main.async { self.onConnection?(true) }
            channel.readLines { line in
                if let message = try? decoder.decode(EngineMessage.self, from: line) {
                    enqueue(message)
                }
            }
            lock.withLock { self.channel = nil }
            sendQueue.sync {}
            channel.close()
            DispatchQueue.main.async { self.onConnection?(false) }
            Thread.sleep(forTimeInterval: 1)
        }
    }

    /// Live data reaches the UI once per stats interval; status replies (Start/Stop) go immediately.
    private func enqueue(_ message: EngineMessage) {
        var urgent = false
        if case .status = message { urgent = true }
        let schedule = lock.withLock {
            pending.append(message)
            if flushScheduled && !urgent { return false }
            flushScheduled = true
            return true
        }
        if schedule {
            let delay = urgent ? 0.05 : PGConstants.statsInterval
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { [weak self] in self?.flush() }
        }
    }

    private func flush() {
        let batch: [EngineMessage] = lock.withLock {
            let b = pending
            pending = []
            flushScheduled = false
            return b
        }
        onMessages?(batch)
    }
}

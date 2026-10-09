import Foundation
import PGCore
import os

final class ConnCounter: Sendable {
    private let state = OSAllocatedUnfairLock(initialState: (sent: UInt64(0), received: UInt64(0)))

    func addSent(_ n: Int) { state.withLock { $0.sent += UInt64(n) } }
    func addReceived(_ n: Int) { state.withLock { $0.received += UInt64(n) } }
    var totals: (sent: UInt64, received: UInt64) { state.withLock { $0 } }
}

/// Live connections and their byte counters.
final class Registry: @unchecked Sendable {
    private let lock = NSLock()
    private var lastID: UInt64 = 0
    private var counters: [UInt64: ConnCounter] = [:]
    private var reported: [UInt64: (UInt64, UInt64)] = [:]

    func nextID() -> UInt64 {
        lock.withLock {
            lastID += 1
            return lastID
        }
    }

    func add(_ id: UInt64) -> ConnCounter {
        let counter = ConnCounter()
        lock.withLock { counters[id] = counter }
        return counter
    }

    func remove(_ id: UInt64) {
        lock.withLock {
            counters[id] = nil
            reported[id] = nil
        }
    }

    /// Counters that changed since the previous call.
    func changes() -> [ConnBytes] {
        lock.withLock {
            var out: [ConnBytes] = []
            for (id, counter) in counters {
                let t = counter.totals
                if let last = reported[id], last == (t.sent, t.received) {
                    continue
                }
                reported[id] = (t.sent, t.received)
                out.append(ConnBytes(id: id, sent: t.sent, received: t.received))
            }
            return out
        }
    }
}

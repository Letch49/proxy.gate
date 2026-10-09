import Foundation
import SystemConfiguration

/// A network adapter a bridge can be bound to. Identified by MAC: BSD names (en7, en8…)
/// of USB adapters may change between ports.
struct NetInterface: Identifiable, Hashable {
    let mac: String
    let bsdName: String
    let displayName: String
    /// Wired (Ethernet/Thunderbolt/USB-LAN) vs Wi-Fi. Wired wins in auto-switch ("at work").
    let wired: Bool

    var id: String { mac }
    var title: String { displayName.contains(bsdName) ? displayName : "\(displayName) (\(bsdName))" }

    /// Adapters currently known to the system (an unplugged USB adapter is absent).
    static func all() -> [NetInterface] {
        guard let list = SCNetworkInterfaceCopyAll() as? [SCNetworkInterface] else { return [] }
        return list.compactMap { iface in
            guard let bsd = SCNetworkInterfaceGetBSDName(iface) as String?,
                  let mac = SCNetworkInterfaceGetHardwareAddressString(iface) as String?,
                  bsd.hasPrefix("en") else { return nil }
            let name = SCNetworkInterfaceGetLocalizedDisplayName(iface) as String? ?? bsd
            let type = SCNetworkInterfaceGetInterfaceType(iface) as String?
            let wired = type != (kSCNetworkInterfaceTypeIEEE80211 as String)
            return NetInterface(mac: mac.lowercased(), bsdName: bsd, displayName: name, wired: wired)
        }
        .sorted { $0.bsdName.localizedStandardCompare($1.bsdName) == .orderedAscending }
    }
}

/// Notifies when the network changes (link up/down, address, interface added/removed), debounced,
/// so the app can re-evaluate which bridge should be active.
final class InterfaceWatcher {
    var onChange: (() -> Void)?

    private var store: SCDynamicStore?
    private var source: CFRunLoopSource?
    private var pending: DispatchWorkItem?

    func start() {
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            Unmanaged<InterfaceWatcher>.fromOpaque(info).takeUnretainedValue().fire()
        }
        guard let store = SCDynamicStoreCreate(nil, "ProxyGate.net" as CFString, callback, &context) else { return }
        let patterns = ["State:/Network/Interface/[^/]+/Link", "State:/Network/Interface/[^/]+/IPv4"] as CFArray
        SCDynamicStoreSetNotificationKeys(store, ["State:/Network/Global/IPv4"] as CFArray, patterns)
        source = SCDynamicStoreCreateRunLoopSource(nil, store, 0)
        CFRunLoopAddSource(CFRunLoopGetMain(), source, .commonModes)
        self.store = store
    }

    private func fire() {
        // Link flaps and DHCP settle within ~2s; collapse a burst into one evaluation.
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in self?.onChange?() }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: work)
    }
}

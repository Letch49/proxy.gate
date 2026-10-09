import Darwin
import Foundation
import PGCore

signal(SIGPIPE, SIG_IGN)

// Raise the open-file limit: a LaunchDaemon defaults to 256, and a burst of connections plus the
// relays would otherwise hit EMFILE ("Too many open files").
var limit = rlimit()
if getrlimit(RLIMIT_NOFILE, &limit) == 0 {
    limit.rlim_cur = min(rlim_t(10240), limit.rlim_max)
    setrlimit(RLIMIT_NOFILE, &limit)
}

// The engine log records connection targets (hostnames) — keep it readable by root only, not 0644.
chmod(PGConstants.helperLogPath, 0o600)

var socketPath = PGConstants.socketPath
var allowedUIDs = Set<uid_t>()
if let sudoUID = ProcessInfo.processInfo.environment["SUDO_UID"].flatMap({ uid_t($0) }) {
    allowedUIDs.insert(sudoUID)
}

var args = CommandLine.arguments.dropFirst().makeIterator()
while let arg = args.next() {
    switch arg {
    case "--socket":
        socketPath = args.next() ?? socketPath
    case "--allow-uid":
        if let uid = args.next().flatMap({ uid_t($0) }) {
            allowedUIDs.insert(uid)
        }
    case "--version":
        print(PGConstants.version)
        exit(0)
    case "--print-rules":
        print(PFRules.generate(listenPort: AdvancedSettings().listenPort, captureIPv6: true, blockQUIC: true, bypass: []), terminator: "")
        exit(0)
    case "--geo-test":
        let geo = GeoDB()
        func site(_ cat: String, _ host: String) {
            print("geosite:\(cat) \(host) -> \(geo.matches(token: "geosite:\(cat)", host: host, ip: IPAddr("0.0.0.0")!))")
        }
        func ipt(_ cc: String, _ ip: String) {
            print("geoip:\(cc) \(ip) -> \(geo.matches(token: "geoip:\(cc)", host: nil, ip: IPAddr(ip)!))")
        }
        site("category-ru", "vk.com"); site("category-ru", "google.com")
        site("private", "localhost")
        ipt("ru", "5.255.255.242"); ipt("ru", "8.8.8.8"); ipt("private", "192.168.1.1")
        exit(0)
    default:
        FileHandle.standardError.write(Data("usage: proxygate-engine [--socket PATH] [--allow-uid UID]... [--version] [--print-rules]\n".utf8))
        exit(2)
    }
}

guard getuid() == 0 else {
    FileHandle.standardError.write(Data("proxygate-engine must run as root (it manages pf)\n".utf8))
    exit(1)
}

// Leftovers from a crashed run would redirect traffic to nobody.
PF.flushAnchor()

let engine = Engine()
let server = ControlServer(path: socketPath, allowedUIDs: allowedUIDs, engine: engine)

var signalSources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT, SIGHUP] {
    signal(sig, SIG_IGN)
    let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    source.setEventHandler {
        engine.stop()
        unlink(socketPath)
        exit(0)
    }
    source.resume()
    signalSources.append(source)
}

Thread {
    do {
        try server.run()
    } catch {
        FileHandle.standardError.write(Data("control socket failed: \(error)\n".utf8))
        exit(1)
    }
}.start()

FileHandle.standardError.write(Data("proxygate-engine \(PGConstants.version) listening on \(socketPath)\n".utf8))
dispatchMain()

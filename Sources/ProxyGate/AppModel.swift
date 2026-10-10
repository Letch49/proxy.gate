import AppKit
import Observation
import PGCore
import SwiftUI

/// Counts are capped for display so busy apps don't turn into ever-growing numbers.
/// Runtime lookup for keys that are not literals (enum raw values).
func loc(_ key: String) -> String {
    NSLocalizedString(key, comment: "")
}

func countText(_ n: Int) -> String {
    n >= 1000 ? "1000+" : "\(n)"
}

enum AppCategory: String, CaseIterable {
    case application = "Applications"
    case cli = "Command-line tools"
    case system = "System services"
    case unknown = "Unknown"

    static func of(_ app: AppIdentity) -> AppCategory {
        guard app.pid > 0, let path = app.path else { return .unknown }
        let systemPrefixes = ["/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/", "/usr/bin/", "/Library/Apple/"]
        if systemPrefixes.contains(where: path.hasPrefix) || (app.bundleID?.hasPrefix("com.apple.") ?? false) {
            return .system
        }
        return app.bundleNames.isEmpty ? .cli : .application
    }
}

/// One live connection (only while open — closed ones are folded into their flow).
struct ConnectionItem {
    let id: UInt64
    let flowID: String
    let started: Date
    var sent: UInt64 = 0
    var received: UInt64 = 0
}

/// All connections of one application to one target, merged into a stable row.
struct Flow: Identifiable {
    let id: String
    let app: String
    /// Executable name, used in the log.
    let appName: String
    /// Outer .app name for bundled apps ("Google Chrome" for its helpers), else the executable.
    let appGroup: String
    let category: AppCategory
    let target: String
    let host: String
    let domain: String
    var rule: String
    var kind: RouteKind
    var active = 0
    var total = 0
    var sent: UInt64 = 0
    var received: UInt64 = 0
    var activeSince: Date?
    var lastActivity: Date
}

struct LogLine: Identifiable {
    enum Kind { case normal, error, blocked, notice }

    let id: Int
    let time: Date
    let text: String
    let kind: Kind
}

enum LogMode: String, CaseIterable, Identifiable {
    case all = "All events"
    case compact = "Compact"
    case errors = "Errors only"
    var id: String { rawValue }
}

struct AppTraffic: Identifiable {
    let id: String
    var category: AppCategory
    var active = 0
    var total = 0
    var sent: UInt64 = 0
    var received: UInt64 = 0
    var downRate: Double = 0
    var upRate: Double = 0
    var pendingDown: UInt64 = 0
    var pendingUp: UInt64 = 0
}

struct HostStat: Identifiable {
    let id: String
    var apps: Set<String> = []
    var connections = 0
    var failures = 0
    var sent: UInt64 = 0
    var received: UInt64 = 0
    var route = ""
    var lastSeen = Date()
}

/// Sidebar destinations.
enum AppSection: String, CaseIterable, Identifiable {
    case connections = "Connections", traffic = "Traffic", log = "Log"
    case rules = "Rules", proxies = "Proxies", vpn = "VPN", dpi = "DPI", anyconnect = "AnyConnect", dns = "DNS", settings = "Settings"
    case mcp = "AI (MCP)"

    var id: String { rawValue }

    static let monitoring: [AppSection] = [.connections, .traffic, .log]
    static let configuration: [AppSection] = [.rules, .proxies, .vpn, .dpi, .anyconnect, .dns, .settings]

    var icon: String {
        switch self {
        case .connections: return "list.bullet"
        case .traffic: return "chart.bar"
        case .log: return "clock"
        case .rules: return "list.bullet.rectangle"
        case .proxies: return "server.rack"
        case .vpn: return "shield.lefthalf.filled"
        case .dpi: return "bolt.horizontal.circle"
        case .anyconnect: return "lock.shield"
        case .dns: return "globe"
        case .settings: return "gearshape"
        case .mcp: return "sparkles"
        }
    }
}

enum ActiveSheet: String, Identifiable {
    case profiles
    var id: String { rawValue }
}

struct ProxyStatus {
    var ok: Bool
    var text: String
    var latencyMs: Int?
}

struct RuleHits {
    var count = 0
    var last = Date()
}

/// A suspected connection loop awaiting the user's decision.
struct LoopAlert: Identifiable {
    let id = UUID()
    let app: String
    let target: String
    let count: Int
}

@MainActor
@Observable
final class AppModel {
    static let shared = AppModel()

    // Profiles
    var profiles: [Profile]
    var activeProfileID: UUID

    // Engine
    var engineConnected = false
    var engineStatus: EngineStatus?
    var helperInstalled = HelperInstaller.isInstalled
    var helperBusy = false
    /// What the user asked for; re-sent after the engine reconnects.
    var wantRunning: Bool

    // Live data
    var connections: [UInt64: ConnectionItem] = [:]
    var flows: [String: Flow] = [:]
    var log: [LogLine] = []
    var appTraffic: [String: AppTraffic] = [:]
    var hostStats: [String: HostStat] = [:]
    /// Everything seen this session, offered as suggestions in the rule editor.
    var seenApps: Set<String> = []
    var downRate: Double = 0
    var upRate: Double = 0
    var totalSent: UInt64 = 0
    var totalReceived: UInt64 = 0
    var totalConnections = 0
    var totalFailures = 0
    var totalBlocked = 0
    var sessionStart = Date()
    var now = Date()

    // UI
    var section: AppSection = .connections
    var sheet: ActiveSheet?
    var ruleHits: [String: RuleHits] = [:]
    var proxyStatus: [UUID: ProxyStatus] = [:]
    var checkingProxies: Set<UUID> = []
    var loopAlert: LoopAlert?
    var alertMessage: String?
    /// Rule prefilled from the connection list ("Create rule for…").
    var ruleDraft: Rule?

    var autoStart: Bool {
        didSet { UserDefaults.standard.set(autoStart, forKey: "autoStart") }
    }
    var showSpeedInMenuBar: Bool {
        didSet { UserDefaults.standard.set(showSpeedInMenuBar, forKey: "showSpeedInMenuBar") }
    }
    /// Seconds an idle flow stays in the list.
    var idleRetention: Double {
        didSet { UserDefaults.standard.set(idleRetention, forKey: "idleRetention") }
    }
    var logMode: LogMode {
        didSet { UserDefaults.standard.set(logMode.rawValue, forKey: "logMode") }
    }
    var loopDetection: Bool {
        didSet { UserDefaults.standard.set(loopDetection, forKey: "loopDetection") }
    }
    /// Connections of one app to one target within 10 s that count as a loop.
    var loopThreshold: Int {
        didSet { UserDefaults.standard.set(loopThreshold, forKey: "loopThreshold") }
    }

    // MCP server: a local, token-authenticated endpoint that lets an AI agent read and edit rules.
    var mcpEnabled: Bool {
        didSet { UserDefaults.standard.set(mcpEnabled, forKey: "mcpEnabled"); applyMCP() }
    }
    var mcpPort: Int {
        didSet { UserDefaults.standard.set(mcpPort, forKey: "mcpPort"); if mcpEnabled { applyMCP() } }
    }
    /// Set to the moment an agent first authenticates, so Settings can show the endpoint as active.
    var mcpLastSeen: Date? {
        didSet { UserDefaults.standard.set(mcpLastSeen?.timeIntervalSince1970, forKey: "mcpLastSeen") }
    }
    /// Bearer token, mirrored in the Keychain.
    var mcpToken: String = ""
    @ObservationIgnored var mcpServer: MCPServer?

    @ObservationIgnored private let client = EngineClient()
    @ObservationIgnored private var logCounter = 0
    @ObservationIgnored private var pendingDown: UInt64 = 0
    @ObservationIgnored private var pendingUp: UInt64 = 0
    @ObservationIgnored private var configPushScheduled = false
    @ObservationIgnored private var timer: Timer?
    /// Last time an "open" line was logged per flow, for compact mode.
    @ObservationIgnored private var lastLoggedOpen: [String: Date] = [:]
    @ObservationIgnored private var saveScheduled = false
    /// Recent open times per flow, for loop detection.
    @ObservationIgnored private var openTimes: [String: [Date]] = [:]
    @ObservationIgnored private var loopDismissed: Set<String> = []

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "MM.dd HH:mm:ss"
        return f
    }()

    init() {
        let state = ProfileStore.load()
        profiles = state.profiles
        activeProfileID = state.activeID
        let defaults = UserDefaults.standard
        autoStart = defaults.bool(forKey: "autoStart")
        showSpeedInMenuBar = defaults.bool(forKey: "showSpeedInMenuBar")
        idleRetention = defaults.object(forKey: "idleRetention") as? Double ?? 60
        logMode = LogMode(rawValue: defaults.string(forKey: "logMode") ?? "") ?? .compact
        loopDetection = defaults.object(forKey: "loopDetection") as? Bool ?? true
        loopThreshold = defaults.object(forKey: "loopThreshold") as? Int ?? 300
        wantRunning = defaults.bool(forKey: "autoStart")
        mcpEnabled = defaults.bool(forKey: "mcpEnabled")
        mcpPort = defaults.object(forKey: "mcpPort") as? Int ?? MCPServer.defaultPort
        if let ts = defaults.object(forKey: "mcpLastSeen") as? Double { mcpLastSeen = Date(timeIntervalSince1970: ts) }
        mcpToken = AppModel.loadOrCreateMCPToken()

        client.onConnection = { [weak self] connected in self?.engineConnectionChanged(connected) }
        client.onMessages = { [weak self] messages in self?.handle(messages) }
        client.start()
        migrateLegacyVPN()
        loadRememberedBridges()
        netWatcher.onChange = { [weak self] in self?.networkChanged() }
        netWatcher.start()
        applyMCP()

        timer = Timer.scheduledTimer(withTimeInterval: PGConstants.statsInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick() }
        }
        addLog("ProxyGate \(PGConstants.version) started", .notice)
    }

    // MARK: - Profile

    var profile: Profile {
        get { profiles.first { $0.id == activeProfileID } ?? profiles[0] }
        set {
            var p = newValue
            p.normalizeRules()
            if let i = profiles.firstIndex(where: { $0.id == p.id }) {
                profiles[i] = p
            }
            persistAndPush()
        }
    }

    func activate(_ id: UUID) {
        guard id != activeProfileID, profiles.contains(where: { $0.id == id }) else { return }
        activeProfileID = id
        addLog("Profile \"\(profile.name)\" loaded", .notice)
        persistAndPush()
    }

    /// Pages edit the profile live, so saving and pushing are debounced.
    func persistAndPush() {
        if !saveScheduled {
            saveScheduled = true
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                guard let self else { return }
                self.saveScheduled = false
                ProfileStore.save(ProfileStore.State(profiles: self.profiles, activeID: self.activeProfileID))
            }
        }
        guard !configPushScheduled else { return }
        configPushScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
            guard let self else { return }
            self.configPushScheduled = false
            self.client.send(.config(self.profile))
        }
    }

    // MARK: - Engine control

    var isRunning: Bool { engineStatus?.running ?? false }

    /// The installed helper pins another app build's cdhash, so it refuses this app.
    var helperPinStale = HelperInstaller.needsReinstall

    var helperOutdated: Bool {
        if helperPinStale { return true }
        guard let version = engineStatus?.version else { return false }
        return version != PGConstants.version
    }

    var statusText: String {
        if !helperInstalled { return String(localized: "Helper not installed") }
        if !engineConnected { return String(localized: "Connecting to helper…") }
        return isRunning ? String(localized: "Running") : String(localized: "Stopped")
    }

    // MARK: - Language

    /// "" = follow the system, otherwise "en" / "ru". Applied on relaunch (standard macOS behaviour).
    var language: String {
        UserDefaults.standard.string(forKey: "appLanguage") ?? ""
    }

    func setLanguage(_ code: String) {
        guard code != language else { return }
        UserDefaults.standard.set(code, forKey: "appLanguage")
        if code.isEmpty {
            UserDefaults.standard.removeObject(forKey: "AppleLanguages")
        } else {
            UserDefaults.standard.set([code], forKey: "AppleLanguages")
        }
        UserDefaults.standard.synchronize()
        relaunch()
    }

    private func relaunch() {
        let path = Bundle.main.bundlePath
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/sh")
        task.arguments = ["-c", "sleep 1; /usr/bin/open \"$0\"", path]
        try? task.run()
        NSApp.terminate(nil)
    }

    func toggle() {
        isRunning ? stop() : start()
    }

    func start() {
        let wasRunning = wantRunning
        wantRunning = true
        if !wasRunning { DispatchQueue.main.async { [weak self] in self?.networkChanged() } }
        guard engineConnected else {
            if !helperInstalled {
                alertMessage = String(localized: "ProxyGate needs its privileged helper to redirect traffic. Install it in Advanced settings or from the banner.")
            }
            return
        }
        client.send(.config(profile))
        client.send(.start)
    }

    func stop() {
        wantRunning = false
        client.send(.stop)
    }

    // MARK: - Xray core

    var xrayVersion: String? { engineStatus?.xrayVersion }
    var xrayRunning: Bool { engineStatus?.xrayRunning ?? false }
    var xrayError: String? { engineStatus?.xrayError }
    var xrayBusy = false
    var xrayMessage: String?
    @ObservationIgnored private var xrayInstallToken = 0

    /// Downloads and verifies the latest Xray core, then has the engine install it as root.
    func installXray() {
        guard engineConnected else {
            alertMessage = String(localized: "Connect the helper before installing the VPN core.")
            return
        }
        if helperOutdated {
            alertMessage = String(localized: "The privileged helper is outdated and can't manage the VPN core. Reinstall it in the Privileged helper section below, then try again.")
            return
        }
        xrayBusy = true
        xrayMessage = String(localized: "Downloading…")
        Task {
            do {
                let release = try await XrayDownloader.latest()
                await MainActor.run { self.xrayMessage = String(localized: "Verifying \(release.version)…") }
                let ready = try await XrayDownloader.prepare(release) { fraction in
                    guard let fraction else { return }
                    let percent = Int(fraction * 100)
                    DispatchQueue.main.async { self.xrayMessage = "\(String(localized: "Downloading")) \(percent)%" }
                }
                await MainActor.run {
                    self.client.send(.installXray(zipPath: ready.zipPath, version: ready.version))
                    self.xrayMessage = String(localized: "Installing \(ready.version)…")
                    self.addLog("VPN core \(ready.version) downloaded, installing", .notice)
                    // The engine replies with a status once installed; fail loudly if it never does.
                    // Longer than the engine's own checksum fetch timeout (45 s) plus staging and unzip.
                    self.xrayInstallToken += 1
                    let token = self.xrayInstallToken
                    DispatchQueue.main.asyncAfter(deadline: .now() + 75) { [weak self] in
                        guard let self, self.xrayBusy, self.xrayInstallToken == token else { return }
                        self.xrayBusy = false
                        self.xrayMessage = nil
                        self.alertMessage = self.xrayError.map { String(localized: "VPN core install failed: \($0)") }
                            ?? String(localized: "The VPN core install did not complete. Check \(PGConstants.xrayLogPath) and that the helper is up to date.")
                    }
                }
            } catch {
                await MainActor.run {
                    self.xrayBusy = false
                    self.xrayMessage = nil
                    self.alertMessage = String(localized: "Could not install the VPN core: \(String(describing: error))")
                }
            }
        }
    }

    /// Pushes a full Xray JSON config to run, or nil to stop the core.
    func setXrayConfig(_ json: String?) {
        client.send(.xrayConfig(json))
    }

    // MARK: - DPI bypass (tpws / ByeDPI)

    var tpwsVersion: String? { engineStatus?.tpwsVersion }
    var tpwsRunning: Bool { engineStatus?.tpwsRunning ?? false }
    var tpwsError: String? { engineStatus?.tpwsError }
    var tpwsBusy = false
    var tpwsMessage: String?

    var byedpiVersion: String? { engineStatus?.byedpiVersion }
    var byedpiRunning: Bool { engineStatus?.byedpiRunning ?? false }
    var byedpiError: String? { engineStatus?.byedpiError }
    var byedpiBusy = false
    var byedpiMessage: String?

    var bypassEnabled: Bool { profile.bypassEnabled }
    var bypassStrategyIndex: Int { profile.bypassStrategyIndex }

    /// The DPI core the active profile uses, its strategy list, and whether it is installed.
    var dpiEngine: DPIEngine { profile.dpiEngine }
    var activeStrategies: [DPIStrategy] { profile.dpiEngine.strategies() }
    var dpiCoreInstalled: Bool { profile.dpiEngine == .byedpi ? byedpiVersion != nil : tpwsVersion != nil }
    var dpiCoreRunning: Bool { profile.dpiEngine == .byedpi ? byedpiRunning : tpwsRunning }
    var dpiCoreError: String? { profile.dpiEngine == .byedpi ? byedpiError : tpwsError }

    private func strategyFlags(_ index: Int) -> [String] {
        let all = activeStrategies
        return all.indices.contains(index) ? all[index].flags : (all.first?.flags ?? [])
    }

    /// Sends run/stop to the active engine's core (tpws or ByeDPI).
    func sendDpiStrategy(_ flags: [String]?) {
        if profile.dpiEngine == .byedpi { client.send(.byedpiStrategy(flags)) }
        else { client.send(.tpwsStrategy(flags)) }
    }

    func installTpws() {
        guard engineConnected else { return }
        tpwsBusy = true
        tpwsMessage = String(localized: "Downloading…")
        Task {
            do {
                let ready = try await TpwsDownloader.prepare()
                await MainActor.run {
                    self.client.send(.installTpws(path: ready.binaryPath, version: ready.version))
                    self.tpwsMessage = String(localized: "Installing \(ready.version)…")
                    self.addLog("DPI-bypass core (tpws) \(ready.version) downloaded, installing", .notice)
                }
            } catch {
                await MainActor.run {
                    self.tpwsBusy = false
                    self.tpwsMessage = nil
                    self.alertMessage = String(localized: "Could not install the DPI-bypass core: \(String(describing: error))")
                }
            }
        }
    }

    func installByedpi() {
        guard engineConnected else { return }
        byedpiBusy = true
        byedpiMessage = String(localized: "Downloading…")
        Task {
            do {
                let ready = try await ByeDpiDownloader.prepare()
                await MainActor.run {
                    self.client.send(.installByedpi(tarballPath: ready.tarballPath, version: ready.version))
                    self.byedpiMessage = String(localized: "Installing \(ready.version)…")
                    self.addLog("ByeDPI core \(ready.version) downloaded, installing", .notice)
                }
            } catch {
                await MainActor.run {
                    self.byedpiBusy = false
                    self.byedpiMessage = nil
                    self.alertMessage = String(localized: "Could not install ByeDPI: \(String(describing: error))")
                }
            }
        }
    }

    /// Switches the active DPI engine: stops the old core, resets the strategy, and (if bypass is on)
    /// starts the new one. The engine side follows `profile.dpiEngine` pushed with the config.
    func setDpiEngine(_ engine: DPIEngine) {
        guard engine != profile.dpiEngine else { return }
        sendDpiStrategy(nil)                 // stop the core we are leaving
        profile.dpiEngine = engine
        profile.bypassStrategyIndex = 0
        didAutoTune = false
        if profile.bypassEnabled, dpiCoreInstalled {
            sendDpiStrategy(strategyFlags(0))
        }
        addLog("DPI engine: \(engine.title)", .notice)
    }

    /// Turns DPI bypass on/off: runs the active core with the chosen strategy and tells the engine to
    /// route direct connections through it.
    func setBypass(_ on: Bool) {
        if on, !dpiCoreInstalled {
            alertMessage = String(localized: "Install the DPI-bypass core first (DPI tab).")
            return
        }
        profile.bypassEnabled = on
        if on {
            sendDpiStrategy(strategyFlags(profile.bypassStrategyIndex))
            client.send(.bypassDirect(true))
            addLog("DPI bypass on", .notice)
            autoTuneIfNeeded()
        } else {
            client.send(.bypassDirect(false))
            sendDpiStrategy(nil)
            addLog("DPI bypass off", .notice)
        }
    }

    func selectStrategy(_ index: Int) {
        profile.bypassStrategyIndex = index
        if profile.bypassEnabled { sendDpiStrategy(strategyFlags(index)) }
    }

    var tuning = false
    /// Live step of the running auto-tune, and the last finished report (DPI page).
    var tuneProgress: TuneProgress?
    var tuneReport: TuneReport?
    @ObservationIgnored private var didAutoTune = false

    /// Test hosts for the DPI auto-tune, parsed from the editable list.
    var dpiTestHosts: [String] {
        profile.dpiTestHosts.components(separatedBy: CharacterSet(charactersIn: ";,\n"))
            .map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// Runs auto-tune once per session when bypass is on (on enable and on launch/reconnect).
    func autoTuneIfNeeded() {
        guard !didAutoTune, profile.bypassEnabled, engineConnected, dpiCoreInstalled else { return }
        didAutoTune = true
        tuneBypass()
    }

    /// Asks the engine to diagnose the test hosts and try the installed cores on the blocked ones.
    /// The probes go straight out (never through VPN or a proxy) and dial the resolved IP with the
    /// real name for SNI, so the result reflects this DNS + core + strategy, not the current routing.
    func tuneBypass() {
        guard engineConnected, tpwsVersion != nil || byedpiVersion != nil else {
            alertMessage = String(localized: "Install the DPI-bypass core first (DPI tab).")
            return
        }
        tuning = true
        tuneProgress = nil
        // The engine reads the DNS provider from the profile; push edits made a moment ago first.
        client.send(.config(profile))
        client.send(.tuneBypass(hosts: dpiTestHosts))
    }

    func cancelTune() {
        client.send(.cancelTune)
    }

    // MARK: - DNS

    var dnsState: SystemDNSState { engineStatus?.dns ?? SystemDNSState() }
    var dnsChecking = false
    var dnsReport: DNSCheckReport?

    func checkDNS(_ host: String) {
        let name = host.trimmingCharacters(in: .whitespaces).lowercased()
        guard engineConnected, DNSName.isValid(name) else { return }
        dnsChecking = true
        client.send(.config(profile))
        client.send(.checkDNS(host: name))
    }

    func selectDNSProvider(_ id: String) {
        profile.dns.providerID = id
        dnsReport = nil
    }

    func setDNSTransport(_ transport: DNSTransport) {
        profile.dns.transport = transport
        dnsReport = nil
    }

    /// Adds a custom provider; returns the reason when the input is rejected.
    func addDNSProvider(name: String, addresses: String, dohURL: String) -> DNSInputError? {
        switch DNSProvider.custom(name: name, addresses: addresses, dohURL: dohURL) {
        case .success(let provider):
            profile.dns.customProviders.append(provider)
            selectDNSProvider(provider.id)
            return nil
        case .failure(let error):
            return error
        }
    }

    func removeDNSProvider(_ id: String) {
        var p = profile
        p.dns.customProviders.removeAll { $0.id == id }
        if p.dns.providerID == id { p.dns.providerID = DNSProviders.builtIn[0].id }
        profile = p
    }

    /// Adds the short domain of each host apps cannot resolve to the provider-resolved list.
    func resolveThroughProvider(hosts: [String]) {
        var p = profile
        var list = DNSDomainList.parse(p.dns.resolveDomains).valid
        for host in hosts {
            guard let d = DNSDomainList.suggestion(for: host), !DNSDomainList.covers(list, host: host) else { continue }
            list.append(d)
        }
        p.dns.resolveDomains = list.joined(separator: "; ")
        p.dns.resolveThroughProvider = true
        profile = p
        addLog("DNS: \(p.dns.upstream.title) now resolves \(list.joined(separator: ", "))", .notice)
    }

    // MARK: - AnyConnect (openconnect)

    var anyConnect: AnyConnectState { engineStatus?.anyConnect ?? AnyConnectState() }
    var anyConnectUp: Bool { anyConnect.phase == .connected }
    var anyConnectBusy: Bool {
        [.authenticating, .awaitingApproval, .connecting].contains(anyConnect.phase)
    }
    var openConnectInstalled: Bool {
        ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect", "/usr/bin/openconnect",
         "/opt/homebrew/sbin/openconnect", "/usr/local/sbin/openconnect"]
            .contains { FileManager.default.isExecutableFile(atPath: $0) }
    }
    var openConnectBusy = false
    var openConnectMessage: String?

    var anyConnectServer: String {
        get { UserDefaults.standard.string(forKey: "anyConnectServer") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "anyConnectServer") }
    }
    var anyConnectUser: String {
        get { UserDefaults.standard.string(forKey: "anyConnectUser") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "anyConnectUser") }
    }

    func savedAnyConnectPassword(server: String, user: String) -> String {
        Keychain.read(account: "anyconnect:\(user)@\(server)") ?? ""
    }

    func anyConnectConnect(server: String, user: String, password: String) {
        guard engineConnected else { return }
        guard openConnectInstalled else {
            alertMessage = String(localized: "Install openconnect first (Settings → AnyConnect).")
            return
        }
        anyConnectServer = server
        anyConnectUser = user
        Keychain.save(password, account: "anyconnect:\(user)@\(server)")
        client.send(.anyConnectConnect(server: server, user: user, password: password))
        addLog("AnyConnect connecting to \(server)…", .notice)
    }

    func anyConnectDisconnect() {
        client.send(.anyConnectDisconnect)
    }

    /// Installs openconnect via Homebrew (runs as the user, not the engine).
    func installOpenConnect() {
        guard let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            alertMessage = String(localized: "Homebrew not found. Install it from brew.sh, then try again.")
            return
        }
        openConnectBusy = true
        openConnectMessage = String(localized: "Installing via Homebrew…")
        Task.detached {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: brew)
            p.arguments = ["install", "openconnect"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
            await MainActor.run {
                self.openConnectBusy = false
                self.openConnectMessage = nil
                self.addLog(self.openConnectInstalled ? "openconnect installed" : "openconnect install failed", .notice)
            }
        }
    }

    /// Reflects the AnyConnect tunnel as read-only "dynamic" rules (concentrator → direct, corp
    /// subnets) and clears them when it drops. The real routing is pf-level; these are for visibility.
    private func syncAnyConnectRules(_ state: AnyConnectState) {
        var p = profile
        let had = p.rules.contains { $0.dynamic }
        if state.phase == .connected {
            var rules: [Rule] = []
            if let server = state.server {
                let host = URL(string: server)?.host ?? server
                rules.append(Rule(name: String(localized: "AnyConnect concentrator"), targetHosts: host, action: .direct, dynamic: true))
            }
            if !state.routes.isEmpty {
                rules.append(Rule(name: String(localized: "AnyConnect routes"), targetHosts: state.routes.joined(separator: "; "), action: .direct, dynamic: true))
            }
            p.rules.removeAll { $0.dynamic }
            p.rules.insert(contentsOf: rules, at: 0)
            profile = p
        } else if had {
            p.rules.removeAll { $0.dynamic }
            profile = p
        }
    }

    private func bypassTuned(_ report: TuneReport) {
        tuning = false
        tuneProgress = nil
        tuneReport = report
        // Learn the hosts that really needed a bypass (not those that open directly).
        let learned = report.hosts.filter { $0.ok && !$0.directOK }.map(\.host)
        if !learned.isEmpty {
            var p = profile
            for host in learned where !p.bypassHosts.contains(host) { p.bypassHosts.append(host) }
            profile = p
        }
        guard report.verdict == .found, let engine = report.engine else { return }
        let installed = engine == .byedpi ? byedpiVersion != nil : tpwsVersion != nil
        guard installed else { return }
        if engine != profile.dpiEngine { setDpiEngine(engine) }
        selectStrategy(report.strategyIndex)
        let label = activeStrategies.indices.contains(report.strategyIndex) ? activeStrategies[report.strategyIndex].label : ""
        addLog("DPI auto-tune picked \(engine.title) \"\(label)\"", .notice)
    }

    // MARK: - Updates

    /// Newer versions available for the cores (nil = up to date / unknown).
    var xrayUpdate: String?
    var tpwsUpdate: String?
    var updateCount: Int { [xrayUpdate, tpwsUpdate].compactMap { $0 }.count }
    @ObservationIgnored private var lastUpdateCheck = Date.distantPast

    /// Checks GitHub for newer cores, at most once a day. Notifies once per new version.
    func checkForUpdates(force: Bool = false) {
        guard force || Date().timeIntervalSince(lastUpdateCheck) > 86_400 else { return }
        lastUpdateCheck = Date()
        Task {
            let xrayLatest = await UpdateChecker.latestTag("XTLS/Xray-core")
            let tpwsLatest = await UpdateChecker.latestTag("bol-van/zapret")
            await MainActor.run {
                self.xrayUpdate = newer(xrayLatest, than: self.xrayVersion)
                self.tpwsUpdate = newer(tpwsLatest, than: self.tpwsVersion)
                self.notifyUpdates()
            }
        }
    }

    private func newer(_ latest: String?, than installed: String?) -> String? {
        guard let latest, let installed, latest != installed else { return nil }
        return latest
    }

    private func notifyUpdates() {
        let defaults = UserDefaults.standard
        for (name, version) in [("Xray", xrayUpdate), ("tpws", tpwsUpdate)] {
            guard let version else { continue }
            let key = "notified-\(name)-\(version)"
            if !defaults.bool(forKey: key) {
                defaults.set(true, forKey: key)
                Notifier.post(title: "ProxyGate", body: String(localized: "\(name) update available: \(version)"))
            }
        }
    }

    // MARK: - VPN subscriptions

    var vpnBusy = false
    var vpnMessage: String?

    func configs(of sub: Subscription) -> [XrayConfigSummary] {
        sub.cachedJSON.map(XraySubscription.summaries) ?? []
    }

    /// Subscriptions whose servers are being latency-tested.
    var pinging: Set<UUID> = []

    /// Asks the engine to latency-test every server of a subscription (its probes bypass pf).
    func pingSubscription(_ id: UUID) {
        guard engineConnected, let sub = profile.subscriptions.first(where: { $0.id == id }),
              let json = sub.cachedJSON else { return }
        let endpoints = XraySubscription.serverEndpoints(json)
        guard !endpoints.isEmpty else { return }
        pinging.insert(id)
        client.send(.pingServers(subscription: id, targets: endpoints.map {
            PingTarget(index: $0.key, host: $0.value.host, port: $0.value.port)
        }))
    }

    private func applyLatencies(_ id: UUID, _ latencies: [Int: Int]) {
        pinging.remove(id)
        guard let i = profile.subscriptions.firstIndex(where: { $0.id == id }) else { return }
        var p = profile
        for (idx, ms) in latencies { p.subscriptions[i].latencies[idx] = ms }
        p.subscriptions[i].latencyCheckedAt = Date()
        profile = p
    }

    /// Latency to show for a config: measured ms, or nil for N/A / not yet tested.
    func latency(_ sub: Subscription, _ index: Int) -> Int? {
        sub.latencies[index].flatMap { $0 > 0 ? $0 : nil }
    }

    func setCollapsed(_ id: UUID, _ collapsed: Bool) {
        guard let i = profile.subscriptions.firstIndex(where: { $0.id == id }) else { return }
        profile.subscriptions[i].collapsed = collapsed
    }

    static let russianRuleTargets = "geosite:category-ru; geoip:ru; geosite:private; geoip:private"

    /// Whether the Russian/local-direct preset rule is present.
    var hasRussianRule: Bool { profile.rules.contains { $0.targetHosts == Self.russianRuleTargets } }

    /// Adds the Russian/local-direct preset rule (geosite/geoip matched by the engine).
    func addRussianDirectRule() { addPreset(hasRussianRule, Rule(name: String(localized: "Russian / local sites"),
                                                                 targetHosts: Self.russianRuleTargets, action: .direct)) }

    var hasDockerRule: Bool { profile.rules.contains { $0.name == "Docker" } }
    func addDockerRule() { addPreset(hasDockerRule, Rule(name: "Docker", applications: "Docker Desktop; com.docker.backend",
                                                         targetHosts: "*.docker.com; *.docker.io", action: .direct)) }

    private func addPreset(_ exists: Bool, _ rule: Rule) {
        guard !exists else { return }
        var p = profile
        p.rules.insert(rule, at: 0)
        profile = p
    }

    func addSubscription(name: String, url: String) {
        vpnBusy = true
        vpnMessage = String(localized: "Fetching subscription…")
        Task {
            do {
                let fetched = try await SubscriptionClient.fetch(url)
                await MainActor.run {
                    var sub = Subscription(name: name.isEmpty ? (fetched.name ?? "VPN") : name, url: url)
                    sub.cachedJSON = fetched.json
                    sub.userInfo = fetched.userInfo
                    sub.updatedAt = Date()
                    var p = self.profile
                    p.subscriptions.append(sub)
                    if p.activeSubscriptionID == nil { p.activeSubscriptionID = sub.id }
                    self.profile = p
                    self.vpnBusy = false
                    self.vpnMessage = nil
                    self.addLog("Subscription \"\(sub.name)\" added (\(self.configs(of: sub).count) configs)", .notice)
                    self.pushVPN()
                }
            } catch {
                await MainActor.run {
                    self.vpnBusy = false
                    self.vpnMessage = nil
                    self.alertMessage = String(localized: "Could not load the subscription: \(String(describing: error))")
                }
            }
        }
    }

    func refreshSubscription(_ id: UUID) {
        guard let sub = profile.subscriptions.first(where: { $0.id == id }) else { return }
        vpnBusy = true
        vpnMessage = String(localized: "Updating subscription…")
        Task {
            do {
                let fetched = try await SubscriptionClient.fetch(sub.url)
                await MainActor.run {
                    var p = self.profile
                    guard let i = p.subscriptions.firstIndex(where: { $0.id == id }) else { return }
                    p.subscriptions[i].cachedJSON = fetched.json
                    p.subscriptions[i].userInfo = fetched.userInfo
                    p.subscriptions[i].updatedAt = Date()
                    let count = XraySubscription.summaries(fetched.json).count
                    if p.subscriptions[i].selectedConfig >= count { p.subscriptions[i].selectedConfig = 0 }
                    if let fetchedName = fetched.name, !fetchedName.isEmpty { p.subscriptions[i].name = fetchedName }
                    self.profile = p
                    self.vpnBusy = false
                    self.vpnMessage = nil
                    if p.activeSubscriptionID == id { self.pushVPN() }
                }
            } catch {
                await MainActor.run {
                    self.vpnBusy = false
                    self.vpnMessage = nil
                    self.alertMessage = String(localized: "Could not update the subscription: \(String(describing: error))")
                }
            }
        }
    }

    /// Selects a config and makes its subscription the active VPN, then (re)starts the core.
    /// Switches to a server: re-applies the config (restarting the tunnel), makes the VPN the active
    /// bridge and (re)starts interception — so tapping a server connects to it, not just selects it.
    func selectVPNConfig(_ id: UUID, index: Int) {
        var p = profile
        guard let i = p.subscriptions.firstIndex(where: { $0.id == id }) else { return }
        p.subscriptions[i].selectedConfig = index
        p.activeSubscriptionID = id
        profile = p
        guard xrayVersion != nil else {
            alertMessage = String(localized: "Install the VPN core first (Settings → VPN core).")
            return
        }
        pushVPN()
        setActiveBridge(.vpn)
        remember(.vpn)
        wantRunning = true
        start()
        addLog("VPN switched to \"\(configs(of: p.subscriptions[i]).first { $0.index == index }?.name ?? "")\"", .notice)
    }

    func stopVPN() {
        profile.activeSubscriptionID = nil
        setXrayConfig(nil)
    }

    // MARK: - Bridges

    /// Egress that `.global` rules follow. Set by Connect/Disconnect and (later) by auto-switch.
    var activeBridge: Bridge = .direct

    func setActiveBridge(_ bridge: Bridge) {
        activeBridge = bridge
        client.send(.activeBridge(bridge))
    }

    /// Human description of the current route for the status header.
    var bridgeDescription: String {
        switch activeBridge {
        case .direct:
            return String(localized: "Global traffic goes direct")
        case .vpn:
            let name = profile.activeSubscription?.name ?? "VPN"
            return xrayRunning ? String(localized: "Global via VPN · \(name)") : String(localized: "VPN core starting…")
        case .proxy(let id):
            return String(localized: "Global via proxy \(profile.proxy(id)?.title ?? "")")
        }
    }

    /// Short suffix for the status line when DPI bypass is active.
    var bypassBadge: String? { bypassEnabled ? String(localized: "DPI bypass on") : nil }

    // MARK: - Auto-switch by interface

    @ObservationIgnored private let netWatcher = InterfaceWatcher()
    /// Per-network remembered choice (network key → bridge), so an ambiguous network isn't asked twice.
    @ObservationIgnored private var rememberedBridges: [String: Bridge] = [:]
    /// Pending "VPN or Proxy?" question for an ambiguous network.
    var bridgePrompt: BridgePrompt?

    struct BridgePrompt: Identifiable { let id = UUID(); let proxyID: UUID; let proxyTitle: String }

    /// Identifies the current network by the set of adapters that are up.
    private func networkKey() -> String {
        NetInterfaces.active().keys.sorted().joined(separator: ",")
    }

    private func loadRememberedBridges() {
        if let data = UserDefaults.standard.data(forKey: "rememberedBridges"),
           let map = try? JSONDecoder().decode([String: Bridge].self, from: data) {
            rememberedBridges = map
        }
    }

    private func remember(_ bridge: Bridge) {
        rememberedBridges[networkKey()] = bridge
        if let data = try? JSONEncoder().encode(rememberedBridges) {
            UserDefaults.standard.set(data, forKey: "rememberedBridges")
        }
    }

    /// A VPN bridge is available when a subscription is chosen, the core is installed, and the VPN's
    /// bound interface (if any) is up.
    private var vpnBridgeAvailable: Bool {
        guard xrayVersion != nil, (profile.activeSubscriptionID ?? profile.subscriptions.first?.id) != nil else { return false }
        guard let mac = profile.vpnInterfaceMAC else { return true }
        return NetInterfaces.active()[mac] != nil
    }

    /// The proxy that serves the proxy bridge right now (bound to an up interface), and whether wired.
    private func proxyBridgeCandidate() -> (proxy: ProxyServer, wired: Bool)? {
        let up = NetInterfaces.active()
        let interfaces = NetInterface.all()
        let candidates = profile.proxies.filter { $0.interfaceMAC.map { up[$0] != nil } ?? false }
        guard !candidates.isEmpty else { return nil }
        let chosen = candidates.first { $0.id == profile.activeProxyID } ?? candidates[0]
        let wired = chosen.interfaceMAC.flatMap { mac in interfaces.first { $0.mac == mac }?.wired } ?? false
        return (chosen, wired)
    }

    /// Re-evaluates which bridge should be active after a network change (debounced by the watcher).
    func networkChanged() {
        guard profile.autoSwitch, wantRunning else { return }
        let proxyCand = proxyBridgeCandidate()
        let vpnOK = vpnBridgeAvailable
        let key = networkKey()

        // A remembered, still-valid choice wins (no re-asking).
        if let remembered = rememberedBridges[key], valid(remembered) {
            apply(remembered)
            return
        }
        // Deterministic: a wired proxy (the work case) wins; else VPN; else any proxy; else direct.
        if let proxyCand, proxyCand.wired {
            apply(.proxy(proxyCand.proxy.id))
        } else if vpnOK, proxyCand != nil, profile.askOnUnknownNetwork {
            bridgePrompt = BridgePrompt(proxyID: proxyCand!.proxy.id, proxyTitle: proxyCand!.proxy.title)
        } else if vpnOK {
            apply(.vpn)
        } else if let proxyCand {
            apply(.proxy(proxyCand.proxy.id))
        } else {
            apply(.direct)
        }
    }

    /// Answer to the VPN/Proxy question; remembers the choice for this network.
    func answerBridgePrompt(useVPN: Bool) {
        guard let prompt = bridgePrompt else { return }
        let bridge: Bridge = useVPN ? .vpn : .proxy(prompt.proxyID)
        bridgePrompt = nil
        remember(bridge)
        apply(bridge)
    }

    private func valid(_ bridge: Bridge) -> Bool {
        switch bridge {
        case .direct: return true
        case .vpn: return vpnBridgeAvailable
        case .proxy(let id): return proxyBridgeCandidate()?.proxy.id == id
        }
    }

    /// Switches the active bridge and brings up what it needs (VPN core for `.vpn`).
    private func apply(_ bridge: Bridge) {
        if bridge == .vpn {
            if profile.activeSubscriptionID == nil { profile.activeSubscriptionID = profile.subscriptions.first?.id }
            pushVPN()
        }
        if case .proxy(let id) = bridge { profile.activeProxyID = id }
        setActiveBridge(bridge)
    }

    /// True when the VPN bridge is active and its core is up.
    var vpnConnected: Bool { activeBridge == .vpn && xrayRunning }

    /// Removes the old leaked "VPN (all traffic)" rule and the managed 127.0.0.1 proxy from a
    /// profile saved by an earlier build, and makes the default rule follow the active bridge.
    private func migrateLegacyVPN() {
        var p = profile
        var changed = false
        if p.rules.contains(where: { $0.name == "VPN (all traffic)" }) {
            p.rules.removeAll { $0.name == "VPN (all traffic)" }
            changed = true
        }
        if let vp = p.proxies.first(where: { $0.host == "127.0.0.1" && $0.port == PGConstants.vpnSocksPort }) {
            p.removeProxy(vp.id)
            changed = true
        }
        if let di = p.rules.lastIndex(where: { $0.isDefault }), p.rules[di].action != .global {
            p.rules[di].action = .global
            changed = true
        }
        if p.routeLocalDirect, !p.rules.contains(where: { $0.targetHosts == Self.russianRuleTargets }) {
            p.rules.insert(Rule(name: String(localized: "Russian / local sites"),
                                targetHosts: Self.russianRuleTargets, action: .direct), at: 0)
            p.routeLocalDirect = false
            changed = true
        }
        // Fold the old firewall-bypass LAN list + the separate Localhost rule into one locked rule.
        if p.advanced.bypassNetworks == "10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16" {
            p.advanced.bypassNetworks = ""
            changed = true
        }
        if !p.rules.contains(where: { $0.locked }) {
            p.rules.removeAll { !$0.isDefault && $0.name == "Localhost" && $0.action == .direct }
            p.rules.insert(Rule(name: String(localized: "Local networks — direct"),
                                targetHosts: "localhost; 127.0.0.1; ::1; %ComputerName%; 10.0.0.0/8; 172.16.0.0/12; 192.168.0.0/16",
                                action: .direct, locked: true), at: 0)
            changed = true
        }
        if changed { profile = p }
    }

    /// Makes the VPN the active bridge: runs the chosen server, routes `.global` rules to it and
    /// starts interception. The default rule is `.global`, so this is all it takes.
    func connectVPN() {
        guard xrayVersion != nil else {
            alertMessage = String(localized: "Install the VPN core first (Settings → VPN core).")
            return
        }
        if profile.activeSubscriptionID == nil {
            guard let first = profile.subscriptions.first?.id else {
                alertMessage = String(localized: "Add a subscription and pick a server first.")
                return
            }
            profile.activeSubscriptionID = first
        }
        pushVPN()
        setActiveBridge(.vpn)
        remember(.vpn)
        wantRunning = true
        start()
        addLog("VPN connected", .notice)
    }

    /// Drops back to direct and stops the core; leaves interception and rules as they are.
    func disconnectVPN() {
        setActiveBridge(.direct)
        stopVPN()
        addLog("VPN disconnected", .notice)
    }

    func toggleVPN() { vpnConnected ? disconnectVPN() : connectVPN() }

    // MARK: - Proxy bridge

    /// True when a proxy is the active bridge (the proxy "Connect" is on).
    var proxyConnected: Bool { if case .proxy = activeBridge { return true }; return false }

    /// The proxy the bridge is pointed at right now, when a proxy is connected.
    var connectedProxyID: UUID? { if case .proxy(let id) = activeBridge { return id }; return nil }

    /// The proxy the bridge would use: the chosen one if it still exists, else the first.
    private func bridgeProxyID() -> UUID? {
        if let id = profile.activeProxyID, profile.proxies.contains(where: { $0.id == id }) { return id }
        return profile.proxies.first?.id
    }

    /// Makes the chosen proxy the active bridge: routes `.global` rules through it and starts
    /// interception. Mirrors `connectVPN`.
    func connectProxy() {
        guard let id = bridgeProxyID() else {
            alertMessage = String(localized: "Add a proxy first.")
            return
        }
        profile.activeProxyID = id
        setActiveBridge(.proxy(id))
        remember(.proxy(id))
        wantRunning = true
        start()
        addLog("Proxy connected", .notice)
    }

    /// Drops back to direct; leaves interception and rules as they are.
    func disconnectProxy() {
        setActiveBridge(.direct)
        addLog("Proxy disconnected", .notice)
    }

    func toggleProxy() { proxyConnected ? disconnectProxy() : connectProxy() }

    /// Picks which proxy the bridge uses; switches on the spot if a proxy is already connected.
    func selectProxyBridge(_ id: UUID) {
        profile.activeProxyID = id
        guard proxyConnected else { return }
        setActiveBridge(.proxy(id))
        remember(.proxy(id))
    }

    func removeSubscription(_ id: UUID) {
        var p = profile
        p.removeSubscription(id)
        profile = p
        pushVPN()
    }

    var vpnActive: Bool { profile.activeSubscriptionID != nil }

    /// Sends the active subscription's chosen config to the core (nil stops it). Prompts to install
    /// the core if it is missing.
    func pushVPN() {
        let config = profile.activeVPNConfig()
        if config != nil, xrayVersion == nil {
            alertMessage = String(localized: "Install the VPN core first (Settings → VPN core).")
        }
        setXrayConfig(config)
    }

    func installHelper() {
        helperBusy = true
        Task.detached {
            let result = Result { try HelperInstaller.install() }
            await MainActor.run {
                self.helperBusy = false
                self.helperInstalled = HelperInstaller.isInstalled
                self.helperPinStale = HelperInstaller.needsReinstall
                switch result {
                case .success:
                    self.addLog("Helper installed", .notice)
                case .failure(let error):
                    if "\(error)" != "Cancelled" {
                        self.alertMessage = String(localized: "Helper installation failed: \(String(describing: error))")
                    }
                }
            }
        }
    }

    func uninstallHelper() {
        helperBusy = true
        Task.detached {
            let result = Result { try HelperInstaller.uninstall() }
            await MainActor.run {
                self.helperBusy = false
                self.helperInstalled = HelperInstaller.isInstalled
                if case .failure(let error) = result, "\(error)" != "Cancelled" {
                    self.alertMessage = String(localized: "Helper removal failed: \(String(describing: error))")
                } else {
                    self.addLog("Helper removed", .notice)
                }
            }
        }
    }

    private func engineConnectionChanged(_ connected: Bool) {
        engineConnected = connected
        helperInstalled = HelperInstaller.isInstalled
        helperPinStale = HelperInstaller.needsReinstall
        if connected {
            client.send(.hello(version: PGConstants.version))
            client.send(.config(profile))
            // Resume the VPN core without the install prompt (status hasn't arrived yet).
            client.send(.xrayConfig(profile.activeVPNConfig()))
            client.send(.activeBridge(activeBridge))
            if profile.bypassEnabled {
                sendDpiStrategy(strategyFlags(profile.bypassStrategyIndex))
                client.send(.bypassDirect(true))
            }
            if wantRunning {
                client.send(.start)
                // Re-pick the bridge for the current network (restores the remembered choice).
                DispatchQueue.main.async { [weak self] in self?.networkChanged() }
            }
        } else {
            if engineStatus?.running == true {
                addLog("Lost connection to the helper", .error)
            }
            engineStatus = nil
            connections.removeAll()
            for key in flows.keys {
                flows[key]?.active = 0
                flows[key]?.activeSince = nil
            }
            for key in appTraffic.keys {
                appTraffic[key]?.active = 0
            }
        }
    }

    // MARK: - Messages

    private func handle(_ messages: [EngineMessage]) {
        for message in messages {
            switch message {
            case .pingResults(let subscription, let latencies):
                applyLatencies(subscription, latencies)
            case .bypassTuned(let report):
                bypassTuned(report)
            case .tuneProgress(let progress):
                tuneProgress = progress
            case .dnsChecked(let report):
                dnsChecking = false
                dnsReport = report
            case .status(let status):
                let wasRunning = isRunning
                let prevXray = engineStatus?.xrayVersion
                let prevAC = engineStatus?.anyConnect
                engineStatus = status
                if prevAC?.phase != status.anyConnect.phase || prevAC?.routes != status.anyConnect.routes {
                    syncAnyConnectRules(status.anyConnect)
                    if let msg = status.anyConnect.message, status.anyConnect.phase == .error {
                        addLog("AnyConnect: \(msg)", .error)
                    }
                }
                if status.running != wasRunning {
                    addLog(status.running ? "Traffic redirection started (port \(status.listenPort))" : "Traffic redirection stopped", .notice)
                }
                if tpwsBusy, status.tpwsVersion != nil {
                    tpwsBusy = false; tpwsMessage = nil
                }
                if byedpiBusy, status.byedpiVersion != nil {
                    byedpiBusy = false; byedpiMessage = nil
                }
                if status.xrayVersion != nil || status.tpwsVersion != nil { checkForUpdates() }
                if status.tpwsVersion != nil || status.byedpiVersion != nil { autoTuneIfNeeded() }
                if xrayBusy, status.xrayVersion != nil {
                    xrayBusy = false
                    xrayMessage = nil
                    if status.xrayVersion != prevXray {
                        addLog("VPN core \(status.xrayVersion ?? "") installed", .notice)
                    }
                }
                if let error = status.error, !status.running, wantRunning {
                    wantRunning = false
                    alertMessage = String(localized: "Cannot start: \(error)")
                }
            case .opened(let info):
                opened(info)
            case .closed(let closed):
                self.closed(closed)
            case .failed(let failure):
                totalFailures += 1
                let host = hostOf(failure.info.target)
                hostStats[host, default: HostStat(id: host)].failures += 1
                // Compact mode: one line per app + target per minute, not one per retry.
                if logMode != .compact || shouldLogOpen("err|\(failure.info.app.name)|\(failure.info.target)") {
                    addLog("\(failure.info.app.name) - \(failure.info.target) error : \(failure.error)", .error)
                }
            case .blocked(let info):
                totalBlocked += 1
                ruleHits[info.rule, default: RuleHits()].count += 1
                ruleHits[info.rule]?.last = Date()
                if shouldLogOpen(flowKey(info)) {
                    addLog("\(info.app.name) - \(info.target) matching \(info.rule) rule : blocked", .blocked)
                }
            case .stats(let items):
                for item in items {
                    updateBytes(item.id, sent: item.sent, received: item.received)
                }
                downRate = Double(pendingDown) / PGConstants.statsInterval
                upRate = Double(pendingUp) / PGConstants.statsInterval
                pendingDown = 0
                pendingUp = 0
                for key in appTraffic.keys {
                    guard var t = appTraffic[key] else { continue }
                    t.downRate = Double(t.pendingDown) / PGConstants.statsInterval
                    t.upRate = Double(t.pendingUp) / PGConstants.statsInterval
                    t.pendingDown = 0
                    t.pendingUp = 0
                    appTraffic[key] = t
                }
            case .log(let entry):
                addLog(entry.text, entry.level == .error ? .error : .notice)
            }
        }
    }

    private func flowKey(_ info: ConnInfo) -> String {
        "\(info.app.display)|\(info.target)"
    }

    private func opened(_ info: ConnInfo) {
        let started = Date(timeIntervalSince1970: info.time)
        let key = flowKey(info)
        let rule = "\(info.rule) : \(info.route)"
        connections[info.id] = ConnectionItem(id: info.id, flowID: key, started: started)
        totalConnections += 1

        let host = hostOf(info.target)
        var flow = flows[key] ?? Flow(
            id: key, app: info.app.display, appName: info.app.name,
            appGroup: info.app.bundleNames.first ?? info.app.name,
            category: AppCategory.of(info.app),
            target: info.target, host: host, domain: Patterns.baseDomain(host),
            rule: rule, kind: info.kind, lastActivity: started)
        flow.rule = rule
        flow.kind = info.kind
        flow.active += 1
        flow.total += 1
        flow.lastActivity = started
        if flow.activeSince == nil {
            flow.activeSince = started
        }
        flows[key] = flow
        seenApps.insert(flow.appGroup)
        ruleHits[info.rule, default: RuleHits()].count += 1
        ruleHits[info.rule]?.last = started
        detectLoop(key: key, app: flow.appGroup, target: info.target)
        seenApps.insert(flow.appName)

        var traffic = appTraffic[flow.appGroup] ?? AppTraffic(id: flow.appGroup, category: flow.category)
        traffic.active += 1
        traffic.total += 1
        appTraffic[flow.appGroup] = traffic

        var stat = hostStats[host] ?? HostStat(id: host)
        stat.apps.insert(flow.appGroup)
        stat.connections += 1
        stat.route = rule
        stat.lastSeen = started
        hostStats[host] = stat

        guard shouldLogOpen(key) else { return }
        switch info.kind {
        case .direct:
            addLog("\(info.app.name) - \(info.target) matching \(info.rule) rule : direct connection", .normal)
        case .proxy:
            addLog("\(info.app.name) - \(info.target) open through proxy \(info.route)", .normal)
        case .chain:
            addLog("\(info.app.name) - \(info.target) open through proxy chain \(info.route)", .normal)
        case .block:
            break
        }
    }

    private func closed(_ c: ConnClosed) {
        updateBytes(c.id, sent: c.sent, received: c.received)
        guard let item = connections.removeValue(forKey: c.id), var flow = flows[item.flowID] else { return }
        let end = Date(timeIntervalSince1970: c.time)
        flow.active = max(0, flow.active - 1)
        if flow.active == 0 {
            flow.activeSince = nil
        }
        flow.lastActivity = end
        flows[item.flowID] = flow
        appTraffic[flow.appGroup]?.active -= 1
        if logMode == .all {
            addLog("\(flow.appName) - \(flow.target) close, \(ByteFormat.log(c.sent)) sent, \(ByteFormat.log(c.received)) received, lifetime \(ByteFormat.duration(end.timeIntervalSince(item.started)))", .normal)
        }
    }

    private func updateBytes(_ id: UInt64, sent: UInt64, received: UInt64) {
        guard var item = connections[id], sent >= item.sent, received >= item.received else { return }
        let dSent = sent - item.sent, dReceived = received - item.received
        guard dSent + dReceived > 0 else { return }
        item.sent = sent
        item.received = received
        connections[id] = item
        pendingUp += dSent
        pendingDown += dReceived
        totalSent += dSent
        totalReceived += dReceived
        guard var flow = flows[item.flowID] else { return }
        flow.sent += dSent
        flow.received += dReceived
        flow.lastActivity = now
        flows[item.flowID] = flow
        if var t = appTraffic[flow.appGroup] {
            t.sent += dSent
            t.received += dReceived
            t.pendingUp += dSent
            t.pendingDown += dReceived
            appTraffic[flow.appGroup] = t
        }
        hostStats[flow.host]?.sent += dSent
        hostStats[flow.host]?.received += dReceived
    }

    private func hostOf(_ target: String) -> String {
        guard let colon = target.lastIndex(of: ":") else { return target }
        let host = String(target[..<colon])
        return host.hasPrefix("[") ? String(host.dropFirst().dropLast()) : host
    }

    private func tick() {
        now = Date()
        let cutoff = now.addingTimeInterval(-idleRetention)
        flows = flows.filter { $0.value.active > 0 || $0.value.lastActivity >= cutoff }
        lastLoggedOpen = lastLoggedOpen.filter { now.timeIntervalSince($0.value) < 60 }
        // Bounded memory: keep the 1000 most recent hosts in statistics.
        if hostStats.count > 1200 {
            let keep = Set(hostStats.values.sorted { $0.lastSeen > $1.lastSeen }.prefix(1000).map(\.id))
            hostStats = hostStats.filter { keep.contains($0.key) }
        }
        if appTraffic.count > 500 {
            appTraffic = appTraffic.filter { $0.value.active > 0 || $0.value.received + $0.value.sent > 0 }
        }
        if !engineConnected {
            helperInstalled = HelperInstaller.isInstalled
            helperPinStale = HelperInstaller.needsReinstall
        }
        autoPing()
    }

    /// Re-pings a subscription's servers once its interval has elapsed.
    private func autoPing() {
        guard engineConnected, profile.pingInterval > 0 else { return }
        let interval = TimeInterval(profile.pingInterval * 60)
        for sub in profile.subscriptions where !pinging.contains(sub.id) {
            if sub.cachedJSON != nil, now.timeIntervalSince(sub.latencyCheckedAt ?? .distantPast) >= interval {
                pingSubscription(sub.id)
            }
        }
    }

    // MARK: - Loop detection

    private func detectLoop(key: String, app: String, target: String) {
        guard loopDetection, !loopDismissed.contains(app), loopAlert == nil else { return }
        let cutoff = now.addingTimeInterval(-10)
        var times = (openTimes[key] ?? []).filter { $0 >= cutoff }
        times.append(Date())
        openTimes[key] = times
        if times.count >= loopThreshold {
            openTimes[key] = nil
            loopAlert = LoopAlert(app: app, target: target, count: times.count)
            addLog("Possible connection loop: \(app) opened \(times.count) connections to \(target) in 10 s", .error)
        }
    }

    /// "Yes" in the loop dialog: route the app directly, ahead of every other rule.
    func excludeFromProcessing(_ alert: LoopAlert) {
        var p = profile
        p.rules.insert(Rule(name: String(localized: "\(alert.app) (loop)"), applications: Patterns.join([alert.app]), action: .direct), at: 0)
        profile = p
        loopAlert = nil
        loopDismissed.insert(alert.app)
    }

    func ignoreLoop(_ alert: LoopAlert) {
        loopAlert = nil
        loopDismissed.insert(alert.app)
    }

    // MARK: - Proxies

    func checkProxy(_ proxy: ProxyServer) {
        checkingProxies.insert(proxy.id)
        Task.detached {
            let started = Date()
            let status: ProxyStatus
            do {
                _ = try ProxyClient.check(proxy)
                status = ProxyStatus(ok: true, text: String(localized: "Working"), latencyMs: Int(Date().timeIntervalSince(started) * 1000))
            } catch {
                status = ProxyStatus(ok: false, text: String(describing: error), latencyMs: nil)
            }
            await MainActor.run {
                self.proxyStatus[proxy.id] = status
                self.checkingProxies.remove(proxy.id)
            }
        }
    }

    /// Bytes that went through a proxy this session (by the route text of flows).
    func traffic(through proxy: ProxyServer) -> UInt64 {
        flows.values.filter { $0.rule.hasSuffix(proxy.title) }.reduce(0) { $0 + $1.sent + $1.received }
    }

    /// Which rule a connection would hit — the route tester on the Rules page.
    func testRoute(app: String, target: String) -> Rule? {
        let trimmed = target.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        var host = trimmed
        var port: UInt16 = 443
        if let colon = trimmed.lastIndex(of: ":"), let p = UInt16(trimmed[trimmed.index(after: colon)...]), !trimmed.hasSuffix("]") || trimmed.hasPrefix("[") {
            host = String(trimmed[..<colon])
            port = p
        }
        host = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]")).lowercased()
        var identity = AppIdentity(pid: 1, name: app.isEmpty ? "unknown" : app)
        identity.bundleNames = app.isEmpty ? [] : [app]
        let ip = IPAddr(host)
        return RuleSet(profile: profile).match(MatchRequest(
            app: identity, hostname: ip == nil ? host : nil, ip: ip ?? IPAddr("0.0.0.0")!, port: port),
            unavailable: profile.unavailableRoutes(active: NetInterfaces.active()))
    }

    // MARK: - Log

    /// In compact mode a flow's "open" is logged at most once a minute.
    private func shouldLogOpen(_ key: String) -> Bool {
        switch logMode {
        case .all:
            return true
        case .errors:
            return false
        case .compact:
            if let last = lastLoggedOpen[key], now.timeIntervalSince(last) < 60 { return false }
            lastLoggedOpen[key] = now
            return true
        }
    }

    func addLog(_ text: String, _ kind: LogLine.Kind) {
        logCounter += 1
        log.append(LogLine(id: logCounter, time: Date(), text: text, kind: kind))
        if log.count > 2000 {
            log.removeFirst(500)
        }
    }

    func formatted(_ line: LogLine) -> String {
        "[\(Self.timeFormatter.string(from: line.time))] \(line.text)"
    }

    func clearLog() {
        log.removeAll()
    }

    func resetStatistics() {
        hostStats.removeAll()
        appTraffic = appTraffic.filter { $0.value.active > 0 }.mapValues {
            var t = $0
            t.total = t.active
            t.sent = 0
            t.received = 0
            return t
        }
        totalSent = 0
        totalReceived = 0
        totalConnections = 0
        totalFailures = 0
        totalBlocked = 0
        sessionStart = Date()
    }

    // MARK: - Helpers for views

    var activeConnectionCount: Int { connections.count }

    /// Recently seen hosts, newest first (rule editor suggestions).
    var recentHosts: [String] {
        hostStats.values.sorted { $0.lastSeen > $1.lastSeen }.map(\.id)
    }

    func createRule(application: String) {
        ruleDraft = Rule(name: application, applications: Patterns.join([application]), action: .direct)
        section = .rules
    }

    func createRule(domain: String) {
        // "*.example.com" also covers example.com itself.
        let hosts = IPAddr(domain) != nil ? domain : "*.\(domain)"
        ruleDraft = Rule(name: domain, targetHosts: hosts, action: .direct)
        section = .rules
    }
}

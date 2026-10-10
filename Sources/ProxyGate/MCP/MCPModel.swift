import Foundation
import PGCore

/// MCP glue on the app model: token storage, server lifecycle, the tool catalogue and the dispatch
/// that reads and edits rules. Everything here runs on the main actor, since it touches the model.
@MainActor
extension AppModel {
    // MARK: - Token and lifecycle

    static let mcpKeychainAccount = "mcp-token"

    static func loadOrCreateMCPToken() -> String {
        if let t = Keychain.read(account: mcpKeychainAccount), !t.isEmpty { return t }
        let t = MCPServer.newToken()
        Keychain.save(t, account: mcpKeychainAccount)
        return t
    }

    func regenerateMCPToken() {
        mcpToken = MCPServer.newToken()
        Keychain.save(mcpToken, account: Self.mcpKeychainAccount)
        if mcpEnabled { applyMCP() }   // rebind so the old token stops working
        addLog("MCP token regenerated", .notice)
    }

    /// Starts, stops or rebinds the server to match the current settings.
    func applyMCP() {
        mcpServer?.stop()
        mcpServer = nil
        guard mcpEnabled else { return }
        let server = MCPServer(model: self, port: UInt16(clamping: mcpPort), token: mcpToken)
        do {
            try server.start()
            mcpServer = server
            addLog("MCP server listening on 127.0.0.1:\(mcpPort)", .notice)
        } catch {
            mcpServer = nil
            alertMessage = String(localized: "Could not start the MCP server on port \(mcpPort): \(String(describing: error))")
        }
    }

    var mcpRunning: Bool { mcpServer?.isRunning ?? false }
    var mcpActive: Bool { mcpLastSeen != nil }
    var mcpURL: String { "http://127.0.0.1:\(mcpPort)/mcp" }

    /// Called by the server (on the main actor) the first time a request authenticates.
    func mcpAgentSeen() {
        if mcpLastSeen == nil { addLog("MCP: an agent connected", .notice) }
        mcpLastSeen = Date()
    }

    // MARK: - initialize instructions

    /// The hint the server returns in `initialize`, so the agent knows what it can do here.
    /// `nonisolated` so `MCPServer.dispatch` can read it off the main actor; it is an immutable
    /// String and touches no AppModel state.
    nonisolated static let mcpInstructions = """
    ProxyGate routes each app's TCP connection by an ordered rule list: first enabled match wins, \
    the last rule is the catch-all Default. Use these tools to read and edit the rules and to \
    inspect the live log and stats.

    ACTIONS a rule can take: direct, block, global (follow the active VPN/proxy bridge), vpn \
    (always the VPN), dpi (direct but through the DPI-bypass core), proxy:<id-or-name>, \
    chain:<id-or-name>. Call list_targets for proxy/chain ids and to see what is available.

    A rule matches on applications, targetHosts and targetPorts. Each is a ';'-separated list; \
    empty (or 'any') matches anything. A list is OR: the rule matches if ANY entry matches. The \
    SAME target grammar works for every action, so a geosite/range/CIDR target is valid whether \
    the rule goes direct, to a proxy or to the VPN.

    targetHosts entries, mix freely:
    - hostname, wildcards '*' and '?': 'discord.com', '*.discord.com' (also covers the bare \
      'discord.com'), 'api-?.example.org'
    - IP: '192.0.2.10' or IPv6
    - IP mask with '*': '10.*', '10.10.*.*'
    - IP range (inclusive, same family): '10.10.10.10-10.11.11.11'
    - CIDR: '10.0.0.0/8', '2001:db8::/32'
    - geosite:<category> matched by hostname: 'geosite:google', 'geosite:category-ads-all', \
      'geosite:category-ru'
    - geoip:<country> matched by IP: 'geoip:cn', 'geoip:ru', 'geoip:private'
    - specials: 'localhost', '%ComputerName%'
    geosite/geoip need the geo databases, which ship with the VPN core; list_targets.geoAvailable \
    tells you if they are present. The 'name@attribute' geosite form is not supported, use the full \
    category. targetPorts entries are a port or a 'lo-hi' range, e.g. '443; 8000-9000'. applications \
    entries are process names, .app names, bundle ids or paths, with '*'/'?'.

    Examples. Block ads: add_rule name='Ads' targetHosts='geosite:category-ads-all' action='block'. \
    Discord only over the VPN: add_rule name='Discord' targetHosts='*.discord.com; *.discord.gg; \
    *.discordapp.com' action='vpn'. A blocked site via DPI bypass: action='dpi'. A corporate subnet \
    via a proxy: targetHosts='10.0.0.0/8' action='proxy:<id>'. New rules go just above Default; \
    reorder with move_rule since earlier rules win.

    DPI rules (action='dpi') take two optional fields. dpiEngine: 'tpws' or 'byedpi' picks the \
    bypass core for that rule; omit it (or pass '') to use the primary core. If the chosen core is \
    not running, another running core is used; with none, the rule goes plain direct. testHosts: \
    ';'-separated host names the DPI auto-tune probes for this rule, e.g. 'www.youtube.com'; empty \
    means they are taken from targetHosts (geosite/geoip, IPs and ranges are skipped, '*.x.com' \
    becomes 'x.com'). Rules with other actions ignore both fields.
    """

    // MARK: - Tool catalogue

    func mcpTools() -> [[String: Any]] {
        func schema(_ props: [String: Any], required: [String] = []) -> [String: Any] {
            ["type": "object", "properties": props, "required": required]
        }
        let actionDesc = "One of: direct, block, global, vpn, dpi, proxy:<id-or-name>, chain:<id-or-name>."
        let hostsDesc = "';'-separated, OR-matched. Each entry: hostname or wildcard ('*.site.com'), "
            + "IP, IP mask ('10.*'), range ('10.0.0.0-10.0.1.255'), CIDR ('10.0.0.0/8'), "
            + "geosite:<category>, geoip:<country>, 'localhost', '%ComputerName%'. Empty = any."
        let hostsField: [String: Any] = ["type": "string", "description": hostsDesc]
        let dpiEngineField: [String: Any] = ["type": "string", "enum": ["tpws", "byedpi", ""],
                                             "description": "Only for action 'dpi': the bypass core for this rule. Empty or omitted = the primary core."]
        let testHostsField: [String: Any] = ["type": "string",
                                             "description": "Only for action 'dpi': ';'-separated host names the auto-tune probes for this rule. Empty = taken from targetHosts."]
        let str: [String: Any] = ["type": "string"]
        return [
            ["name": "list_rules",
             "description": "List all routing rules in order, with their id, match fields and action.",
             "inputSchema": schema([:])],
            ["name": "list_targets",
             "description": "List proxies and chains (with ids) and the symbolic actions available, so you can build a rule action.",
             "inputSchema": schema([:])],
            ["name": "add_rule",
             "description": "Add a rule above the Default rule.",
             "inputSchema": schema([
                "name": ["type": "string", "description": "Rule name."],
                "action": ["type": "string", "description": actionDesc],
                "applications": ["type": "string", "description": "';'-separated app names/paths/bundle ids, with '*'/'?'. Empty = any."],
                "targetHosts": hostsField,
                "targetPorts": ["type": "string", "description": "';'-separated ports or 'lo-hi' ranges, e.g. '443; 8000-9000'. Empty = any."],
                "dpiEngine": dpiEngineField,
                "testHosts": testHostsField,
                "position": ["type": "string", "description": "'top', 'bottom' (default, just above Default), or a 0-based index."],
             ], required: ["name", "action"])],
            ["name": "update_rule",
             "description": "Change fields of a rule by id or index. Only the given fields change.",
             "inputSchema": schema([
                "id": ["type": "string", "description": "Rule id (uuid) or its 0-based index."],
                "name": str, "action": ["type": "string", "description": actionDesc],
                "applications": str, "targetHosts": hostsField, "targetPorts": str,
                "dpiEngine": dpiEngineField, "testHosts": testHostsField,
                "enabled": ["type": "boolean"],
             ], required: ["id"])],
            ["name": "delete_rule",
             "description": "Delete a rule by id or index. The Default and locked rules cannot be deleted.",
             "inputSchema": schema(["id": ["type": "string", "description": "Rule id (uuid) or its 0-based index."]], required: ["id"])],
            ["name": "move_rule",
             "description": "Reorder a rule. Earlier rules win.",
             "inputSchema": schema([
                "id": ["type": "string", "description": "Rule id (uuid) or its 0-based index."],
                "position": ["type": "string", "description": "'top', 'bottom', or a 0-based index."],
             ], required: ["id", "position"])],
            ["name": "get_log",
             "description": "Recent journal entries, newest last.",
             "inputSchema": schema([
                "limit": ["type": "integer", "description": "How many entries (default 50, max 500)."],
                "errors_only": ["type": "boolean"],
             ])],
            ["name": "get_stats",
             "description": "Session traffic stats and the busiest hosts and apps.",
             "inputSchema": schema([:])],
            ["name": "get_status",
             "description": "Whether redirection is on, the active bridge, and VPN/DPI/AnyConnect state.",
             "inputSchema": schema([:])],
        ]
    }

    // MARK: - Dispatch

    /// Runs a tool and returns (text, isError). `args` is the raw JSON `arguments` object.
    func mcpCall(_ name: String, _ args: [String: Any]) -> (text: String, isError: Bool) {
        switch name {
        case "list_rules": return ok(mcpRulesPayload())
        case "list_targets": return ok(mcpTargetsPayload())
        case "add_rule": return mcpAddRule(args)
        case "update_rule": return mcpUpdateRule(args)
        case "delete_rule": return mcpDeleteRule(args)
        case "move_rule": return mcpMoveRule(args)
        case "get_log": return ok(mcpLogPayload(args))
        case "get_stats": return ok(mcpStatsPayload())
        case "get_status": return ok(mcpStatusPayload())
        default: return ("Unknown tool: \(name)", true)
        }
    }

    // MARK: - Read payloads

    private func mcpRulesPayload() -> [String: Any] {
        ["rules": profile.rules.enumerated().map { mcpRuleJSON($0.element, index: $0.offset) }]
    }

    private func mcpRuleJSON(_ r: Rule, index: Int) -> [String: Any] {
        var json: [String: Any] = [
            "index": index, "id": r.id.uuidString, "name": r.name, "enabled": r.enabled,
            "applications": r.applications, "targetHosts": r.targetHosts, "targetPorts": r.targetPorts,
            "action": mcpActionString(r.action), "actionLabel": profile.describe(r.action),
            "default": r.isDefault, "locked": r.locked, "dynamic": r.dynamic,
        ]
        if r.action == .directDPI {
            if let e = r.dpiEngine { json["dpiEngine"] = e.rawValue }
            json["testHosts"] = r.testHosts
        }
        return json
    }

    private func mcpTargetsPayload() -> [String: Any] {
        [
            "proxies": profile.proxies.map { ["id": $0.id.uuidString, "name": $0.title, "type": $0.type.rawValue, "endpoint": $0.endpoint] },
            "chains": profile.chains.map { ["id": $0.id.uuidString, "name": $0.name] },
            "symbolicActions": ["direct", "block", "global", "vpn", "dpi"],
            "vpnAvailable": xrayVersion != nil && !profile.subscriptions.isEmpty,
            "dpiAvailable": anyDPICoreInstalled,
            "dpiEngines": installedDPIEngines.map(\.rawValue),
            "primaryDpiEngine": primaryDPIEngine.rawValue,
            "geoAvailable": xrayVersion != nil,   // geosite.dat/geoip.dat ship with the VPN core
        ]
    }

    private func mcpLogPayload(_ args: [String: Any]) -> [String: Any] {
        let limit = max(1, min(500, (args["limit"] as? Int) ?? 50))
        let errorsOnly = (args["errors_only"] as? Bool) ?? false
        let iso = ISO8601DateFormatter()
        let entries = log.filter { !errorsOnly || $0.kind == .error }.suffix(limit).map {
            ["time": iso.string(from: $0.time), "kind": "\($0.kind)", "text": $0.text]
        }
        return ["entries": Array(entries)]
    }

    private func mcpStatsPayload() -> [String: Any] {
        let topHosts = hostStats.values.sorted { $0.connections > $1.connections }.prefix(10).map {
            ["host": $0.id, "connections": $0.connections, "failures": $0.failures,
             "sent": Int($0.sent), "received": Int($0.received), "route": $0.route]
        }
        let topApps = appTraffic.values.sorted { ($0.sent + $0.received) > ($1.sent + $1.received) }.prefix(10).map {
            ["app": $0.id, "active": $0.active, "total": $0.total, "sent": Int($0.sent), "received": Int($0.received)]
        }
        return [
            "uptimeSeconds": Int(Date().timeIntervalSince(sessionStart)),
            "activeConnections": activeConnectionCount,
            "totalConnections": totalConnections, "totalFailures": totalFailures, "totalBlocked": totalBlocked,
            "totalSent": Int(totalSent), "totalReceived": Int(totalReceived),
            "downRateBytesPerSec": Int(downRate), "upRateBytesPerSec": Int(upRate),
            "topHosts": Array(topHosts), "topApps": Array(topApps),
        ]
    }

    private func mcpStatusPayload() -> [String: Any] {
        [
            "redirectionOn": isRunning, "engineConnected": engineConnected, "helperInstalled": helperInstalled,
            "activeBridge": bridgeDescription,
            "vpnConnected": vpnConnected, "proxyConnected": proxyConnected,
            "dpiBypassOn": bypassEnabled, "dpiCoreRunning": anyDPICoreRunning,
            "anyConnectUp": anyConnectUp,
        ]
    }

    // MARK: - Write tools

    private func mcpAddRule(_ args: [String: Any]) -> (String, Bool) {
        guard let name = (args["name"] as? String)?.trimmingCharacters(in: .whitespaces), !name.isEmpty else {
            return ("name is required", true)
        }
        guard let actionStr = args["action"] as? String, let action = mcpParseAction(actionStr) else {
            return ("invalid or missing action (call list_targets for valid ids)", true)
        }
        var dpiEngine: DPIEngine?
        if let raw = args["dpiEngine"] {
            let parsed = mcpParseDPIEngine(raw)
            guard parsed.valid else { return ("invalid dpiEngine (use 'tpws', 'byedpi' or '')", true) }
            dpiEngine = parsed.engine
        }
        var p = profile
        let rule = Rule(name: name,
                        applications: (args["applications"] as? String) ?? "",
                        targetHosts: (args["targetHosts"] as? String) ?? "",
                        targetPorts: (args["targetPorts"] as? String) ?? "",
                        action: action,
                        dpiEngine: dpiEngine,
                        testHosts: (args["testHosts"] as? String) ?? "")
        let at = mcpInsertionIndex(in: p, position: args["position"])
        p.rules.insert(rule, at: at)
        profile = p
        return ok(["added": mcpRuleJSON(rule, index: profile.rules.firstIndex { $0.id == rule.id } ?? at)])
    }

    private func mcpUpdateRule(_ args: [String: Any]) -> (String, Bool) {
        var p = profile
        guard let idx = mcpRuleIndex(args["id"], in: p) else { return ("rule not found", true) }
        if p.rules[idx].locked || p.rules[idx].dynamic { return ("this rule is locked and cannot be changed", true) }
        if let v = args["name"] as? String { p.rules[idx].name = v }
        if let v = args["applications"] as? String { p.rules[idx].applications = v }
        if let v = args["targetHosts"] as? String { p.rules[idx].targetHosts = v }
        if let v = args["targetPorts"] as? String { p.rules[idx].targetPorts = v }
        if let v = args["enabled"] as? Bool, !p.rules[idx].isDefault { p.rules[idx].enabled = v }
        if let v = args["testHosts"] as? String { p.rules[idx].testHosts = v }
        if let raw = args["dpiEngine"] {
            let parsed = mcpParseDPIEngine(raw)
            guard parsed.valid else { return ("invalid dpiEngine (use 'tpws', 'byedpi' or '')", true) }
            p.rules[idx].dpiEngine = parsed.engine
        }
        if let s = args["action"] as? String {
            guard let a = mcpParseAction(s) else { return ("invalid action", true) }
            p.rules[idx].action = a
        }
        let updated = p.rules[idx]
        profile = p
        return ok(["updated": mcpRuleJSON(updated, index: profile.rules.firstIndex { $0.id == updated.id } ?? idx)])
    }

    private func mcpDeleteRule(_ args: [String: Any]) -> (String, Bool) {
        var p = profile
        guard let idx = mcpRuleIndex(args["id"], in: p) else { return ("rule not found", true) }
        let r = p.rules[idx]
        if r.isDefault || r.locked || r.dynamic { return ("the Default and locked rules cannot be deleted", true) }
        p.rules.remove(at: idx)
        profile = p
        return ok(["deleted": r.id.uuidString, "name": r.name])
    }

    private func mcpMoveRule(_ args: [String: Any]) -> (String, Bool) {
        var p = profile
        guard let idx = mcpRuleIndex(args["id"], in: p) else { return ("rule not found", true) }
        let r = p.rules[idx]
        if r.isDefault || r.locked || r.dynamic { return ("this rule cannot be moved", true) }
        p.rules.remove(at: idx)
        let at = mcpInsertionIndex(in: p, position: args["position"])
        p.rules.insert(r, at: at)
        profile = p
        return ok(["moved": r.id.uuidString, "toIndex": profile.rules.firstIndex { $0.id == r.id } ?? at])
    }

    // MARK: - Helpers

    private func ok(_ obj: [String: Any]) -> (String, Bool) { (mcpJSON(obj), false) }

    private func mcpJSON(_ obj: Any) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
              let s = String(data: data, encoding: .utf8) else { return "{}" }
        return s
    }

    /// Resolves a rule reference that is either a uuid string or a 0-based index.
    private func mcpRuleIndex(_ ref: Any?, in p: Profile) -> Int? {
        if let s = ref as? String {
            if let uuid = UUID(uuidString: s) { return p.rules.firstIndex { $0.id == uuid } }
            if let n = Int(s), p.rules.indices.contains(n) { return n }
        }
        if let n = ref as? Int, p.rules.indices.contains(n) { return n }
        return nil
    }

    /// Where a new/moved rule should land: above Default and below any leading locked rules.
    private func mcpInsertionIndex(in p: Profile, position: Any?) -> Int {
        let lastEditable = p.rules.firstIndex { $0.isDefault } ?? p.rules.count
        let firstEditable = p.rules.firstIndex { !$0.locked } ?? 0
        if let s = position as? String {
            if s == "top" { return firstEditable }
            if s == "bottom" { return lastEditable }
            if let n = Int(s) { return max(firstEditable, min(n, lastEditable)) }
        }
        if let n = position as? Int { return max(firstEditable, min(n, lastEditable)) }
        return lastEditable
    }

    /// Machine form of an action (the string tools accept and return).
    private func mcpActionString(_ a: RuleAction) -> String {
        switch a {
        case .direct: return "direct"
        case .block: return "block"
        case .global: return "global"
        case .vpn: return "vpn"
        case .directDPI: return "dpi"
        case .proxy(let id): return "proxy:\(id.uuidString)"
        case .chain(let id): return "chain:\(id.uuidString)"
        }
    }

    /// Parses an action string: a symbolic word, or "proxy:"/"chain:" with a uuid or a name.
    private func mcpParseAction(_ raw: String) -> RuleAction? {
        let s = raw.trimmingCharacters(in: .whitespaces)
        switch s.lowercased() {
        case "direct": return .direct
        case "block": return .block
        case "global": return .global
        case "vpn": return .vpn
        case "dpi", "directdpi", "direct+dpi", "direct + dpi": return .directDPI
        default: break
        }
        if let v = dropPrefix(s, "proxy:") {
            if let id = UUID(uuidString: v), profile.proxy(id) != nil { return .proxy(id) }
            if let p = profile.proxies.first(where: { $0.title.caseInsensitiveCompare(v) == .orderedSame || $0.endpoint.caseInsensitiveCompare(v) == .orderedSame }) { return .proxy(p.id) }
        }
        if let v = dropPrefix(s, "chain:") {
            if let id = UUID(uuidString: v), profile.chain(id) != nil { return .chain(id) }
            if let c = profile.chains.first(where: { $0.name.caseInsensitiveCompare(v) == .orderedSame }) { return .chain(c.id) }
        }
        return nil
    }

    /// "tpws" / "byedpi" pick a core; "", "primary" or null mean the primary core (engine nil).
    /// `valid` is false for anything else.
    private func mcpParseDPIEngine(_ raw: Any) -> (valid: Bool, engine: DPIEngine?) {
        if raw is NSNull { return (true, nil) }
        guard let s = (raw as? String)?.trimmingCharacters(in: .whitespaces).lowercased() else { return (false, nil) }
        if s.isEmpty || s == "primary" { return (true, nil) }
        guard let e = DPIEngine(rawValue: s) else { return (false, nil) }
        return (true, e)
    }

    private func dropPrefix(_ s: String, _ prefix: String) -> String? {
        guard s.lowercased().hasPrefix(prefix) else { return nil }
        return String(s.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
    }
}

import Foundation
import Network
import PGCore

/// A tiny localhost HTTP server that speaks the MCP Streamable HTTP transport (JSON-RPC over HTTP
/// POST, a single JSON response per request, no SSE). It binds to 127.0.0.1 only, requires a Bearer
/// token, and rejects cross-origin requests, so only a local agent holding the token can drive it.
/// All model access hops to the main actor, where the rules live.
final class MCPServer: @unchecked Sendable {
    static let defaultPort = 18766
    static let protocolVersion = "2025-06-18"

    /// A URL-safe random token (32 bytes, hex).
    static func newToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        var rng = SystemRandomNumberGenerator()
        for i in bytes.indices { bytes[i] = UInt8.random(in: .min ... .max, using: &rng) }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    private weak var model: AppModel?
    private let port: UInt16
    private let token: String
    private let sessionID = UUID().uuidString
    private let queue = DispatchQueue(label: "proxygate.mcp")
    private var listener: NWListener?
    private var ready = false

    init(model: AppModel, port: UInt16, token: String) {
        self.model = model
        self.port = port
        self.token = token
    }

    var isRunning: Bool { ready }

    func start() throws {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(rawValue: port) ?? 18766)
        params.allowLocalEndpointReuse = true
        let listener = try NWListener(using: params)
        listener.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.ready = true
            case .failed(let error):
                self?.ready = false
                self?.onFailure("\(error)")
            case .cancelled: self?.ready = false
            default: break
            }
        }
        listener.newConnectionHandler = { [weak self] conn in self?.accept(conn) }
        listener.start(queue: queue)
        self.listener = listener
    }

    func stop() {
        listener?.cancel()
        listener = nil
        ready = false
    }

    private func onFailure(_ message: String) {
        DispatchQueue.main.async { [weak model] in
            MainActor.assumeIsolated {
                model?.mcpServer = nil
                model?.mcpEnabled = false
                model?.alertMessage = String(localized: "The MCP server stopped: \(message). The port may be in use.")
            }
        }
    }

    // MARK: - Connection

    private func accept(_ conn: NWConnection) {
        conn.start(queue: queue)
        receive(conn, buffer: Data())
    }

    private func receive(_ conn: NWConnection, buffer: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { [weak self] data, _, isComplete, error in
            guard let self else { conn.cancel(); return }
            var buf = buffer
            if let data { buf.append(data) }
            if buf.count > 2_000_000 {
                self.send(conn, Self.response(413, "Payload Too Large", body: Data()))
                return
            }
            if let request = Self.parse(buf) {
                self.send(conn, self.handle(request))
            } else if isComplete || error != nil {
                conn.cancel()
            } else {
                self.receive(conn, buffer: buf)
            }
        }
    }

    private func send(_ conn: NWConnection, _ data: Data) {
        conn.send(content: data, completion: .contentProcessed { _ in conn.cancel() })
    }

    // MARK: - HTTP

    private struct Request { let method: String; let path: String; let headers: [String: String]; let body: Data }

    /// Parses a full HTTP/1.1 request, or nil when more bytes are needed.
    private static func parse(_ buf: Data) -> Request? {
        guard let sep = buf.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: buf[..<sep.lowerBound], as: UTF8.self)
        var lines = head.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ")
        guard parts.count >= 2 else { return nil }
        lines.removeFirst()
        var headers: [String: String] = [:]
        for line in lines {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            headers[key] = value
        }
        let length = headers["content-length"].flatMap { Int($0) } ?? 0
        let bodyStart = sep.upperBound
        let have = buf.distance(from: bodyStart, to: buf.endIndex)
        if have < length { return nil }   // wait for the rest of the body
        let body = length > 0 ? buf.subdata(in: bodyStart..<buf.index(bodyStart, offsetBy: length)) : Data()
        return Request(method: String(parts[0]).uppercased(), path: String(parts[1]), headers: headers, body: body)
    }

    private static func response(_ status: Int, _ reason: String, headers extra: [String: String] = [:], body: Data) -> Data {
        var head = "HTTP/1.1 \(status) \(reason)\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Connection: close\r\n"
        for (k, v) in extra { head += "\(k): \(v)\r\n" }
        head += "\r\n"
        var out = Data(head.utf8)
        out.append(body)
        return out
    }

    private static func json(_ status: Int, _ obj: Any, session: String? = nil) -> Data {
        let body = (try? JSONSerialization.data(withJSONObject: obj)) ?? Data("{}".utf8)
        var headers = ["Content-Type": "application/json"]
        if let session { headers["Mcp-Session-Id"] = session }
        return response(status, status == 200 ? "OK" : "Error", headers: headers, body: body)
    }

    // MARK: - Request handling

    private func handle(_ req: Request) -> Data {
        // Reject a cross-site caller (DNS-rebinding guard). Native agents send no Origin.
        if let origin = req.headers["origin"], !Self.isLocalOrigin(origin) {
            return Self.response(403, "Forbidden", body: Data())
        }
        guard req.method == "POST" else {
            // GET/other: we offer no server-initiated SSE stream.
            return Self.response(405, "Method Not Allowed", headers: ["Allow": "POST"], body: Data())
        }
        guard Self.constantTimeEqual(req.headers["authorization"] ?? "", "Bearer " + token) else {
            return Self.response(401, "Unauthorized", headers: ["WWW-Authenticate": "Bearer"], body: Data())
        }
        onMain { $0.mcpAgentSeen() }

        guard let obj = try? JSONSerialization.jsonObject(with: req.body), let msg = obj as? [String: Any] else {
            return Self.json(400, Self.rpcError(id: nil, code: -32700, message: "Parse error"))
        }
        let method = msg["method"] as? String ?? ""
        let id = msg["id"]
        // A notification (no id) is acknowledged with 202 and no body.
        guard id != nil else { return Self.response(202, "Accepted", body: Data()) }

        guard let result = dispatch(method: method, params: msg["params"] as? [String: Any] ?? [:], id: id!) else {
            return Self.json(200, Self.rpcError(id: id, code: -32601, message: "Method not found: \(method)"))
        }
        return Self.json(200, ["jsonrpc": "2.0", "id": id!, "result": result], session: method == "initialize" ? sessionID : nil)
    }

    /// Returns the JSON-RPC `result` for a request, or nil for an unknown method.
    private func dispatch(method: String, params: [String: Any], id: Any) -> [String: Any]? {
        switch method {
        case "initialize":
            let clientVersion = params["protocolVersion"] as? String ?? Self.protocolVersion
            return [
                "protocolVersion": clientVersion,
                "capabilities": ["tools": [:] as [String: Any]],
                "serverInfo": ["name": "ProxyGate", "version": PGConstants.version],
                "instructions": AppModel.mcpInstructions,
            ]
        case "ping":
            return [:]
        case "tools/list":
            return ["tools": onMain { $0.mcpTools() } ?? []]
        case "tools/call":
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            let result = onMain { $0.mcpCall(name, args) } ?? (text: "The app is not available.", isError: true)
            return ["content": [["type": "text", "text": result.text]], "isError": result.isError]
        default:
            return nil
        }
    }

    private static func rpcError(id: Any?, code: Int, message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]]
    }

    // MARK: - Helpers

    /// Runs `block` on the main actor (where the model lives) and returns its value synchronously.
    private func onMain<T>(_ block: @escaping @MainActor (AppModel) -> T) -> T? {
        guard let model else { return nil }
        return DispatchQueue.main.sync { MainActor.assumeIsolated { block(model) } }
    }

    private static func isLocalOrigin(_ origin: String) -> Bool {
        guard let host = URLComponents(string: origin)?.host else { return false }
        return host == "127.0.0.1" || host == "localhost" || host == "::1"
    }

    private static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
        return diff == 0
    }
}

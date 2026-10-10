import Foundation
import PGCore

/// Fetches a subscription as the app (normal network, macOS system trust — handles modern roots
/// that Python's bundled CA list misses). Identifies as Happ so subscription panels return the
/// full Xray JSON config.
enum SubscriptionClient {
    struct Fetched {
        var json: String
        var name: String?
        var userInfo: String?
    }

    static func fetch(_ urlString: String) async throws -> Fetched {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), url.scheme?.hasPrefix("http") == true else {
            throw NetError("enter a valid https:// subscription link")
        }
        var request = URLRequest(url: url)
        request.setValue("Happ/3.0.0", forHTTPHeaderField: "User-Agent")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw NetError("the provider returned HTTP \(http.statusCode)")
        }
        let json = String(decoding: data, as: UTF8.self)
        guard !XraySubscription.summaries(json).isEmpty else {
            throw NetError("no Xray configs in the response — is this a subscription link for Happ?")
        }
        var name: String?
        var userInfo: String?
        if let http = response as? HTTPURLResponse {
            if let title = http.value(forHTTPHeaderField: "profile-title") {
                name = title.hasPrefix("base64:") ? decodeBase64(String(title.dropFirst(7))) ?? title : title
            }
            userInfo = http.value(forHTTPHeaderField: "subscription-userinfo")
        }
        return Fetched(json: json, name: name, userInfo: userInfo)
    }

    private static func decodeBase64(_ s: String) -> String? {
        Data(base64Encoded: s).map { String(decoding: $0, as: UTF8.self) }
    }
}

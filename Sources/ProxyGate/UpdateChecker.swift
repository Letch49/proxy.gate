import Foundation

/// Checks GitHub for newer versions of the bundled cores (Xray, tpws). The app's own update is left
/// to a future release feed; this covers the two cores the user installs from here.
enum UpdateChecker {
    /// Latest release tag of a repo, or nil on failure.
    static func latestTag(_ repo: String) async -> String? {
        guard let url = URL(string: "https://api.github.com/repos/\(repo)/releases/latest") else { return nil }
        var request = URLRequest(url: url)
        request.setValue("ProxyGate", forHTTPHeaderField: "User-Agent")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        guard let (data, response) = try? await URLSession.shared.data(for: request),
              (response as? HTTPURLResponse)?.statusCode == 200,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return json["tag_name"] as? String
    }
}

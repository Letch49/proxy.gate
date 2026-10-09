import Foundation
import PGCore

/// Profiles live in ~/Library/Application Support/ProxyGate/profiles.json (mode 0600: it holds proxy passwords).
enum ProfileStore {
    struct State: Codable {
        var profiles: [Profile]
        var activeID: UUID
    }

    static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("ProxyGate")
    }

    private static var file: URL { directory.appendingPathComponent("profiles.json") }

    static func load() -> State {
        if let data = try? Data(contentsOf: file),
           var state = try? JSONDecoder().decode(State.self, from: data),
           !state.profiles.isEmpty {
            for i in state.profiles.indices {
                state.profiles[i].normalizeRules()
            }
            if !state.profiles.contains(where: { $0.id == state.activeID }) {
                state.activeID = state.profiles[0].id
            }
            return state
        }
        let profile = Profile.makeDefault()
        return State(profiles: [profile], activeID: profile.id)
    }

    static func save(_ state: State) {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(state).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            NSLog("ProxyGate: cannot save profiles: \(error)")
        }
    }

    static func export(_ profile: Profile, to url: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(profile).write(to: url, options: .atomic)
    }

    static func importProfile(from url: URL) throws -> Profile {
        var profile = try JSONDecoder().decode(Profile.self, from: Data(contentsOf: url))
        profile.id = UUID()
        profile.normalizeRules()
        return profile
    }
}

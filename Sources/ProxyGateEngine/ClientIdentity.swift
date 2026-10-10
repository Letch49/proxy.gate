import Darwin
import Foundation
import PGCore
import Security

/// Checks that a control-socket peer is the pinned build of the app, by code signature.
/// The peer is identified by its audit token, never by PID (PIDs get reused).
struct ClientIdentity {
    private let requirement: SecRequirement

    /// nil when no cdhash is pinned (manual dev run): the caller then falls back to uid only.
    init?(cdhashes: Set<String>) {
        guard let text = CDHash.requirement(for: cdhashes) else { return nil }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(text as CFString, SecCSFlags(), &req) == errSecSuccess, let req else {
            return nil
        }
        requirement = req
    }

    /// True if the peer on `fd` runs validly signed code whose cdhash is pinned.
    func accepts(fd: Int32) -> Bool {
        // SOL_LOCAL and LOCAL_PEERTOKEN from <sys/un.h>, spelled out in case the overlay omits them.
        let solLocal: Int32 = 0
        let localPeerToken: Int32 = 0x006
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, solLocal, localPeerToken, &token, &length) == 0,
              Int(length) == MemoryLayout<audit_token_t>.size else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }

        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, SecCSFlags(), &code) == errSecSuccess, let code else {
            return false
        }
        // Dynamic check: the running process is validly signed and its cdhash matches a pin.
        return SecCodeCheckValidity(code, SecCSFlags(), requirement) == errSecSuccess
    }
}

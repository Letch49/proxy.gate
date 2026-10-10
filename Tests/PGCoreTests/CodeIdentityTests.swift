import Foundation
import Testing
@testable import PGCore

private let sample = "0123456789abcdef0123456789abcdef01234567"

@Test func cdhashNormalize() {
    #expect(CDHash.normalize(sample) == sample)
    #expect(CDHash.normalize(sample.uppercased()) == sample)
    #expect(CDHash.normalize("") == nil)
    #expect(CDHash.normalize(String(sample.dropLast())) == nil)
    #expect(CDHash.normalize(sample + "0") == nil)
    #expect(CDHash.normalize("g123456789abcdef0123456789abcdef01234567") == nil)
    #expect(CDHash.normalize(" 123456789abcdef0123456789abcdef01234567") == nil)
    #expect(CDHash.normalize("\"123456789abcdef0123456789abcdef01234567") == nil)
    // Non-ASCII digits must not slip through a Character-based check.
    #expect(CDHash.normalize("\u{0663}123456789abcdef0123456789abcdef0123456") == nil)
}

@Test func cdhashHex() {
    #expect(CDHash.hex(Data(repeating: 0xAB, count: 20)) == String(repeating: "ab", count: 20))
    #expect(CDHash.hex(Data(repeating: 0, count: 32)) == nil)
    #expect(CDHash.hex(Data()) == nil)
}

@Test func cdhashPinnedFromArguments() {
    let args = ["/path/engine", "--allow-uid", "501", "--client-cdhash", sample.uppercased(), "--client-cdhash", "junk", "--client-cdhash"]
    #expect(CDHash.pinned(in: args) == [sample])
    #expect(CDHash.pinned(in: []).isEmpty)
    #expect(CDHash.pinned(in: ["--client-cdhash"]).isEmpty)
}

@Test func cdhashRequirement() {
    #expect(CDHash.requirement(for: []) == nil)
    #expect(CDHash.requirement(for: ["junk"]) == nil)
    #expect(CDHash.requirement(for: [sample]) == "cdhash H\"\(sample)\"")
    let other = String(repeating: "f", count: 40)
    #expect(CDHash.requirement(for: [other, sample]) == "cdhash H\"\(sample)\" or cdhash H\"\(other)\"")
}

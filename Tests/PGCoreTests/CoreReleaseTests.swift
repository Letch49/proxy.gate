import Foundation
import Testing
@testable import PGCore

private let hexA = String(repeating: "a", count: 64)
private let hexB = String(repeating: "B", count: 64)

@Test func releaseTagValidation() {
    #expect(CoreReleases.isValidTag("v25.10.15"))
    #expect(CoreReleases.isValidTag("v71.4"))
    #expect(CoreReleases.isValidTag("0.16.6"))
    #expect(CoreReleases.isValidTag("v1.2.3.4"))
    #expect(CoreReleases.isValidTag("v72"))
    #expect(!CoreReleases.isValidTag(""))
    #expect(!CoreReleases.isValidTag("v"))
    #expect(!CoreReleases.isValidTag("v1..2"))
    #expect(!CoreReleases.isValidTag("v1.2."))
    #expect(!CoreReleases.isValidTag("v1.2.3.4.5"))
    #expect(!CoreReleases.isValidTag("../v1.2"))
    #expect(!CoreReleases.isValidTag("v1.2/../../x"))
    #expect(!CoreReleases.isValidTag("v1.2?x=1"))
    #expect(!CoreReleases.isValidTag("v1.2-rc1"))
    #expect(!CoreReleases.isValidTag("V1.2"))
    #expect(!CoreReleases.isValidTag("v１.２"))
    #expect(!CoreReleases.isValidTag("v1234567.1"))
    #expect(CoreReleases.xrayChecksumURL(tag: "v1.2/x", arm64: true) == nil)
    #expect(CoreReleases.tpwsChecksumURL(tag: "") == nil)
    #expect(CoreReleases.xrayChecksumURL(tag: "v25.10.15", arm64: true)?.absoluteString
            == "https://github.com/XTLS/Xray-core/releases/download/v25.10.15/Xray-macos-arm64-v8a.zip.dgst")
    #expect(CoreReleases.tpwsChecksumURL(tag: "v71.4")?.absoluteString
            == "https://github.com/bol-van/zapret/releases/download/v71.4/sha256sum.txt")
}

@Test func dgstParsing() {
    let dgst = "MD5= 0123\nSHA1= 4567\nSHA2-256= \(hexA)\nSHA2-512= \(String(repeating: "c", count: 128))\n"
    #expect(CoreReleases.parseDgst(dgst) == hexA)
    #expect(CoreReleases.parseDgst("SHA2-256=\(hexB)\r\n") == hexB.lowercased())
    #expect(CoreReleases.parseDgst("SHA2-512= \(hexA)") == nil)
    #expect(CoreReleases.parseDgst("SHA2-256= nothex") == nil)
    #expect(CoreReleases.parseDgst("SHA2-256= \(hexA)ff") == nil)
    #expect(CoreReleases.parseDgst("SHA2-256=") == nil)
    #expect(CoreReleases.parseDgst("=") == nil)
    #expect(CoreReleases.parseDgst("") == nil)
    #expect(CoreReleases.parseDgst("\n\n==\n") == nil)
    #expect(CoreReleases.parseDgst(String(repeating: "x", count: 10_000)) == nil)
}

@Test func sha256SumMatching() {
    let sums = """
    \(String(repeating: "1", count: 64))  zapret-v71.4/binaries/linux-x86_64/tpws
    \(hexA)  zapret-v71.4/binaries/mac64/tpws
    \(String(repeating: "2", count: 64))  zapret-v71.4/binaries/mac64/ip2net
    """
    let entry = CoreReleases.tpwsEntry(inSumFile: sums)
    #expect(entry?.sha256 == hexA)
    #expect(entry?.path == "zapret-v71.4/binaries/mac64/tpws")

    // Binary-mode marker, tabs and CRLF.
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexB) *binaries/mac64/tpws\r\n")?.sha256 == hexB.lowercased())
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)\tz/binaries/mac64/tpws")?.sha256 == hexA)
    // A look-alike file name must not match.
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)  z/binaries/mac64/xtpws") == nil)
    // Traversal and absolute paths are dropped.
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)  ../../binaries/mac64/tpws") == nil)
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)  /binaries/mac64/tpws") == nil)
    // Conflicting hashes for the same binary are refused.
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)  a/binaries/mac64/tpws\n\(hexB)  b/binaries/mac64/tpws") == nil)
    // Malformed input.
    #expect(CoreReleases.tpwsEntry(inSumFile: "") == nil)
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)") == nil)
    #expect(CoreReleases.tpwsEntry(inSumFile: "\(hexA)   ") == nil)
    #expect(CoreReleases.tpwsEntry(inSumFile: "nothex  z/binaries/mac64/tpws") == nil)
    #expect(CoreReleases.tpwsEntry(inSumFile: " \n*\n\t\t\n") == nil)
    #expect(CoreReleases.sumEntries("garbage\n\(hexA) *\n").isEmpty)
}

@Test func byedpiPinnedTable() {
    let arm = CoreReleases.byedpiBuild(version: CoreReleases.byedpiVersion, arm64: true)
    let x86 = CoreReleases.byedpiBuild(version: CoreReleases.byedpiVersion, arm64: false)
    #expect(arm?.member == "ciadpi-arm")
    #expect(x86?.member == "ciadpi-x64")
    #expect(arm?.tarballSHA256 == "f2a2287f9d1fd4493d82516591a46a97c94fbab015d8a626805598d99f3dd3de")
    #expect(x86?.tarballSHA256 == "615f4fb1758878a2459467bde290a15908a28dc02965ec9e43e3cdc55a0ab592")
    #expect(CoreReleases.byedpiBuild(version: "9.9.9", arm64: true) == nil)
    #expect(CoreReleases.byedpiBuild(version: "", arm64: false) == nil)
    for build in CoreReleases.byedpiBuilds {
        #expect(CoreReleases.isSHA256Hex(build.tarballSHA256))
        #expect(CoreReleases.isValidTag(build.version))
        #expect(!build.member.isEmpty && !build.member.contains("/") && !build.member.hasPrefix("-"))
        #expect(build.url.hasPrefix("https://"))
    }
}

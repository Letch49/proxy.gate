// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "ProxyGate",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ProxyGate", targets: ["ProxyGate"]),
        .executable(name: "proxygate-engine", targets: ["ProxyGateEngine"]),
    ],
    targets: [
        .target(name: "CSys"),
        .target(name: "PGCore", dependencies: ["CSys"]),
        .executableTarget(name: "ProxyGateEngine", dependencies: ["PGCore", "CSys"]),
        .executableTarget(name: "ProxyGate", dependencies: ["PGCore"]),
        .testTarget(name: "PGCoreTests", dependencies: ["PGCore"]),
    ],
    swiftLanguageModes: [.v5]
)

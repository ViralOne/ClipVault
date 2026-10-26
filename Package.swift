// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ClipVault",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ClipVault", targets: ["ClipVault"])
    ],
    targets: [
        .target(name: "ClipVaultKit"),
        .executableTarget(name: "ClipVault", dependencies: ["ClipVaultKit"]),
        .testTarget(name: "ClipVaultKitTests", dependencies: ["ClipVaultKit"])
    ]
)

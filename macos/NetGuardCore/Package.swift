// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "NetGuardCore", platforms: [.macOS("15.0")], products: [.library(name: "NetGuardCore", type: .static, targets: ["NetGuardCore"])], targets: [.target(name: "NetGuardCore"), .testTarget(name: "NetGuardCoreTests", dependencies: ["NetGuardCore"])])

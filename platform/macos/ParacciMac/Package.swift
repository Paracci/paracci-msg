// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "ParacciMac",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "ParacciMac", targets: ["ParacciMac"])
    ],
    targets: [
        .executableTarget(
            name: "ParacciMac",
            path: "Sources"
        ),
        .testTarget(
            name: "ParacciMacTests",
            dependencies: ["ParacciMac"],
            path: "Tests"
        )
    ]
)

// swift-tools-version:5.9
// The platform floors below are the single source of the Apple deployment
// targets: build-xcframework.sh reads them to compile the Rust slices.

import PackageDescription

let package = Package(
    name: "ZannCoreKit",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "ZannCoreKit", targets: ["ZannCoreKit"]),
    ],
    targets: [
        // Built by build-xcframework.sh; not committed.
        .binaryTarget(name: "ZannFFI", path: "Generated/ZannFFI.xcframework"),
        .target(
            name: "ZannCoreKit",
            dependencies: ["ZannFFI"],
            path: "Generated/Swift",
            // `rustc --print native-static-libs` for each slice of libzann_ffi.a.
            linkerSettings: [
                .linkedFramework("CoreFoundation"),
                .linkedLibrary("iconv"),
                .linkedFramework("Security", .when(platforms: [.macOS])),
                .linkedFramework("IOKit", .when(platforms: [.macOS])),
                .linkedFramework("AppKit", .when(platforms: [.macOS])),
            ]
        ),
        .testTarget(name: "ZannCoreKitTests", dependencies: ["ZannCoreKit"]),
    ]
)

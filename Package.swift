// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "PasuFSPrototype",
  platforms: [
    // This constrains only the prototype package, not the future product.
    .macOS(.v11)
  ],
  products: [
    .library(name: "PasuFSPolicy", targets: ["PasuFSPolicy"]),
    .library(name: "PasuFSEndpointCore", targets: ["PasuFSEndpointCore"]),
    .executable(name: "es-integration-harness", targets: ["ESIntegrationHarness"]),
    .executable(name: "pasu-fs-host", targets: ["PasuFSHost"]),
    .executable(name: "pasu-fs-system-extension", targets: ["PasuFSSystemExtension"]),
  ],
  targets: [
    .target(name: "PasuFSPolicy"),
    .target(
      name: "PasuFSEndpointCore",
      dependencies: ["PasuFSPolicy"],
      linkerSettings: [
        .linkedLibrary("EndpointSecurity"),
        .linkedLibrary("bsm"),
      ]
    ),
    .executableTarget(
      name: "ESIntegrationHarness",
      dependencies: ["PasuFSEndpointCore", "PasuFSPolicy"]
    ),
    .executableTarget(
      name: "PasuFSHost",
      linkerSettings: [
        .linkedFramework("SystemExtensions")
      ]
    ),
    .executableTarget(
      name: "PasuFSSystemExtension",
      linkerSettings: [
        .linkedLibrary("EndpointSecurity")
      ]
    ),
    .testTarget(
      name: "PasuFSPolicyTests",
      dependencies: ["PasuFSPolicy"]
    ),
    .testTarget(
      name: "PasuFSEndpointCoreTests",
      dependencies: ["PasuFSEndpointCore"]
    ),
  ]
)

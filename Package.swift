// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "PasuFSPrototype",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .library(name: "PasuFSPolicy", targets: ["PasuFSPolicy"]),
    .library(name: "PasuFSEndpointCore", targets: ["PasuFSEndpointCore"]),
    .library(name: "PasuFSConfiguration", targets: ["PasuFSConfiguration"]),
    .library(name: "PasuFSIPC", targets: ["PasuFSIPC"]),
    .library(name: "PasuFSHostCore", targets: ["PasuFSHostCore"]),
    .executable(name: "es-integration-harness", targets: ["ESIntegrationHarness"]),
    .executable(name: "pasu-fs-host", targets: ["PasuFSHost"]),
    .executable(name: "pasu-fs-app", targets: ["PasuFSApp"]),
    .executable(name: "pasu-fs-system-extension", targets: ["PasuFSSystemExtension"]),
  ],
  targets: [
    .target(name: "PasuFSPolicy"),
    .target(
      name: "PasuFSConfiguration",
      dependencies: ["PasuFSPolicy"]
    ),
    .target(
      name: "PasuFSEndpointCore",
      dependencies: ["PasuFSConfiguration", "PasuFSPolicy"],
      linkerSettings: [
        .linkedLibrary("EndpointSecurity"),
        .linkedLibrary("bsm"),
      ]
    ),
    .target(
      name: "PasuFSIPC",
      dependencies: ["PasuFSConfiguration"],
      linkerSettings: [
        .linkedFramework("Security")
      ]
    ),
    .target(
      name: "PasuFSHostCore",
      dependencies: ["PasuFSConfiguration", "PasuFSIPC"],
      linkerSettings: [
        .linkedFramework("SystemExtensions")
      ]
    ),
    .executableTarget(
      name: "ESIntegrationHarness",
      dependencies: ["PasuFSEndpointCore", "PasuFSPolicy"]
    ),
    .executableTarget(
      name: "PasuFSHost",
      dependencies: ["PasuFSHostCore"]
    ),
    .executableTarget(
      name: "PasuFSApp",
      dependencies: ["PasuFSConfiguration", "PasuFSHostCore", "PasuFSIPC"],
      linkerSettings: [
        .linkedFramework("AppKit"),
        .linkedFramework("SwiftUI"),
      ]
    ),
    .executableTarget(
      name: "PasuFSSystemExtension",
      dependencies: [
        "PasuFSConfiguration", "PasuFSEndpointCore", "PasuFSIPC", "PasuFSPolicy",
      ],
      linkerSettings: [
        .linkedLibrary("EndpointSecurity"),
        .linkedFramework("Security"),
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
    .testTarget(
      name: "PasuFSConfigurationTests",
      dependencies: ["PasuFSConfiguration", "PasuFSPolicy"]
    ),
    .testTarget(
      name: "PasuFSHostCoreTests",
      dependencies: ["PasuFSConfiguration", "PasuFSHostCore"]
    ),
    .testTarget(
      name: "PasuFSAppTests",
      dependencies: ["PasuFSApp", "PasuFSConfiguration"]
    ),
  ]
)

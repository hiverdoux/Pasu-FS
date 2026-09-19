// swift-tools-version: 6.0

import PackageDescription

let package = Package(
  name: "PasuFS",
  platforms: [
    .macOS(.v14)
  ],
  products: [
    .library(name: "PasuFSPolicy", targets: ["PasuFSPolicy"]),
    .library(name: "PasuFSEndpointCore", targets: ["PasuFSEndpointCore"]),
    .library(name: "PasuFSConfiguration", targets: ["PasuFSConfiguration"]),
    .library(name: "PasuFSIPC", targets: ["PasuFSIPC"]),
    .library(name: "PasuFSHostCore", targets: ["PasuFSHostCore"]),
    .library(name: "PasuFSMaintenanceCore", targets: ["PasuFSMaintenanceCore"]),
    .executable(name: "pasu-fs-maintenance", targets: ["PasuFSMaintenance"]),
    .executable(name: "es-capability-probe", targets: ["ESCapabilityProbe"]),
    .executable(name: "pasu-fs-host", targets: ["PasuFSHost"]),
    .executable(name: "pasu-fs-app", targets: ["PasuFSApp"]),
    .executable(name: "pasu-fs-system-extension", targets: ["PasuFSSystemExtension"]),
  ],
  targets: [
    .target(name: "PasuFSPolicy"),
    .target(
      name: "PasuFSEndpointCore",
      dependencies: ["PasuFSConfiguration", "PasuFSPolicy"],
      linkerSettings: [
        .linkedLibrary("EndpointSecurity"),
        .linkedLibrary("bsm"),
      ]
    ),
    .target(
      name: "PasuFSConfiguration",
      dependencies: ["PasuFSPolicy"]
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
      dependencies: ["PasuFSConfiguration", "PasuFSIPC", "PasuFSMaintenanceCore"],
      linkerSettings: [
        .linkedFramework("Security"),
        .linkedFramework("SystemExtensions"),
      ]
    ),
    .target(
      name: "PasuFSMaintenanceCore",
      dependencies: ["PasuFSConfiguration", "PasuFSIPC"]
    ),
    .executableTarget(
      name: "PasuFSMaintenance",
      dependencies: ["PasuFSMaintenanceCore", "PasuFSHostCore"]
    ),
    .testTarget(
      name: "PasuFSMaintenanceTests",
      dependencies: ["PasuFSMaintenanceCore", "PasuFSMaintenance"]
    ),
    .executableTarget(
      name: "ESCapabilityProbe",
      linkerSettings: [
        .linkedLibrary("EndpointSecurity")
      ]
    ),
    .executableTarget(
      name: "PasuFSHost",
      dependencies: []
    ),
    .executableTarget(
      name: "PasuFSApp",
      dependencies: [
        "PasuFSConfiguration", "PasuFSHostCore", "PasuFSIPC", "PasuFSMaintenanceCore",
      ],
      linkerSettings: [
        .linkedFramework("AppKit"),
        .linkedFramework("ServiceManagement"),
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

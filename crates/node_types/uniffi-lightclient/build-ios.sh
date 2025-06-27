#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# Clean up old build artifacts
rm -rf ./bindings ./PrismLightClient

# Create necessary directories
mkdir -p ./bindings/Headers
mkdir -p ./PrismLightClient/Sources/PrismLightClient

# Build for host architecture to generate bindings
cargo build

# Generate Swift bindings
cargo run --bin uniffi-bindgen \
  generate \
  --library ../../../target/debug/libprism_uniffi_lightclient.dylib \
  --language swift \
  --out-dir ./bindings

# Prepare headers
cat ./bindings/prism_uniffi_lightclientFFI.modulemap > ./bindings/Headers/module.modulemap
cp ./bindings/*.h ./bindings/Headers/

# Build for iOS targets
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build --lib --release --target="$target"
done

# Create XCFramework
xcodebuild -create-xcframework \
  -library ../../../target/aarch64-apple-ios-sim/release/libprism_uniffi_lightclient.a -headers ./bindings/Headers \
  -library ../../../target/aarch64-apple-ios/release/libprism_uniffi_lightclient.a -headers ./bindings/Headers \
  -output "PrismLightClient/PrismLightClientFFI.xcframework"

# Create Swift Package structure
echo "Creating Swift Package..."

# Create Package.swift
cat > PrismLightClient/Package.swift << 'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PrismLightClient",
    platforms: [
        .iOS(.v14)
    ],
    products: [
        .library(
            name: "PrismLightClient",
            targets: ["PrismLightClient", "PrismLightClientFFI"]),
    ],
    targets: [
        .target(
            name: "PrismLightClient",
            dependencies: ["PrismLightClientFFI"],
            path: "Sources/PrismLightClient",
            linkerSettings: [
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("Network")
            ]),
        .binaryTarget(
            name: "PrismLightClientFFI",
            path: "./PrismLightClientFFI.xcframework")
    ]
)
EOF

# Copy Swift files to the package
cp bindings/prism_uniffi_lightclient.swift PrismLightClient/Sources/PrismLightClient/

rm -rf ./bindings

echo "✅ Swift package created at ./PrismLightClient"
echo ""
echo "To use in Xcode:"
echo "1. Open your project in Xcode"
echo "2. Go to File → Add Package Dependencies..."
echo "3. Click 'Add Local...' and select the PrismLightClient folder"
echo "4. Add the package to your target"

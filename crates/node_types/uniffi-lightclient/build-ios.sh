#!/usr/bin/env bash
set -euxo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

rm -rf ./bindings ./ios
mkdir -p ./bindings
mkdir -p ./ios
mkdir -p ./bindings/Headers

cargo build

cargo run --bin uniffi-bindgen \
  generate \
  --library ../../../target/debug/libprism_uniffi_lightclient.dylib \
  --language swift \
  --out-dir ./bindings

cat ./bindings/prism_uniffi_lightclientFFI.modulemap > ./bindings/Headers/module.modulemap

cp ./bindings/*.h ./bindings/Headers/

rm -rf ./ios/prism.xcframework
for target in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build --lib --release --target="$target"
done

xcodebuild -create-xcframework \
  -library ../../../target/aarch64-apple-ios-sim/release/libprism_uniffi_lightclient.a -headers ./bindings/Headers \
  -library ../../../target/aarch64-apple-ios/release/libprism_uniffi_lightclient.a -headers ./bindings/Headers \
  -output "ios/prism.xcframework"

cp ./bindings/*.swift ./ios/

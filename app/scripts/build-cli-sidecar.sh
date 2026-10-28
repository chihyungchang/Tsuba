#!/bin/sh
# Builds the terminal checker (crates/cli) for the release bundle and puts it where Tauri's externalBin expects it,
# src-tauri/binaries/tsuba-<target triple>. The bundler copies it to Tsuba.app/Contents/MacOS/tsuba, which is where
# the App looks for it (shell_hook::bundled_cli). Without this step a release build ships without terminal protection.
#
# Runs from tauri.release.conf.json's beforeBuildCommand; Tauri sets TAURI_ENV_TARGET_TRIPLE.
set -eu
cd "$(dirname "$0")/.."
target="${TAURI_ENV_TARGET_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"
out=src-tauri/binaries
mkdir -p "$out"

build() {
  cargo build --release --locked -p tsuba-cli --target "$1" --manifest-path ../Cargo.toml
}

if [ "$target" = universal-apple-darwin ]; then
  build aarch64-apple-darwin
  build x86_64-apple-darwin
  lipo -create -output "$out/tsuba-$target" ../target/aarch64-apple-darwin/release/tsuba ../target/x86_64-apple-darwin/release/tsuba
else
  build "$target"
  cp "../target/$target/release/tsuba" "$out/tsuba-$target"
fi
echo "sidecar: $out/tsuba-$target"

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
  # A universal build compiles each architecture on its own first, and each of those looks for its own sidecar;
  # only the final bundle uses the merged one
  for arch in aarch64-apple-darwin x86_64-apple-darwin; do
    build "$arch"
    cp "../target/$arch/release/tsuba" "$out/tsuba-$arch"
  done
  lipo -create -output "$out/tsuba-$target" "$out/tsuba-aarch64-apple-darwin" "$out/tsuba-x86_64-apple-darwin"
else
  build "$target"
  cp "../target/$target/release/tsuba" "$out/tsuba-$target"
fi
echo "sidecar: $out/tsuba-$target"

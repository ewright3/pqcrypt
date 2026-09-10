#!/usr/bin/env bash
# Cross-compile pqcrypt for Windows, macOS, and Linux (amd64 + arm64).
# Pure Go, CGO disabled -> fully static, no runtime dependencies.
set -euo pipefail
cd "$(dirname "$0")"

export CGO_ENABLED=0
export GOTOOLCHAIN=local   # build with the installed Go, no auto-download
OUT=dist
rm -rf "$OUT" && mkdir "$OUT"

build() {
	local goos=$1 goarch=$2 name=$3
	GOOS=$goos GOARCH=$goarch go build -trimpath -ldflags="-s -w" -o "$OUT/$name" .
	echo "  $name"
}

echo "building -> $OUT/"
build windows amd64 pqcrypt-windows-amd64.exe
build windows arm64 pqcrypt-windows-arm64.exe
build darwin  amd64 pqcrypt-macos-amd64
build darwin  arm64 pqcrypt-macos-arm64
build linux   amd64 pqcrypt-linux-amd64
build linux   arm64 pqcrypt-linux-arm64

( cd "$OUT" && sha256sum pqcrypt-* > SHA256SUMS.txt )
echo "done. checksums in $OUT/SHA256SUMS.txt"

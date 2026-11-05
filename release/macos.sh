#!/usr/bin/env bash
# eventchain-verify for macOS with libcrypto linked in, so the binary needs
# nothing beyond what macOS ships. Needs GHC 9.12.4, cabal 3.16 and
# Homebrew's openssl@3. The binary's architecture is the build machine's.
#
#   release/macos.sh OUT_DIR
#
# macOS cannot link a fully static binary, and ld64 takes a .dylib over a .a
# in the same directory, so the build sees a pkg-config file whose library
# directory holds only libcrypto.a. The binary is checked before the script
# exits: it may load nothing from outside /usr/lib and /System, and it must
# verify the lifecycle vector. Beside it, openssl-version names the libcrypto
# linked in, for the release notes.
set -euo pipefail

[ $# -eq 1 ] || { echo "usage: $0 OUT_DIR" >&2; exit 2; }
OUT=$1
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SSL=$(brew --prefix openssl@3)
[ -f "$SSL/lib/libcrypto.a" ] || { echo "no libcrypto.a under $SSL/lib" >&2; exit 1; }

PC=$(mktemp -d)
trap 'rm -rf "$PC"' EXIT
cp "$SSL/lib/libcrypto.a" "$PC/"
VERSION=$(pkg-config --modversion "$SSL/lib/pkgconfig/libcrypto.pc")
cat > "$PC/libcrypto.pc" <<EOF
Name: OpenSSL-libcrypto
Description: OpenSSL cryptography library, static archive only
Version: $VERSION
Libs: -L$PC -lcrypto
Cflags: -I$SSL/include
EOF

cd "$ROOT"
# A build directory of its own, so a development build's cached libcrypto
# configuration is neither reused here nor overwritten.
FLAGS=(--builddir=dist-release --disable-tests --disable-benchmarks)
PKG_CONFIG_LIBDIR=$PC cabal build "${FLAGS[@]}" exe:eventchain-verify
BIN=$(cabal list-bin "${FLAGS[@]}" exe:eventchain-verify)
mkdir -p "$OUT"
cp "$BIN" "$OUT/eventchain-verify"
strip "$OUT/eventchain-verify"
echo "$VERSION" > "$OUT/openssl-version"

otool -L "$OUT/eventchain-verify"
if otool -L "$OUT/eventchain-verify" | tail -n +2 | grep -vE '^\s+(/usr/lib/|/System/Library/)'; then
  echo "the binary loads a library macOS does not ship" >&2
  exit 1
fi
otool -l "$OUT/eventchain-verify" | grep -A4 LC_BUILD_VERSION | grep minos
"$OUT/eventchain-verify" aof conformance/vectors/v0-lifecycle.jsonl

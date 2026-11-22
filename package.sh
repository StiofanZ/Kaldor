#!/bin/sh
set -eu
action=$1
case "$action" in build|package) ;; *) exit 2;; esac
mkdir -p "$2"
out=$(cd "$2" && pwd)
export COPYFILE_DISABLE=1
target=armv7-unknown-linux-musleabihf
target_dir=${CARGO_TARGET_DIR:-"$PWD/target"}
mkdir -p "$target_dir"
CARGO_TARGET_DIR=$(cd "$target_dir" && pwd)
export CARGO_TARGET_DIR
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml)
name=kaldor-$version
if [ "$action" = build ]; then
 python3 build/cross.py armv7 build --locked --release
 cp "$CARGO_TARGET_DIR/$target/release/kaldor" "$out/kaldor"
 exit
fi
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp -R src build third_party test panel.html service.sh kaldorctl kaldor-update Cargo.toml Cargo.lock Makefile package.sh README.md LICENSE "$stage/"
mkdir -p "$stage/.cargo"
if [ -d vendor ]; then
 cp -R vendor "$stage/"
else
 cargo vendor --locked "$stage/vendor" > /dev/null
fi
cat > "$stage/.cargo/config.toml" <<'CONFIG'
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
CONFIG
(cd "$stage" && CARGO_NET_OFFLINE=true python3 build/cross.py armv7 build --locked --release)
cp "$CARGO_TARGET_DIR/$target/release/kaldor" "$out/kaldor"
cp kaldorctl kaldor-update "$out/"
tar -czf "$out/$name-linux-armv7.tar.gz" -C "$out" kaldor kaldorctl kaldor-update -C "$stage" README.md LICENSE
tar -czf "$out/$name-source.tar.gz" -C "$stage" .
(cd "$out"
 binary_hash=$(sha256sum kaldor)
 printf '%s %s\n' "$version" "${binary_hash%% *}" > rt-ax89x.manifest
 sha256sum kaldor kaldor-update rt-ax89x.manifest "$name-linux-armv7.tar.gz" "$name-source.tar.gz" > SHA256SUMS
)

#!/bin/sh
set -eu
action=$1
mkdir -p "$2"
out=$(cd "$2" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
export COPYFILE_DISABLE=1
version=$(cat VERSION)
name=axproxy-$version
cp *.go go.mod go.sum panel.html service.sh axproxyctl Makefile package.sh VERSION README.md LICENSE "$stage/"
cp -R test "$stage/test"
if [ -d vendor ]; then cp -R vendor "$stage/vendor"; else go mod vendor -o "$stage/vendor"; fi
# Compile from the exact tree shipped in the source archive, including its dependencies.
(cd "$stage" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -mod=vendor -trimpath -buildvcs=false \
  -ldflags="-s -w -X main.version=$version" -o "$out/axproxy" .)
if [ "$action" = package ]; then
 cp axproxyctl "$out/axproxyctl"
 tar -czf "$out/$name-linux-armv7.tar.gz" -C "$out" axproxy axproxyctl -C "$stage" README.md LICENSE VERSION
 tar -czf "$out/$name-source.tar.gz" -C "$stage" .
 (cd "$out" && sha256sum axproxy "$name-linux-armv7.tar.gz" "$name-source.tar.gz" > SHA256SUMS)
fi

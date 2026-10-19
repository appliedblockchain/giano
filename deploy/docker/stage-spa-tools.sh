#!/bin/sh
# Stage the SPA tool allow-list for a DHI nginx runtime (docs/abip-compliance.md): /bin/sh (dash),
# envsubst and jq, each with the shared libraries it links that the runtime does not already ship,
# at their real paths under $1. Runs in the nginx -dev build stage of the three SPA Dockerfiles; the
# final stage copies $1 over / in a single COPY. Adding a binary here widens what every SPA image
# carries — the allow-list is pinned by the container-images spec, so change both or neither.
set -eu
dest=$1

# glibc and the dynamic loader are in the runtime already (nginx links them); copying ours over
# them could only introduce a mismatch.
provided() {
  case "$1" in
    */libc.so.* | */ld-linux-*.so.* | */libm.so.* | */libpthread.so.* | */libdl.so.*) return 0 ;;
  esac
  return 1
}

stage() {
  src=$1 target=$2
  mkdir -p "$dest$(dirname "$target")"
  cp -L "$src" "$dest$target"
  ldd "$src" | while read -r first _ second _; do
    lib=$second
    case "$first" in /*) lib=$first ;; esac # the loader line has no "=>"
    case "$lib" in /*) ;; *) continue ;; esac
    provided "$lib" && continue
    # ldd names libraries through /lib, a symlink in the merged-/usr runtime: stage them under the
    # real directory, keeping the soname the binary asks for
    dir=$(readlink -f "$(dirname "$lib")")
    mkdir -p "$dest$dir"
    cp -L "$lib" "$dest$dir/$(basename "$lib")"
  done
}

# /bin is a symlink to usr/bin in the runtime (merged /usr), so stage under usr/bin
stage /usr/bin/dash /usr/bin/sh
stage /usr/bin/envsubst /usr/bin/envsubst
stage /usr/bin/jq /usr/bin/jq

# the entrypoint renders config.json/config.js into the html root as the nginx user (65532)
mkdir -p "$dest/usr/share/nginx/html"
chown -R 65532:65532 "$dest/usr/share/nginx/html"

echo "staged:"; find "$dest" -type f | sort

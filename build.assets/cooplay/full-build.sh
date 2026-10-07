#!/usr/bin/env bash
# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/../.."
repo_dir=$(pwd -P)
ui_image=$(python3 -c 'import json; print(json.load(open("build.assets/cooplay/toolchains.json"))["ui_linux_arm64"])')
export GOTOOLCHAIN=go1.25.14 CGO_ENABLED=1 TZ=UTC LC_ALL=C
case "${1:-all}" in
 ui)
  : "${GOMODCACHE:?set a task-local Go module cache}"
  go mod download golang.org/toolchain@v0.0.1-go1.25.14.linux-arm64
  linux_go="$GOMODCACHE/golang.org/toolchain@v0.0.1-go1.25.14.linux-arm64"
  chmod u+x "$linux_go/bin/go" "$linux_go/bin/gofmt"
  find "$linux_go/pkg/tool" -type f -exec chmod u+x {} \;
  mkdir -p build/cooplay-cache/cargo-git build/cooplay-cache/cargo-registry
  docker pull "$ui_image"
  docker run --rm --platform=linux/arm64 --user=0 \
    --mount "type=bind,source=$repo_dir,target=/workspace" --workdir=/workspace \
    --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/workspace \
    --mount "type=bind,source=$linux_go,target=/opt/go,readonly" \
    --env GOROOT=/opt/go --env PATH=/opt/go/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --mount "type=bind,source=$repo_dir/build/cooplay-cache/cargo-git,target=/usr/local/cargo/git" \
    --mount "type=bind,source=$repo_dir/build/cooplay-cache/cargo-registry,target=/usr/local/cargo/registry" \
    --env CARGO_BUILD_JOBS=4 --env GITHUB_REPOSITORY_OWNER=cooplay-tw --env COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    --env TZ=UTC --env LC_ALL=C --env SOURCE_DATE_EPOCH=0 --env RUSTUP_TOOLCHAIN=1.94.0 \
    "$ui_image" bash -euc '
      test "$(node --version)" = v24.20.0
      test "$(rustc --version | cut -d" " -f2)" = 1.94.0
      sha256sum pnpm-lock.yaml Cargo.lock > /tmp/locks.before
      # The server UI has no Electron runtime dependency. Limit installation
      # to its workspace dependency graph; build the normal upstream assets.
      pnpm --filter @gravitational/teleport... install --frozen-lockfile
      pnpm generate-theme
      cp web/packages/design/src/assets/images/agpl-light.svg web/packages/teleport/public/app/logo-light.svg
      cp web/packages/design/src/assets/images/agpl-dark.svg web/packages/teleport/public/app/logo-dark.svg
      make --assume-old=ensure-js-deps build-ui WEBASSETS_SKIP_BUILD=0
      sha256sum --check /tmp/locks.before
      test -s webassets/teleport/index.html
      find webassets/teleport -type f | wc -l
    '
  ;;
 native)
  test -s webassets/teleport/index.html
  test "$(go env GOVERSION)" = "$GOTOOLCHAIN"
  output_dir="build/cooplay-candidate/$(go env GOOS)-$(go env GOARCH)"
  mkdir -p "$output_dir"
  build_tags=webassets_embed,kustomize_disable_go_plugin_support
  if [ "$(go env GOOS)" = linux ]; then
    go -C session build -p=4 -mod=readonly -trimpath -buildvcs=false \
      -tags=gravitational_trace.nocrypto -o "$repo_dir/$output_dir/.sessionhelper" ./cmd/sessionhelper
    mkdir -p session/reexec/embed
    gzip -9 -n < "$output_dir/.sessionhelper" > "session/reexec/embed/sessionhelper_linux_$(go env GOARCH).gz"
    rm "$output_dir/.sessionhelper"
    build_tags="$build_tags,sessionhelper_embed"
  fi
  for binary in teleport tsh tctl; do
    go build -p=4 -mod=readonly -trimpath -buildvcs=false \
      -tags="$build_tags" \
      -ldflags "-X github.com/gravitational/teleport.Gitref=$(git rev-parse HEAD)" \
      -o "$output_dir/$binary" "./tool/$binary"
  done
  python3 build.assets/cooplay/manifest.py --output "$output_dir" --profile full-ui-keycloak-candidate
  ;;
 linux|linux-amd64)
  target_arch=arm64
  if [ "$1" = linux-amd64 ]; then
    target_arch=amd64
    ui_image=$(python3 -c 'import json; print(json.load(open("build.assets/cooplay/toolchains.json"))["linux_amd64"])')
  fi
  test -s webassets/teleport/index.html
  : "${GOMODCACHE:?set a task-local Go module cache}"
  : "${GOCACHE:?set a task-local Go build cache}"
  go mod download golang.org/toolchain@v0.0.1-go1.25.14.linux-$target_arch
  linux_go="$GOMODCACHE/golang.org/toolchain@v0.0.1-go1.25.14.linux-$target_arch"
  chmod u+x "$linux_go/bin/go" "$linux_go/bin/gofmt"
  find "$linux_go/pkg/tool" -type f -exec chmod u+x {} \;
  mkdir -p "$GOCACHE/linux-$target_arch"
  docker run --rm --platform=linux/$target_arch --user=0 \
    --mount "type=bind,source=$repo_dir,target=/workspace" --workdir=/workspace \
    --mount "type=bind,source=$linux_go,target=/opt/go,readonly" \
    --mount "type=bind,source=$GOMODCACHE,target=/gomod" \
    --mount "type=bind,source=$GOCACHE/linux-$target_arch,target=/gocache" \
    --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/workspace \
    --env GOMODCACHE=/gomod --env GOCACHE=/gocache --env GOROOT=/opt/go \
    --env PATH=/opt/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    "$ui_image" bash build.assets/cooplay/full-build.sh native
  ;;
 all)
  bash build.assets/cooplay/full-build.sh ui
  bash build.assets/cooplay/full-build.sh native
  bash build.assets/cooplay/full-build.sh linux
  bash build.assets/cooplay/full-build.sh linux-amd64
  ;;
 *) echo 'Usage: full-build.sh [ui|native|linux|linux-amd64|all]' >&2; exit 2 ;;
esac

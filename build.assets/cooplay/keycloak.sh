#!/usr/bin/env bash
# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail
cd "$(dirname "$0")/../.."
export GOTOOLCHAIN=go1.25.14
export CGO_ENABLED=1
export TZ=UTC
export LC_ALL=C
base=27eb07217a0efca4a5d2dd88bce7472cba5f406a
git merge-base --is-ancestor "$base" HEAD
test "$(go env GOVERSION)" = "$GOTOOLCHAIN"
test "$(go env GOOS)" = "$(go env GOHOSTOS)"
test "$(go env GOARCH)" = "$(go env GOHOSTARCH)"

case "${1:-test}" in
  test)
    python3 -m unittest discover -s build.assets/cooplay -p 'test_*.py'
    go test -mod=readonly -count=1 ./lib/cooplay/secrets
    go test -mod=readonly -count=1 -timeout=15m ./lib/auth ./lib/web ./lib/srv \
      -run 'TestKeycloak|TestGenerateUserCertWithLocks|TestUpsertDeleteLockEventsEmitted|TestCloseConnectionsOnLogout|TestApplicationWebSessionsDeletedAfterLogout|TestConnectionMonitorLockInForce|TestMonitorLockInForce|TestMonitorStaleLocks|TestMonitorDisconnectExpiredCertBeforeTimeNow|TestWebSessionWithoutAccessRequest|TestWebSessionMultiAccessRequests|TestWebSessionWithApprovedAccessRequestAndSwitchback|TestExtendWebSessionWithReloadUser|TestExtendWebSessionWithMaxDuration|TestGenerateUserCertsWithRoleRequest'
    ;;
  build)
    # Deliberately a CLI/local-evaluation profile: no bundled UI, Touch ID,
    # libfido2, PIV, BPF or RDP. Do not distribute as a production build.
    mkdir -p build/cooplay-keycloak
    for binary in teleport tsh tctl; do
      go build -mod=readonly -trimpath -buildvcs=false \
        -tags=kustomize_disable_go_plugin_support \
        -ldflags "-X github.com/gravitational/teleport.Gitref=$(git rev-parse HEAD)" \
        -o "build/cooplay-keycloak/$binary" "./tool/$binary"
    done
    python3 build.assets/cooplay/manifest.py
    ;;
  *) echo 'Usage: bash build.assets/cooplay/keycloak.sh [test|build]' >&2; exit 2 ;;
esac

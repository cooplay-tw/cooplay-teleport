# Candidate validation — 2026-10-07

This is the historical first-candidate evidence. The current hybrid contract
removes public deployment helpers and adds private Admin endpoints, startup
fencing and authoritative session reconciliation; see [the current contract](README.md).

This is local evidence, not production deployment or hosted CI approval. The
maintained v18.11.1 baseline is fixed in [upstream.json](../../build.assets/cooplay/upstream.json).
The implementation and supported deployment contract are in [README](README.md).
The previous [October 6 PoC](validation.md) remains historical evidence.

## Executed builds and tests

- Normal embedded UI built twice with the pinned Linux ARM64 builder,
  Node 24.20.0, Rust 1.94.0 and unchanged dependency locks: all **377** assets
  byte-identical. No fallback-root or UI-disable source overlays.
- Normal full-UI Linux ARM64 (with embedded session helper) and native macOS
  ARM64 builds of teleport, tsh, tctl, cooplay-secrets and cooplay-backup passed.
  Go 1.25.14; macOS Apple clang 21.0.0; Linux Debian GCC 12.2.0 in the pinned builder.
- Full `go test -race -mod=readonly -count=1` for lib/auth, lib/web,
  lib/cooplay/secrets, tool/cooplay-backup and tool/cooplay-secrets passed.
  The final full package run took 20.135s / 170.969s / 2.000s / 2.413s / 1.555s.
  After synchronous startup lock replay was added, the complete Keycloak test
  set passed again under race detection (5.304s), including immediate post-restore
  lock presence before the background loop starts.
- `bash build.assets/cooplay/keycloak.sh test` passed: secret/backup tests and
  focused native authorization, role request, logout, expiry and lock-watcher
  regressions in lib/auth, lib/web and lib/srv. The complete unrelated upstream
  repository test suite was not run.
- The pinned nonroot Kubernetes runtime executes the actual binary with a
  read-only root filesystem, no-new-privileges and all capabilities removed.
- Private eight-test suite passed for renderers, least privilege, manifest pin /
  platform / digest / overwrite rejection, launchd arguments, encrypted restore,
  journal merge, tampering, live PID and filesystem safety. Actual macOS artifact
  staging and execution plus launchd plist syntax passed without service activation.

## Real services

The [public harness](real-smoke.md) uses real Keycloak 26.8.0, Chrome 154.0.8037.98,
Linux SSH and K3s v1.35.9+k3s1. The private cross-repository extension exercises
its actual nonroot Kubernetes Deployment, trusted artifact staging, age-encrypted
native Auth snapshots and a separately built unchanged upstream binary.

Observed positives and negatives include password+OTP browser/CLI login,
wrong-password/OTP denial, exact group roles, non-root SSH and root denial,
current-login copied-session/certificate revocation with another login preserved,
automatic account/group revocation, real Keycloak signed logout and fresh login,
namespace/named-pod access and denial of Secrets / other namespace / cluster-wide
listing / deletion / other-pod exec / impersonation, active SSH/exec termination,
and natural certificate expiry. A valid-before-expiry mutual-TLS probe avoids
mistaking tsh's automatic fresh-login prompt for an authorization result.

The separate real PostgreSQL 18.6-alpine / Keycloak production-mode Compose drill
passed on 2026-10-06 17:47:08 UTC: non-superuser application DB account, read-only
sync account, encrypted pg_dump / restore into a second fresh database, refusal
to overwrite a nonempty database, and restored realm HTTPS readiness. All its
containers and generated secrets were cleaned up.

The source manifest and safe final acceptance reports identify the exact tested
inputs. Do not copy raw browser/HTTP logs, audit streams, UUIDs, profiles, DBs or
recordings into public evidence. Fork revisions and artifact manifests used by
the company belong in its private version pin.

## Limits

The CI files describe reproducible checks but have not been executed on GitHub
in this task. Repeated local builds establish equality for the recorded inputs,
not cross-host or cross-compiler reproducibility. Actual AWS Secrets Manager
permissions, formal DNS/TLS and storage/alert routing require the deployment
identity and owned environment. No production changes were made.

Single Auth is the supported topology. Multi-Auth journal replication, unrelated
Enterprise features and same-subject reinstatement are not claimed. Target Mac
launchd/OS permissions/recording/termination, hardware keys and the joint company
Keycloak/Headscale/Teleport access/recovery acceptance remain external gates.

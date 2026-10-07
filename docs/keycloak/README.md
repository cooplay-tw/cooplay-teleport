# Keycloak SSO candidate

This public fork implements a native, opt-in Keycloak connector and its
credential lifecycle. Company configuration belongs in the separate private
`cooplay-internal-platform` repository. This is a locally validated deployment
candidate, not an Enterprise distribution or a production acceptance claim.

The maintained source baseline is **v18.11.1**, commit
`27eb07217a0efca4a5d2dd88bce7472cba5f406a`. Upstream tags were checked again on
**2026-10-07 Asia/Taipei**: v18.11.1 remained the newest available non-prerelease
v18.11 source tag. The website advertised v18.11.2 without a corresponding tag.
The upstream [support schedule](https://goteleport.com/docs/upcoming-releases/)
places v18 support through August 2027. Recheck source tags and security
advisories before release; do not silently substitute a vendor binary.

See [current validation](candidate-validation.md), the [reproducible lab](real-smoke.md),
and [upgrade/recovery](security/upgrade-rollback.md). The [October 6 PoC evidence](validation.md)
is historical and describes an earlier, less capable implementation.

## Source and extension evidence

The following observations refer to the **unmodified v18.11.1 baseline**, not to
an assumption that public Teleport contains Enterprise SSO:

| Area | Source evidence | Implication |
| --- | --- | --- |
| Source license | [README license section](../../README.md#license), [LICENSE](../../LICENSE) | The server source is AGPLv3; preserve license notices and provide corresponding source as required by its terms, including the network-use provisions. |
| API module license | [api/LICENSE](../../api/LICENSE) | The API module is Apache-2.0; that does not relicense the server source. |
| Vendor Community Edition binaries | [build.assets/LICENSE-community](../../build.assets/LICENSE-community) | Vendor binaries have a separate modified Apache license with commercial-use restrictions. A source build and a downloaded CE binary are different distributions. |
| OIDC entry points | [lib/auth/oidc.go](../../lib/auth/oidc.go), `OIDCService` and the nil-service rejection | Public source provides the interface and connector storage, but not a working native OIDC login implementation. |
| Connector permissions | [lib/auth/auth_with_roles.go](../../lib/auth/auth_with_roles.go), OIDC create/update/upsert and auth-request methods | Existing resource authorization and administrative MFA checks coexist with Enterprise entitlement checks. Merely changing a feature flag cannot supply the missing protocol implementation. |
| Feature advertisement | [lib/modules/modules.go](../../lib/modules/modules.go), `defaultModules.Features` | The source build does not advertise an OIDC entitlement by default. |
| Existing login integration | [lib/web/apiserver.go](../../lib/web/apiserver.go), [lib/auth/github.go](../../lib/auth/github.go) | Native browser/CLI response helpers, certificate/session issuance, and GitHub login audit conventions can be reused. The missing Keycloak Auth implementation and OIDC proxy handlers still need new code; GitHub authentication cannot validate arbitrary Keycloak tokens. |
| Resource and claim model | [api/types/oidc.go](../../api/types/oidc.go) | A versioned connector resource already exists; the experiment restricts its accepted fields instead of adding a general plugin or a second certificate authority. |

The vendor's [license announcement](https://goteleport.com/blog/teleport-community-license/)
also distinguishes source builds from distributed binaries. The license texts
above govern this checkout; this project does not include Enterprise code or
grant an Enterprise license.

## Supported contract

Set `TELEPORT_UNSTABLE_KEYCLOAK=yes` on Auth and Proxy and point Auth at a private
`TELEPORT_KEYCLOAK_CONFIG` JSON file. Startup fails without valid managed lifecycle
configuration. The name retains the deliberate experimental opt-in; it does not
turn on an Enterprise entitlement. Native RBAC and administrative MFA remain
required for connector/role changes. Callback and IdP notification Auth APIs
accept only authenticated native Proxy identities.

- Confidential authorization-code flow, S256 PKCE, RS256 signature, issuer,
  audience/authorized party, nonce, state and time validation. State is consumed
  atomically in the shared backend. Discovery/token/JWKS endpoints must use
  HTTPS on the configured issuer origin; redirects and unverified TLS are rejected.
- Stable identity is `keycloak-` plus SHA-256 of `issuer + NUL + sub`. Email and
  display names cannot select an account. Conflicting account ownership fails.
- Literal full group paths map to existing static roles. Unmapped users,
  regexes/globs/templates, role impersonation and access-request augmentation fail.
  The Admin API rechecks enabled status and groups at every login.
- Supported resource grants are SSH and Kubernetes. Role v8, strict locking,
  disconnect on expiry and at most five-minute TTL are mandatory. SSH grants
  require explicit unprivileged logins and labels; forwarding/file copy are off.
  Kubernetes grants require explicit labels, users/groups, namespaces and verbs;
  exec requires an exact pod name. App/DB/desktop/cloud/admin grants are rejected.
  See [SSH example](../../examples/keycloak/role.yaml) and
  [Kubernetes example](../../examples/keycloak/kubernetes-role.yaml).
- Teleport signs the normal SSH/TLS credentials. Lifetime is the minimum of
  requested TTL, role TTL, five minutes and ID-token remaining lifetime. Native
  reissue and web renewal preserve the original deadline and role generation.
  Insufficient remaining time for native minimum issuance fails closed; use
  requests of 2–5 minutes. No refresh/offline tokens are retained.
- Every login carries two extra **zero-grant** roles: a unique login marker and
  a connector health marker. Native locks target these markers without adding
  resource privileges. The stored user's roles remain the actual mapped roles.
- Keycloak enforces MFA. The tested realm requires password plus TOTP, with
  wrong password, missing/incorrect OTP and OTP reuse protections retained.
  `prompt=login` alone is not an MFA guarantee. Hardware/WebAuthn enrollment and
  target device behavior require real devices; no hardware attestation is claimed.

## Managed configuration and secrets

An Auth-local example (unusable addresses and no company values):

```json
{
  "revocation_journal_dir": "/var/lib/teleport-revocations",
  "poll_seconds": 5,
  "max_stale_seconds": 30,
  "connectors": {
    "keycloak-lab": {
      "issuer": "https://idp.example.invalid/realms/lab",
      "client_id": "teleport-lab",
      "admin_url": "https://idp-admin.example.invalid:8444/admin/realms/lab",
      "client_secret": {"file": "/var/lib/teleport-secrets/current/oidc-client"},
      "admin_client_id": "teleport-sync",
      "admin_client_secret": {"file": "/var/lib/teleport-secrets/current/sync-client"}
    }
  }
}
```

An optional `ca_file` adds an explicitly trusted CA without disabling verification.
`admin_url` is an explicit Auth-local HTTPS URL ending in the same issuer realm's
`/admin/realms/<realm>` path (and context prefix, if present). It may use a private
origin. Only fixed read-only user/count/group/session paths receive the service
bearer there. User info, query strings, fragments, encoded paths, other realms and
redirects are rejected. Public OIDC discovery/token/JWKS origin restrictions are
unchanged. Network/proxy policy must independently prevent public Admin access;
Keycloak's admin hostname setting alone does not enforce that restriction.

`client_id` must match the native connector. User sessions must contain both the
validated ID-token `sid` and this client ID in the Admin API's client map. Missing
sessions revoke only the affected login generation. An unavailable, oversized or
malformed response fails synchronization; it is never interpreted as logout.
The startup health probe uses `GET /users/count`, including when no logins exist.
These operations use the existing `view-users` service account role.

Secret references contain an absolute private regular `file` and optional
`json_key`; OIDC secrets must be single-line. Cloud-provider fields are rejected
by the managed configuration loader. Put a non-secret sentinel in the native
connector's required `client_secret` field. Errors are redacted. Files are reopened
on use, so rotation needs no Auth restart. Use atomic file replacement or a
private parent-owned generation link; never overwrite a live file partially.
Configuration/CA changes require a controlled restart.

Provisioning, provider SDKs, IAM, rotation orchestration and backup utilities belong
to the deployment repository. This connector needs no AWS credentials, Secrets
Manager, metadata service or provider process. A home deployment must persist its
local secret generation independently of this Auth's availability and `/run`.
Cloud secret refresh failure is distinct from an unavailable authoritative IdP.

## Logout, deactivation, and already issued credentials

| Trigger | Implemented behavior |
| --- | --- |
| Web or `tsh logout` | Revoke the current login marker server-side before local cleanup. A copied session/certificate and its active connections are denied by native locks; another independent login remains valid. If remote revocation cannot be confirmed, cleanup still runs and the caller receives an error. |
| Keycloak back-channel logout | Verify a signed logout JWT, exact event, issuer/audience, recent issue time, no nonce, subject/session and replay identity. Lock all matching existing login generations; fresh authentication is allowed. Identical retries finish idempotently; a changed payload reusing a `jti` fails. |
| Missed Keycloak logout notification | Read-only session reconciliation detects the missing session or client binding and durably revokes matching login markers. Another active session and future authentication remain usable. |
| Group removed | Reconciliation locks affected old login markers. Fresh login may obtain remaining/current mappings. Re-adding a group never unlocks an old marker. |
| Account disabled/deleted | Persist a non-expiring user revocation and native user lock, including after temporary user resources expire. Re-enabling the same IdP subject does **not** reinstate it. |
| Auth restart / restore | Replay retained journal and synchronously create connector guard locks; discard previous health timestamps before serving. Only fresh private Admin probing and account/session reconciliation remove the guards. Native lock propagation to already-running remote agents remains bounded separately. |
| Sync unavailable | New login requires a fresh live check. After configured staleness, a connector marker lock denies existing credentials and closes monitored connections. Recovery verifies client sessions before removing the health lock, never individual revocations. |
| Certificate expiry | Native strict monitors close SSH/Kubernetes connections; old credentials cannot authenticate or extend their original lifetime. |

The candidate intentionally treats account suspension as permanent for that
issuer/subject. It has no same-subject reinstatement API. Reviewed recovery can
onboard a **new Keycloak subject** with fresh MFA and explicit group approval,
while preserving the old subject's lock/history. Do not delete journal entries
or locks to make an old credential work. This conservative policy is an explicit
operational constraint, not automatic reactivation.

Local logout does not redirect the browser through Keycloak RP-initiated logout;
that would also terminate its IdP session. Use Keycloak's session/account logout
for that scope, which delivers the validated back-channel notification. Session polling
provides bounded recovery when the notification path fails. The
[OIDC back-channel specification](https://openid.net/specs/openid-connect-backchannel-1_0.html)
is the notification contract.

Reconciliation uses only Keycloak `view-users` (including online sessions): no realm-admin, writes or client
administration. Passes are bounded, retry with jitter, deduplicate subjects, page
groups completely, and fail closed on partial reads. Metrics expose successful
sync time, allowed staleness and failures; native high-severity cluster alerts
report failures. Runtime logs never include raw IdP responses or secrets.

New login rejects a stale health timestamp immediately. Existing-connection
fencing runs at reconciliation boundaries: an in-flight pass can consume up to
`max_stale_seconds`, followed by up to 1.2 poll intervals and native lock
propagation. Size the formal revocation SLO for that conservative bound, not
just the configured poll interval; credentials independently expire within five
minutes. The local outage measurement is evidence for that fixture, not a
production latency guarantee. Native tsh may retry a disconnected session;
the outage/expiry probes use `--no-resume` to measure actual termination.

## Durability and audit

Use **one Auth instance** for this candidate. The journal must be a mode-0700
directory on separately retained encrypted storage, outside Auth's data directory.
Immutable mode-0600 records are fsynced before native locks are applied; startup
and periodic reconciliation replay them. Account records do not expire; login
marker records outlive their credentials by 24 hours and are then collected.
Atomic callback/replay behavior is concurrency-tested, but HA journal replication
and multi-Auth disaster recovery are outside this single-Auth deployment contract.

An older Auth backup is safe only with the **latest independent journal**.
The private restore tool merges it before starting the candidate. Losing both
state and current revocation history requires isolation and expiration of all
old credentials before recovery. Never open a restored listener first.

Native events cover login success/failure, lock creation/deletion, SSH/Kubernetes
session start/end, Kubernetes requests and recording upload. Login audit failure
denies credential delivery. Native operations outside this callback may log
an audit-sink failure without reversing the operation, so monitor disk/storage
and verify downstream audit retention separately. SSH uses strict node recording;
actual recorded terminal output is replayed in the lab. macOS enhanced BPF
recording is unavailable; standard recording/termination needs target-Mac testing.

## Local build and test entry point

Prerequisites: Docker with ARM64 Linux support, Python 3, OpenSSL, native Go/CGO
prerequisites, and writable task-local `GOMODCACHE`/`GOCACHE`. The source requires
Go 1.25.14. [Toolchain pins](../../build.assets/cooplay/toolchains.json) fix the
Linux builder, Node, Rust, Keycloak and Kubernetes images. Dependency locks are
unchanged. No overlays or placeholder UI are used in candidate artifacts.

```sh
bash build.assets/cooplay/keycloak.sh test
bash build.assets/cooplay/full-build.sh all
python3 build.assets/cooplay/baseline-build.py
python3 build.assets/cooplay/real-keycloak-smoke.py
```

`full-build.sh` builds normal embedded UI and `teleport`, `tsh`, `tctl`
for native macOS ARM64 and pinned Linux ARM64 / AMD64. Deployment helpers
are built and versioned independently in the private platform repository.
Linux includes the upstream embedded session helper. The `ui`, `native`, `linux` (ARM64) and
`linux-amd64` targets may be invoked separately. Each output directory has a manifest
with exact fork revision, dirty status, compiler, lock/asset hashes and every
artifact digest. The older `keycloak.sh build` profile is only a CLI development
build and must not be selected for deployment.

Build the Kubernetes-only nonroot OCI runtime from the verified Linux output:

```sh
docker build --platform=linux/arm64 -f build.assets/cooplay/Dockerfile.kube-agent   -t cooplay-keycloak-agent:local-candidate build/cooplay-candidate/linux-arm64
```

The local tag is for the drill; deployment manifests require an immutable digest.
The host SSH agent uses the native installer because it needs OS user switching.
Do not use the Kubernetes image as a privileged SSH agent.

## Audit and acceptance gates

The local suite uses real Keycloak, Chromium, Linux SSH and disposable Kubernetes.
See [validation evidence](candidate-validation.md) for what actually passed.
Before formal use, supply owned infrastructure, DNS/TLS, IAM/secret references,
reviewed mappings, alert receivers, encrypted storage and backup custody. Enroll
real employees/devices, validate Mac launchd/OS accounts/recording, remove old SSH
keys/shared kubeconfigs through their owners, and perform joint access/revocation/
recovery acceptance with Headscale. No production deployment is authorized here.

If a required capability exceeds this strict SSH/Kubernetes, single-Auth contract,
keep the gate closed. Alternatives include a supported licensed native OIDC
service with separately verified revocation or another maintained access gateway.
Do not restore functionality by broad SSH, shared cluster-admin or entitlement flags.

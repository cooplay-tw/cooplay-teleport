# Local validation — 2026-10-06

Historical PoC evidence. See [the current candidate](candidate-validation.md) for later implementation and validation.

This records local experimental results, not a release or deployment approval.
The checkout is `codex/keycloak-sso-mvp`, based on upstream v18.11.1 at
`27eb07217a0efca4a5d2dd88bce7472cba5f406a`, with uncommitted fork changes.
The ignored build manifest records the tracked patch hash and untracked source
file hashes; the base commit alone does not identify the implemented connector.

## Native tests

On macOS ARM64, with Go 1.25.14 and CGO enabled:

```sh
bash build.assets/cooplay/keycloak.sh test
go test -race -mod=readonly -count=1 ./lib/auth -run '^TestKeycloakAtomicConsume$'
```

Both commands passed. The first runs 22 new top-level `TestKeycloak*` tests
(including their subtests), plus the selected upstream lock, certificate-expiry,
web/application logout, role-request, and ordinary/access-request web renewal
regressions in `lib/auth`, `lib/web`, and `lib/srv`.
The final package results were 2.546s, 10.445s, and 3.129s respectively. The race
test passed in 3.432s; it uses concurrent connector services sharing one test
backend, not a deployed multi-Auth cluster.

The new coverage includes real RSA-signed mock-IdP tokens over verified TLS,
native Auth certificate/session issuance, wrong token bindings and replay,
connector changes and identity collisions, unmapped groups and unsafe roles,
connector RBAC, Proxy-only callback authorization, login CSRF, encrypted console
responses, and audit-emitter failure. Native API tests confirm that resource
certificate reissue stays within the original identity and stored-user expiry,
changes to role membership require a fresh login, and ordinary web renewal stays
bounded. This does not freeze the native definitions of the named roles.
Slow-signer tests advance the clock during real native signing and verify that
overlong credentials are withheld and an overlong renewal is not persisted.
The role-condition test covers every non-SSH allow field and unknown protobuf
fields, and actual login tests reject app/database/Kubernetes grants.

This is focused regression coverage; the complete upstream test suite and online
GitHub Actions have not been run. It does not prove target-node access, active
SSH termination, external audit durability, or recovery.

## Repeated native build

`bash build.assets/cooplay/keycloak.sh build` succeeded twice with the same
runtime source, checkout, environment, and cached Go dependencies. All three
artifact hashes were equal across those builds:

| Artifact | SHA-256 |
| --- | --- |
| `teleport` | `85e41552de4830ca87b33f74e8ef2a00ebfac9556d808e384523b5e6d04a9bf6` |
| `tsh` | `5d11eff9f3c03f8cb2661a5fa922d8444166d93f7b2b163ac9273fce85ff2d28` |
| `tctl` | `3f25481e87d1a63aefb543c00b791945c3f6db91a60f93af704a51fe0fe062e9` |

Compiler: Apple clang 21.0.0 (`clang-2100.1.1.101`), target
`arm64-apple-darwin25.5.0`. Go: `go1.25.14 darwin/arm64`. These are local CLI
evaluation artifacts without bundled UI or hardware MFA, as described in the
[build contract](README.md#local-build-and-test-entry-point). Their manifest is
`build/cooplay-keycloak/manifest.json`. Equality in this environment is not a
clean-room, cross-host, Linux, or complete production-build reproduction.

## Real Keycloak

The separate [protocol harness](real-smoke.md) completed one full successful run
on **2026-10-06 at 14:05:22 UTC**, against real Keycloak **26.8.0** on Linux ARM64
in Docker and native macOS ARM64 Teleport processes. All **24 checks passed**.
The [safe machine-readable report](real-keycloak-result-2026-10-06.json) records
the immutable image digest, source and harness hashes, every check, and cleanup.

The run exercised a real confidential-client code exchange with PKCE over
verified TLS, native `tsh` callback decryption and certificate use, exact group
mapping to one role and Unix login, SSH certificate and temporary-user lifetimes
of at most five minutes, and a native secure HttpOnly web-session cookie.
Unmapped and disabled accounts could not log in. Disabling the mapped Keycloak
account denied a fresh login, while its previously issued credentials continued
working. A copy also continued working after local `tsh logout`.

An explicit, uniquely identified Teleport user lock then denied that copied
credential. Removing only the fixture's lock restored access with the same SSH
and TLS certificate fingerprints while the IdP account remained disabled.
This controlled unlock is a test of causality, not an incident-response procedure.
Native OIDC success/failure and lock-created audit records were present.

These artifacts include two **test-only Go overlays**: a generated fallback CA
root and `DisableWebInterface` with the native authentication API still enabled.
They are separate from the normal CLI evaluation artifacts above:

| Lab artifact or overlay | SHA-256 |
| --- | --- |
| `teleport` | `f88314e0895da6cffd0a3ec6692400179d4acd4a67463a2e81c020ede309501f` |
| `tsh` | `3e87b9ee59428eed46e195ef4698f1717e8953dca245f74f829431b613140979` |
| `tctl` | `99e8bd8186ee108b87538fe43a16332c37376030e9b99741ced5b2e75e295dbd` |
| CA initialization hook | `a2c7efa1a4320500dee013fb54b5dd365b2f0d79cdb176548734d21260f7c7a2` |
| Proxy source overlay | `4377bde996982eb9a0ccb48221c1e6ee854e7280bf10937a4c64e3b280de016a` |

Harness development exposed fixture and assertion errors before that complete
run: unsupported MFA settings, absent UI assets, connector-dependent bootstrap
readiness, an incorrect error-redirect expectation, client error wording, and
immediate reads before native Auth caches observed new users or locks. The
final harness uses supported `second_factor: otp`, the documented no-UI overlay,
fixed native redirect paths, bounded cache waits, and the causal lock check.
The password-only Keycloak fixture does not prove MFA enforcement.

All started processes and the unique container were stopped, and the exact
private credential directory was removed after reviewing the safe result.
An additional inventory found zero fixture containers and directories. No
production deployment or system trust change occurred; the pinned image may
remain in Docker's cache. Unmodified macOS private-CA trust, a complete Web UI
build, target-node access, active sessions, full web-session revocation, MFA,
multi-Auth operation, and durable external audit remain outside this result and
in the [acceptance matrix](README.md#audit-and-acceptance-gates).

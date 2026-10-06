# Reproduce the candidate acceptance lab

Build the [normal full artifacts](README.md#local-build-and-test-entry-point),
then run from this repository:

```sh
python3 build.assets/cooplay/real-keycloak-smoke.py
```

Requirements: ARM64 Docker, Python 3, OpenSSL, Node and Chromium. macOS defaults
to the installed Google Chrome. On Linux install the lockfile-pinned browser:

```sh
node node_modules/.pnpm/playwright@1.62.1/node_modules/playwright/cli.js install --with-deps chromium
```

`--binaries` selects a normal full-UI Linux artifact directory. Every binary must
match its manifest. `--node`/`--browser` select explicit local tools. No source
or UI-disable overlays are used. The result defaults to
`build/cooplay-candidate/real-keycloak-result.json`; failures return nonzero.

The suite runs pinned Keycloak 26.8.0, K3s and Linux processes inside disposable
containers, publishes host ports only on loopback, creates its own non-root SSH
account inside the Linux container, and keeps all fixture passwords/keys/state
in a fresh mode-0700 directory. K3s needs a privileged **disposable container**,
not privileged application pods. The lab mounts only its own directory into
its runner. It changes no host trust store, SSH configuration, user profile,
production realm or existing Docker stack.

An ephemeral CA verifies Python and native Linux HTTPS. Auth uses an explicit
CA file. Chrome accepts only the exact generated leaf SPKI for this fixture;
Node API probes use the CA. No `--insecure` or general certificate-error bypass
is used. Browser passwords and OTP seeds are passed through stdin, never shell
arguments; no browser tracing, HAR or persistent profile is retained.

Checks include real browser and CLI password+OTP, incorrect credentials,
copied-session and copied-certificate logout, independent-login isolation,
least-privilege SSH, disabled/group-removed account synchronization, real signed
Keycloak back-channel logout, fresh login after IdP logout, active SSH and
Kubernetes exec termination, namespace/verb/Secrets/escalation denials, actual
certificate expiry, secret rotation without Auth restart, stale-sync lock and
recovery, native audit events and replay of actual recorded terminal output.
The fixture refuses OTP reuse instead of weakening Keycloak's policy.

The private repo extends this same harness with verified release staging,
encrypted native Auth backup/restore and the latest revocation journal,
unchanged-upstream migration/expiry-gated rollback, and its rendered nonroot
in-cluster agent. It separately exercises real PostgreSQL/Keycloak encrypted
backup/restore and the read-only service account permissions. Company deployment
files and identities never enter this public tree.

The safe result includes check names, booleans, measured timings and build/image
provenance. Raw HTTP responses, tokens, passwords and browser state are excluded.
Native logs/recordings contain lab identity data and stay in the temporary
private directory. Normal cleanup removes processes, containers and private
workdirs. `--keep-private-workdir` is for diagnosis only: delete that exact
credential-bearing directory afterward. Shared Docker image caches remain.

[Current evidence](candidate-validation.md) distinguishes executed tests from
formal acceptance. The [October 6 result](real-keycloak-result-2026-10-06.json)
is historical PoC evidence and must not be mistaken for this suite's behavior.

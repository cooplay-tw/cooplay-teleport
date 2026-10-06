# Upgrade and rollback

This procedure accompanies the [candidate contract](../README.md). Production
activation is outside the local implementation task. One Auth instance, a
separately retained encrypted revocation journal, and independent recovery
administration are required.

## Fixed inputs and release staging

Use the exact public fork commit, unchanged dependency locks, pinned Go/Linux
builder/UI toolchain and normal full-UI recipe. Preserve LICENSE and third-party
notices plus corresponding source. The manifest records source revision, dirty
state, compiler, dependency/asset hashes and all five binary hashes. The private
installer requires an **independently pinned manifest SHA-256**, matching host
platform, clean source and exact artifact hashes, and writes a new release only.
A local `--allow-dirty-lab` exception cannot be used as release provenance.

Repeat UI and binary builds and compare hashes. Same-host equality is evidence
for the recorded inputs; it is not a claim of cross-compiler or cross-OS identity.
The CI workflow records the same checks but a workflow file is not a hosted CI
run. Keep previous source, manifest, configuration and encrypted backup available.

Before rebasing, inspect upstream changes to OIDC interfaces, connector RBAC and
admin MFA, callback routing, certificate/WebSession issuance, role defaults,
lock watchers, audit and Kubernetes authorization. Keep this implementation in
its own files and narrow native hooks. Never resolve a conflict by enabling an
Enterprise entitlement or deleting authorization. Recheck source licenses,
supported releases/tags and advisories; rerun all affected tests and the real lab.
Keycloak upgrades are a separate controlled variable.

## Encrypted backup and native restore

The private `snapshot.py` stops short of service activation. Stop the exact Auth
process, verify it is gone, and use a clean artifact manifest. The tool rejects a
live PID, arbitrary symlinks/special files and existing output. The upstream
leftover `debug.sock` and the validated `log/events.log` alias are omitted; their
real persistent audit files are included. Archives are age-authenticated and
include a per-file SHA-256 inventory. Encryption identities belong in independent
recovery custody, never Git or the archive itself.

Restore into a **new isolated directory**. Require the current independently
retained journal, validate its immutable entries, merge newer revocations and
reject conflicting history. Point the restored Auth at that merged journal.
Startup synchronously replays native locks before serving; the loop repairs them
thereafter. Verify a still-valid revoked credential is denied and an unrevoked
credential still identifies the same cluster CA. The private real drill performs
both checks against an old native database snapshot.

PostgreSQL uses its own custom-format `pg_dump` encrypted with the same helper.
The private restore script refuses a nonempty target DB and is tested against a
second fresh Keycloak/PostgreSQL stack. Restore verification includes the real
realm and HTTPS startup, not only decryption success.

## Rollback preserves the security boundary

Switching binaries, deleting local credentials, stopping new SSO, or restoring
an old database does **not** revoke issued certificates. The unmodified upstream
has no Keycloak connector or custom journal replayer. Its native locks still
work, but do not assume a restored database contains the latest ones.

For a rollback that removes this connector:

1. Close the affected ingress and stop all credential issuers. Preserve current
   audit data and the latest journal. Confirm active sessions are stopped.
2. If reverting to an earlier lifecycle-capable candidate, use matching state,
   source and configuration plus the latest journal and verify all denials before
   reopening. Follow the specific upstream migration rules for version changes.
3. For unchanged upstream or a missing/corrupt latest journal, keep the service
   isolated for **every possible credential's remaining lifetime plus clock
   margin**. The isolated drill waits 330 seconds after stopping issuance, only
   because its entire cluster uses the proven five-minute cap. An existing
   company cluster needs an inventory of older/other-connector credentials.
4. Start the verified upstream binary with local recovery authentication and
   Keycloak SSO disabled. Verify old credentials fail and recovery access remains
   controlled. Do not create broad SSH or shared administrator access.

`baseline-build.py` builds the unchanged v18.11.1 server with the same normal
assets/toolchain. The private migration drill starts that server, activates the
verified staged candidate, exercises real SSO/revocation/recovery, then performs
the stopped-issuance expiry barrier and starts unchanged upstream again. This
validates removal of this patch on the **same upstream version**. A future
v18→v19 database downgrade needs a new version-specific drill.

Account suspension remains permanent for the old issuer/subject. Re-enabling it
or deleting a native lock cannot erase its journal record. A reviewed new-subject
onboarding preserves the old history and requires fresh MFA/group approval.

#!/usr/bin/env python3
"""Record exact local build provenance without reading runtime configuration."""
import argparse
import hashlib
import json
import pathlib
import subprocess

root = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--output", type=pathlib.Path, default=root / "build/cooplay-keycloak")
parser.add_argument("--profile", default="local-evaluation-no-bundled-ui-no-hardware-mfa")
args = parser.parse_args()
out = args.output



def command(*args):
    return subprocess.check_output(args, cwd=root, text=True).strip()


manifest = {
    "upstream": json.loads((root / "build.assets/cooplay/upstream.json").read_text()),
    "fork_revision": command("git", "rev-parse", "HEAD"),
    "dirty": bool(command("git", "status", "--porcelain")),
    "profile": args.profile,
    "go_version": command("go", "version"),
    "go_environment": json.loads(command("go", "env", "-json", "GOOS", "GOARCH", "CGO_ENABLED", "CC")),
    "compiler": command("cc", "--version"),
    "tracked_patch_sha256": hashlib.sha256(subprocess.check_output(["git", "diff", "--binary", "HEAD"], cwd=root)).hexdigest(),
    "dependency_locks": {},
    "untracked_source_sha256": {},
    "artifacts": {},
}
for name in ("go.mod", "go.sum", "api/go.mod", "api/go.sum", "pnpm-lock.yaml", "Cargo.lock", "rust-toolchain.toml", "build.assets/cooplay/toolchains.json"):
    manifest["dependency_locks"][name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
for name in command("git", "ls-files", "--others", "--exclude-standard").splitlines():
    path = root / name
    if path.is_file():
        manifest["untracked_source_sha256"][name] = hashlib.sha256(path.read_bytes()).hexdigest()
for name in ("teleport", "tsh", "tctl", "cooplay-secrets", "cooplay-backup"):
    if not (out / name).exists():
        continue
    path = out / name
    with path.open("rb") as artifact:
        manifest["artifacts"][name] = {
            "sha256": hashlib.file_digest(artifact, "sha256").hexdigest(),
            "bytes": path.stat().st_size,
        }
if args.profile == "full-ui-keycloak-candidate":
    manifest["webassets"] = {str(path.relative_to(root / "webassets")): hashlib.sha256(path.read_bytes()).hexdigest()
                             for path in sorted((root / "webassets/teleport").rglob("*")) if path.is_file()}
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("Build provenance:", out / "manifest.json")

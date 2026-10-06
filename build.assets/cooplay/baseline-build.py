#!/usr/bin/env python3
"""Build the unmodified pinned upstream server for isolated migration drills."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

repo=Path(__file__).resolve().parents[2]
pin=json.loads((repo/'build.assets/cooplay/upstream.json').read_text())
image=json.loads((repo/'build.assets/cooplay/toolchains.json').read_text())['ui_linux_arm64']
out=repo/'build/cooplay-upstream';out.mkdir(parents=True,exist_ok=True)
gomod=Path(os.environ['GOMODCACHE']);cache=Path(os.environ['GOCACHE'])/'linux-arm64'
toolchain=gomod/'golang.org/toolchain@v0.0.1-go1.25.14.linux-arm64'
with tempfile.TemporaryDirectory(prefix='cooplay-upstream-') as td:
    source=Path(td)
    archive=subprocess.Popen(['git','archive',pin['commit']],cwd=repo,stdout=subprocess.PIPE)
    subprocess.run(['tar','-x','-C',td],stdin=archive.stdout,check=True)
    archive.stdout.close()
    if archive.wait():raise SystemExit('upstream source export failed')
    for path in ('webassets/teleport','session/reexec/embed'):
        shutil.copytree(repo/path,source/path,dirs_exist_ok=True)
    subprocess.run(['docker','run','--rm','--platform=linux/arm64',
       '--mount',f'type=bind,source={source},target=/workspace','--workdir=/workspace',
       '--mount',f'type=bind,source={out},target=/out',
       '--mount',f'type=bind,source={toolchain},target=/opt/go,readonly',
       '--mount',f'type=bind,source={gomod},target=/gomod','--mount',f'type=bind,source={cache},target=/gocache',
       '--env','GOROOT=/opt/go','--env','GOMODCACHE=/gomod','--env','GOCACHE=/gocache','--env','GOTOOLCHAIN=go1.25.14',
       '--env','PATH=/opt/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',image,
       'go','build','-p=4','-mod=readonly','-trimpath','-buildvcs=false',
       '-tags=webassets_embed,sessionhelper_embed,kustomize_disable_go_plugin_support',
       '-ldflags','-X github.com/gravitational/teleport.Gitref='+pin['commit'],
       '-o','/out/teleport','./tool/teleport'],check=True)
with (out/'teleport').open('rb') as f: digest=hashlib.file_digest(f,'sha256').hexdigest()
(out/'manifest.json').write_text(json.dumps({'upstream':pin,'teleport_sha256':digest,'builder':image,'go':'go1.25.14'},indent=2)+'\n')
print('Built unchanged upstream server for local migration validation.')

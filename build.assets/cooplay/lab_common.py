#!/usr/bin/env python3
"""Isolated real-Keycloak/native-Teleport protocol smoke test, never production.

Subprocess output and HTTP state stay in memory. Keys, profiles and fixture
passwords are private credential files, never diagnostic logs.
"""
# Copyright 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import datetime as dt
import hashlib
import html.parser
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "26.8.0"
DIGEST = "sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc"
IMAGE = "quay.io/keycloak/keycloak@" + DIGEST
REPO = Path(__file__).resolve().parents[2]


class Failure(Exception):
    """Only fixed, non-secret messages may be exposed."""


class Page(html.parser.HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.action = None
        self.fields = {}
        self.redirect = None
        self.feed(body)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") in ("kc-form-login", "kc-otp-login-form") :
            self.action = attrs.get("action")
        if tag == "input" and attrs.get("type") == "hidden" and attrs.get("name"):
            self.fields[attrs["name"]] = attrs.get("value", "")
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"url\s*=\s*(.*)", attrs.get("content", ""), re.I)
            if match:
                self.redirect = match[1].strip("\"'")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Lab:
    @property
    def stage(self):
        return self._stage

    @stage.setter
    def stage(self, value):
        self._stage = value
        print('Local verification stage: ' + value, file=sys.stderr, flush=True)

    def __init__(self, args):
        self.args = args
        self.root = Path(tempfile.mkdtemp(prefix="cooplay-keycloak-smoke-", dir="/private/tmp" if sys.platform == "darwin" else "/tmp"))
        self.root.chmod(0o700)
        self.stage = "prepare"
        self.processes = []
        self.outputs = {}
        self.readers = []
        self.container = "cooplay-keycloak-smoke-" + secrets.token_hex(6)
        self.created = False
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("TELEPORT_") and k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID")}
        self.env.update(TELEPORT_UNSTABLE_KEYCLOAK="yes", TELEPORT_HOME=str(self.root / "profile"),
                        TELEPORT_ADD_KEYS_TO_AGENT="no", KUBECONFIG=str(self.root / "kubeconfig"), GOTOOLCHAIN="go1.25.14")
        self.result = {"keycloak_version": VERSION, "keycloak_image": IMAGE, "checks": {}}
        ports = set()
        while len(ports) < 5: ports.add(port())
        self.kcport, self.proxyport, self.authport, self.sshport, self.tunnelport = sorted(ports)
        self.idp = f"https://127.0.0.1:{self.kcport}"
        self.proxy = f"https://127.0.0.1:{self.proxyport}"
        self.issuer = self.idp + "/realms/cooplay-smoke"
        self.password = secrets.token_urlsafe(32)
        self.admin_password = secrets.token_urlsafe(32)
        self.client_secret = secrets.token_urlsafe(32)
        self.log = open(self.root / "commands.log", "ab", buffering=0)

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        path.chmod(0o600)
        return path

    def run(self, cmd, *, env=None, timeout=120, check=True):
        p = subprocess.run([str(v) for v in cmd], cwd=REPO, env=env or self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        self.log.write((self.stage + ": exit " + str(p.returncode) + "\n").encode())
        if check and p.returncode:
            self.result["failed_command"] = Path(cmd[0]).name
            self.result["failed_command_exit"] = p.returncode
            if len(cmd) > 1 and str(cmd[0]) == "docker" and cmd[1] == "start":
                raise Failure("disposable container startup failed: " + p.stderr.decode(errors="replace")[:1200])
            raise Failure("subprocess failed at " + self.stage)
        return p

    def check(self, name, ok):
        self.result["checks"][name] = bool(ok)
        if not ok:
            raise Failure("check failed: " + name)

    def setup(self):
        self.stage = "generate ephemeral TLS CA"
        self.write("openssl.cnf", """[req]
distinguished_name=dn
prompt=no
[dn]
CN=Cooplay disposable protocol test
[ca]
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:cooplay-proxy.test,IP:127.0.0.1
""")
        c = self.root / "openssl.cnf"
        self.run(["openssl", "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                  "-config", c, "-extensions", "ca", "-keyout", self.root / "ca.key", "-out", self.root / "ca.crt"])
        self.run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-config", c,
                  "-keyout", self.root / "server.key", "-out", self.root / "server.csr"])
        self.run(["openssl", "x509", "-req", "-days", "2", "-in", self.root / "server.csr", "-CA", self.root / "ca.crt",
                  "-CAkey", self.root / "ca.key", "-CAcreateserial", "-extfile", c, "-extensions", "server", "-out", self.root / "server.crt"])
        self.env.update(SSL_CERT_FILE=str(self.root / "ca.crt"), )
        self.ssl = ssl.create_default_context(cafile=str(self.root / "ca.crt"))
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.ssl))
        self.build()
        self.start_keycloak()
        self.start_teleport()

    def build(self):
        raise NotImplementedError("Use the candidate harness with normal artifacts")

    def realm_fixture(self, fixture):
        return fixture

    def keycloak_ready(self):
        """Private deployment drills can start explicit HTTPS gateways here."""

    def keycloak_port_options(self):
        return ["--publish", f"127.0.0.1:{self.kcport}:{self.kcport}", "--publish", f"127.0.0.1:{self.proxyport}:{self.proxyport}"]

    def start_keycloak(self):
        self.stage = "start digest-pinned Keycloak"
        fixture = {"realm": "cooplay-smoke", "enabled": True, "sslRequired": "all", "accessTokenLifespan": 300,
                   "registrationAllowed": False, "resetPasswordAllowed": False,
                   "groups": [{"name": "lab", "subGroups": [{"name": "teleport-ssh"}]}],
                   "clients": [{"clientId": "teleport-smoke", "secret": self.client_secret, "protocol": "openid-connect",
                                "publicClient": False, "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                                "redirectUris": [self.proxy + "/v1/webapi/oidc/callback"],
                                "attributes": {"pkce.code.challenge.method": "S256"},
                                "defaultClientScopes": ["profile", "email"],
                                "protocolMappers": [{"name": "groups", "protocol": "openid-connect",
                                                     "protocolMapper": "oidc-group-membership-mapper",
                                                     "config": {"claim.name": "groups", "full.path": "true", "id.token.claim": "true", "access.token.claim": "false"}}]}],
                   "users": [{"username": name, "enabled": enabled, "email": name + "@example.invalid", "emailVerified": True,
                              "firstName": "Lab", "lastName": "Fixture", "requiredActions": [], "groups": groups,
                              "credentials": [{"type": "password", "value": self.password, "temporary": False}]}
                             for name, enabled, groups in [("allowed", True, ["/lab/teleport-ssh"]), ("unmapped", True, []), ("disabled", False, ["/lab/teleport-ssh"])]]}
        fixture = self.realm_fixture(fixture)
        self.write("kc/realm.json", fixture)
        for name in ("server.key", "server.crt", "ca.crt"):
            shutil.copyfile(self.root / name, self.root / "kc" / name)
            (self.root / "kc" / name).chmod(0o600)
        envfile = self.write("kc.env", "KC_BOOTSTRAP_ADMIN_USERNAME=lab-admin\nKC_BOOTSTRAP_ADMIN_PASSWORD=" + self.admin_password + "\n")
        self.run(["docker", "pull", IMAGE], timeout=600)
        image = json.loads(self.run(["docker", "image", "inspect", IMAGE]).stdout)[0]
        self.check("container_digest_matches_pin", IMAGE in image["RepoDigests"])
        self.result["keycloak_image_id"] = image["Id"]
        self.result["keycloak_architecture"] = image["Architecture"]
        # The default unprivileged image user starts only after the copied
        # private fixture is assigned to its UID. No host directory is mounted.
        command = "while [ ! -e /tmp/cooplay-ready ]; do sleep 0.1; done; exec /opt/keycloak/bin/kc.sh start-dev --http-enabled=false --https-port=" + str(getattr(self,"keycloak_backend_port",self.kcport)) + " --hostname=" + self.idp + " --truststore-paths=/tmp/cooplay-keycloak/ca.crt --https-certificate-file=/tmp/cooplay-keycloak/server.crt --https-certificate-key-file=/tmp/cooplay-keycloak/server.key --import-realm"
        self.run(["docker", "create", "--name", self.container, "--memory=1g", *self.keycloak_port_options(),
                  "--env-file", envfile, "--entrypoint=/bin/bash", IMAGE, "-c", command])
        self.created = True
        self.run(["docker", "cp", self.root / "kc", self.container + ":/tmp/cooplay-keycloak"])
        self.run(["docker", "start", self.container])
        self.run(["docker", "exec", "--user=0", self.container, "/bin/bash", "-c",
                  "mkdir -p /opt/keycloak/data/import && cp /tmp/cooplay-keycloak/realm.json /opt/keycloak/data/import/realm.json && chown -R 1000:0 /tmp/cooplay-keycloak /opt/keycloak/data/import && touch /tmp/cooplay-ready"])
        self.keycloak_ready()
        self.wait_http(self.issuer + "/.well-known/openid-configuration", 180)
        self.check("real_issuer_discovery_verified_tls", True)

    def start(self, cmd, logfile, env=None):
        process = subprocess.Popen([str(v) for v in cmd], cwd=REPO, env=env or self.env,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.outputs[process.pid] = bytearray()
        def collect():
            while True:
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                self.outputs[process.pid].extend(chunk)
                if len(self.outputs[process.pid]) > 4 * 1024 * 1024:
                    del self.outputs[process.pid][:-2 * 1024 * 1024]
        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        self.readers.append(reader)
        self.processes.append(process)
        return process

    def browser(self, csrf=None):
        jar = http.cookiejar.CookieJar()
        if csrf:
            jar.set_cookie(http.cookiejar.Cookie(0, "__Host-grv_csrf", csrf, None, False, "127.0.0.1", False, False, "/", True, True, None, True, None, None, {}))
        return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=self.ssl), urllib.request.HTTPCookieProcessor(jar)), jar

    def wait_http(self, url, timeout):
        self.log.write((self.stage + ": waiting for HTTPS readiness\n").encode())
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            # Denial/expiry probes intentionally exit nonzero. Only the active
            # server determines readiness, including after upgrade or rollback.
            process = getattr(self, "teleport", None)
            if process is not None and process.poll() is not None:
                self.result["failed_process_exit"] = process.returncode
                if self.args.keep_private_workdir:
                    self.write("failed-server-private.log", bytes(self.outputs[process.pid]).decode(errors="replace"))
                raise Failure("native server exited before readiness")
            try:
                with self.http.open(url, timeout=3) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.5)
        raise Failure("HTTPS readiness timeout at " + self.stage)

    def login_form(self, browser, initial, username):
        with browser.open(initial, timeout=30) as response:
            page = Page(response.read().decode())
        if not page.action or not page.action.startswith(self.idp + "/"):
            raise Failure("expected real Keycloak login form")
        fields = dict(page.fields, username=username, password=self.password, credentialId="")
        request = urllib.request.Request(page.action, urllib.parse.urlencode(fields).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        with browser.open(request, timeout=30) as response:
            return Page(response.read().decode()), response.geturl()

    def web_login(self, username):
        browser, jar = self.browser(secrets.token_hex(32))
        query = urllib.parse.urlencode({"connector_id": "keycloak-lab", "redirect_url": "/web"})
        page, final = self.login_form(browser, self.proxy + "/v1/webapi/oidc/login/web?" + query, username)
        sessions = [c for c in jar if c.name == "__Host-session"]
        return page, sessions, final

    def admin(self, path, method="GET", payload=None):
        if not hasattr(self, "admin_token") or time.monotonic() >= self.admin_token_until:
            form = urllib.parse.urlencode({"client_id": "admin-cli", "grant_type": "password", "username": "lab-admin", "password": self.admin_password}).encode()
            request = urllib.request.Request(getattr(self,"operator_idp",self.idp) + "/realms/master/protocol/openid-connect/token", form)
            with self.http.open(request, timeout=30) as response:
                value = json.load(response)
                self.admin_token = value["access_token"]
                self.admin_token_until = time.monotonic() + max(1, value["expires_in"] - 10)
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(getattr(self,"operator_idp",self.idp) + "/admin/realms/cooplay-smoke/" + path, data, method=method,
                                         headers={"Authorization": "Bearer " + self.admin_token, "Content-Type": "application/json"})
        with self.http.open(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None

    def cleanup(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for reader in self.readers:
            reader.join(timeout=5)
        self.result["cleanup_processes_stopped"] = all(process.poll() is not None for process in self.processes)
        if self.created:
            removed = self.run(["docker", "rm", "--force", self.container], check=False)
            self.result["cleanup_container_removed"] = removed.returncode == 0
            if removed.returncode:
                self.result["container_requiring_cleanup"] = self.container
                raise Failure("container cleanup failed")
        self.log.close()
        if self.args.keep_private_workdir:
            self.result["private_workdir"] = str(self.root)
        else:
            shutil.rmtree(self.root)
        self.result["cleanup_private_workdir_removed"] = not self.root.exists()

# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real expiry, secret rotation, fail-closed outage and recording probes."""
import datetime as dt
import json
import os
import secrets
import time
from pathlib import Path
import subprocess
import re
from lab_common import Failure


class LifecycleLab:
    def atomic_secret(self, name, value):
        path = self.write(name + '.next', value)
        os.replace(path, self.root / name)

    def start_recorded_ssh(self, env, marker, duration=120):
        process = self.start([self.root/'bin/tsh', 'ssh', '--no-resume', '-t', 'lab-user@keycloak-smoke',
                              'echo '+marker+'; sleep '+str(duration)], marker, env)
        deadline = time.monotonic()+20
        while marker.encode() not in self.outputs[process.pid]:
            if process.poll() is not None or time.monotonic()>deadline:
                raise Failure('recorded SSH command did not start')
            time.sleep(.1)
        return process

    def start_expiry_probe(self):
        self.expiry_env = self.cli_login('expiry-user', ttl=2)
        status = json.loads(self.run([self.root/'bin/tsh','status','--format=json'],env=self.expiry_env).stdout)['active']
        self.expiry_deadline = dt.datetime.fromisoformat(status['valid_until'].replace('Z','+00:00'))
        self.check('requested_two_minute_certificate_bound', 0 < (self.expiry_deadline-dt.datetime.now(dt.timezone.utc)).total_seconds() <= 121)
        self.expiry_session = self.start_recorded_ssh(self.expiry_env, 'EXPIRY_SESSION_READY', 180)
        # Probe the real Auth mutual-TLS listener so native tsh cannot turn an
        # expected expiration denial into an interactive fresh SSO ceremony.
        profile=Path(self.expiry_env['TELEPORT_HOME'])
        keys=next(p for p in (profile/'keys').iterdir() if p.is_dir() and list(p.glob('*.crt')))
        self.expiry_tls=(next(keys.glob('*.key')),next(keys.glob('*.crt')),keys/'certs.pem')
        self.check('explicit_expiry_probe_valid_before_expiry',self.expiry_request().returncode==0)

    def expiry_request(self):
        code='''import socket,ssl,sys
try:
 c=ssl.create_default_context(cafile=sys.argv[3]);c.load_cert_chain(sys.argv[2],sys.argv[1])
 with c.wrap_socket(socket.create_connection(('127.0.0.1',int(sys.argv[4])),timeout=5),server_hostname='teleport.cluster.local') as s:
  s.sendall(b'GET /v1/domain HTTP/1.1\\r\\nHost: teleport.cluster.local\\r\\nConnection: close\\r\\n\\r\\n')
  data=s.recv(4096)
  sys.exit(0 if data.startswith(b'HTTP/1.1 ') and b'403' not in data.split(b'\\r\\n')[0] and b'401' not in data.split(b'\\r\\n')[0] else 1)
except (OSError,ssl.SSLError):sys.exit(1)
'''
        return self.run(['docker','exec',self.runner,'python3','-c',code,*self.expiry_tls,str(self.authport)],check=False,timeout=15)

    def exercise_lifecycle(self):
        self.stage = 'actual certificate expiry'
        remaining = max(0,(self.expiry_deadline-dt.datetime.now(dt.timezone.utc)).total_seconds())
        self.check('expired_certificate_active_ssh_disconnected',self.expiry_session.wait(timeout=remaining+15)!=0)
        self.check('expired_certificate_new_request_denied',self.expiry_request().returncode!=0)
        self.stage = 'secret rotation and synchronization outage'
        env = self.cli_login('rotation-user')
        process = self.start_recorded_ssh(env, 'OUTAGE_SESSION_READY')
        self.atomic_secret('sync.secret', secrets.token_urlsafe(32))
        self.result['sync_outage_denial_seconds'] = self.wait_denied(env,seconds=15)
        self.check('stale_sync_active_ssh_disconnected',process.wait(timeout=15)!=0)
        locks = json.loads(self.tctl('get','locks','--format=json').stdout)
        self.check('outage_native_guard_lock',any(x['metadata']['name'].startswith('keycloak-health-') for x in locks))
        metrics=self.run(['docker','exec',self.runner,'python3','-c',"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:3000/metrics',timeout=5).read().decode())"]).stdout.decode()
        failures=re.search(r'^teleport_keycloak_sync_failures_total ([0-9.e+]+)$',metrics,re.M)
        self.check('sync_failure_metrics_exported',failures is not None and float(failures[1])>0 and 'teleport_keycloak_max_stale_seconds' in metrics and 'teleport_keycloak_last_successful_sync_timestamp_seconds' in metrics)
        # Rotate the actual IdP credentials, then publish the new file reference.
        # No Auth restart and no credentials in command arguments or evidence.
        for client_id, filename in (('teleport-sync','sync.secret'),('teleport-smoke','client.secret')):
            client = self.admin('clients?clientId='+client_id)[0]
            value = self.admin('clients/'+client['id']+'/client-secret','POST')['value']
            self.atomic_secret(filename,value)
        deadline = time.monotonic()+20
        while self.run([self.root/'bin/tsh','ls','--format=json'],env=env,check=False).returncode:
            if time.monotonic()>deadline: raise Failure('rotated synchronization credential did not recover')
            time.sleep(.25)
        self.check('rotated_sync_secret_recovers_without_restart',True)
        self.cli_login('rotation-user','-rotated')
        self.check('rotated_oidc_secret_login_without_restart',True)
        self.stage = 'real IdP rejection of disabled and unmapped identities'
        for username in ('disabled','unmapped'):
            _,sessions,_ = self.web_login(username)
            self.check('real_'+username+'_login_denied',not sessions)

    def check_recordings(self, events):
        self.check('kube_request_audit',any(e.get('event')=='kube.request' for e in events))
        self.check('kube_session_end_audit',any(e.get('event')=='session.end' and e.get('proto')=='kube' for e in events))
        recordings = list((getattr(self,'audit_data',self.root/'data')/'log/records').glob('*.tar'))
        found = False
        for path in recordings:
            result = self.run([self.root/'bin/tsh','play','--format=text',path])
            found |= b'COOPLAY_SESSION_READY' in result.stdout
        self.check('ssh_recording_contains_actual_terminal_output',found)
        self.check('ssh_recording_uploaded_audit',any(e.get('event')=='session.upload' for e in events))

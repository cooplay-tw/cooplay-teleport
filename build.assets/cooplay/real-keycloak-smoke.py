#!/usr/bin/env python3
# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Real Keycloak + normal full-UI Linux artifacts in disposable containers.

All listeners published to the host bind loopback. No host SSH, trust store,
Kubernetes configuration, production identity, or existing Docker stack changes.
"""
import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import subprocess
import sys
import time
import traceback
import urllib.parse
import urllib.request

from lab_common import Lab, Page, Failure, REPO, sha
from kube_lab import KubernetesLab
from lifecycle_lab import LifecycleLab

PINS=json.loads((REPO/'build.assets/cooplay/toolchains.json').read_text())

class CandidateLab(LifecycleLab, KubernetesLab, Lab):
    def __init__(self,args):
        super().__init__(args)
        self.runner=self.container+'-linux'
        self.runner_created=False
        self.extra_containers=[]
        self.sync_secret=secrets.token_urlsafe(32)
        self.otp_secret=base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
        self.profiles={}
        self.last_otp_period={}
        self.result.update(trust_profile='normal Linux artifact with SSL_CERT_FILE; Auth uses explicit private CA; no source overlay',
                           proxy_profile='normal full bundled Web UI', limitations=['no production deployment','target Mac launchd, OS privileges and hardware keys require target-device acceptance'])
    def build(self):
        self.stage='verify normal candidate artifacts'
        manifest=json.loads((self.args.binaries/'manifest.json').read_text())
        self.check('full_ui_artifact_profile',manifest['profile']=='full-ui-keycloak-candidate' and bool(manifest.get('webassets')))
        self.check('linux_arm64_artifacts',manifest['go_environment']['GOOS']=='linux' and manifest['go_environment']['GOARCH']=='arm64')
        (self.root/'bin').mkdir(mode=0o700)
        for binary,entry in manifest['artifacts'].items():
            source=self.args.binaries/binary
            self.check('digest_'+binary,sha(source)==entry['sha256'])
            shutil.copyfile(source,self.root/'bin'/binary); (self.root/'bin'/binary).chmod(0o755)
        self.result['build_manifest']=manifest
        self.write('manifest.json',manifest)
    def realm_fixture(self,fixture):
        fixture.update(eventsEnabled=True,adminEventsEnabled=True,adminEventsDetailsEnabled=False,
                       browserFlow='lab-browser-mfa',otpPolicyType='totp',otpPolicyAlgorithm='HmacSHA1',otpPolicyDigits=6,otpPolicyPeriod=30,
                       authenticationFlows=[{'alias':'lab-browser-mfa','providerId':'basic-flow','topLevel':True,'builtIn':False,
                                             'authenticationExecutions':[{'authenticator':'auth-username-password-form','requirement':'REQUIRED','priority':10,'authenticatorFlow':False},
                                                                         {'authenticator':'auth-otp-form','requirement':'REQUIRED','priority':20,'authenticatorFlow':False}]}])
        fixture['clients'][0]['attributes'].update({'backchannel.logout.url':getattr(self,'logout_url',self.proxy+'/v1/webapi/oidc/logout/keycloak-lab'),
                                                    'backchannel.logout.session.required':'true'})
        fixture['clients'].append({'clientId':'teleport-sync','secret':self.sync_secret,'protocol':'openid-connect','publicClient':False,
                                   'standardFlowEnabled':False,'directAccessGrantsEnabled':False,'serviceAccountsEnabled':True,'fullScopeAllowed':True,'defaultClientScopes':['roles']})
        fixture['groups'][0]['subGroups'].append({'name':'teleport-kube'})
        original=fixture['users'][0]
        for name in ('logout-user','group-user','kube-user','sso-user','web-user','expiry-user','rotation-user'):
            user=json.loads(json.dumps(original)); user['username']=name; user['email']=name+'@example.invalid'; fixture['users'].append(user)
        for user in fixture['users']:
            if user['username']=='kube-user': user['groups']=['/lab/teleport-kube']
            user['credentials'].append({'type':'otp','secretData':json.dumps({'value':self.otp_secret}),
                                        'credentialData':json.dumps({'subType':'totp','digits':6,'counter':0,'period':30,'algorithm':'HmacSHA1','secretEncoding':'BASE32'})})
        fixture['users'].append({'username':'service-account-teleport-sync','enabled':True,'serviceAccountClientId':'teleport-sync','clientRoles':{'realm-management':['view-users']}})
        return fixture
    def command(self,cmd,env):
        if self.runner_created and str(cmd[0]).startswith(str(self.root/'bin')+'/'):
            passthrough=('TELEPORT_UNSTABLE_KEYCLOAK','TELEPORT_KEYCLOAK_CONFIG','TELEPORT_HOME','TELEPORT_ADD_KEYS_TO_AGENT','KUBECONFIG','SSL_CERT_FILE')
            wrapped=['docker','exec']
            for name in passthrough:
                if name in env: wrapped += ['--env',name+'='+env[name]]
            return wrapped+[self.runner,*map(str,cmd)]
        return cmd
    def run(self,cmd,*,env=None,timeout=120,check=True):
        return super().run(self.command(cmd,env or self.env),env=env,timeout=timeout,check=check)
    def start(self,cmd,logfile,env=None):
        return super().start(self.command(cmd,env or self.env),logfile,env)
    def start_teleport(self):
        self.start_kubernetes(PINS)
        self.stage='start normal Linux Auth Proxy and SSH'
        self.run(['docker','run','--detach','--name',self.runner,'--network','container:'+self.container,'--user=0',
                  '--mount','type=bind,source='+str(self.root)+',target='+str(self.root),'--entrypoint=/bin/sleep',PINS['ui_linux_arm64'],'infinity'])
        self.runner_created=True
        self.run(['docker','exec',self.runner,'sh','-c',"printf '\\n127.0.0.1 cooplay-proxy.test\\n' >> /etc/hosts"])
        self.run(['docker','exec',self.runner,'useradd','--create-home','--shell','/bin/sh','lab-user'])
        self.run(['docker','exec',self.runner,'passwd','--delete','lab-user'])
        client=self.write('client.secret',self.client_secret); sync=self.write('sync.secret',self.sync_secret)
        lifecycle=self.write('lifecycle.json',{'ca_file':str(self.root/'ca.crt'),'poll_seconds':1,'max_stale_seconds':5,'revocation_journal_dir':str(self.root/'revocations'),
            'connectors':{'keycloak-lab':{'issuer':self.issuer,'client_id':'teleport-smoke','admin_url':getattr(self,'private_admin_url',self.idp+'/admin/realms/cooplay-smoke'),'client_secret':{'file':str(client)},'admin_client_id':'teleport-sync','admin_client_secret':{'file':str(sync)}}}})
        self.env['TELEPORT_KEYCLOAK_CONFIG']=str(lifecycle)
        config={'version':'v3','teleport':{'nodename':'keycloak-smoke','data_dir':str(self.root/'data'),'pid_file':str(self.root/'data/teleport.pid'),'diag_addr':'127.0.0.1:3000','log':{'output':'stderr','severity':'INFO'}},
          'auth_service':{'enabled':True,'cluster_name':'cooplay-keycloak-smoke','listen_addr':f'127.0.0.1:{self.authport}',
                          'authentication':{'type':'oidc','connector_name':'keycloak-lab','second_factor':'otp'},'proxy_listener_mode':'multiplex','session_recording':'node-sync'},
          'proxy_service':{'enabled':True,'web_listen_addr':f'0.0.0.0:{self.proxyport}','public_addr':[f'cooplay-proxy.test:{self.proxyport}',f'127.0.0.1:{self.proxyport}'],'tunnel_public_addr':f'cooplay-proxy.test:{self.proxyport}',
                           'https_keypairs':[{'key_file':str(self.root/'server.key'),'cert_file':str(self.root/'server.crt')}]},
          'ssh_service':{'enabled':True,'listen_addr':f'127.0.0.1:{self.sshport}','labels':{'environment':'lab','purpose':'keycloak-ssh'}}}
        config['kubernetes_service']={'enabled':True,'listen_addr':'127.0.0.1:3026','kubeconfig_file':str(self.agent_kubeconfig),'labels':{'environment':'lab','purpose':'keycloak-kube'}}
        self.config=self.write('teleport.yaml',config)
        self.teleport=self.start([self.root/'bin/teleport','start','--config',self.config,'--no-debug-service'],'teleport')
        self.wait_http(self.proxy+'/v1/webapi/find',120)
        self.tctl('create',REPO/'examples/keycloak/role.yaml')
        self.tctl('create',REPO/'examples/keycloak/kubernetes-role.yaml')
        connector={'kind':'oidc','version':'v3','metadata':{'name':'keycloak-lab'},'spec':{'provider':'keycloak','issuer_url':self.issuer,'client_id':'teleport-smoke',
             'client_secret':'external-secret-reference','redirect_url':self.proxy+'/v1/webapi/oidc/callback','scope':['openid','profile','email'],
             'claims_to_roles':[{'claim':'groups','value':'/lab/teleport-ssh','roles':['keycloak-lab-ssh']},{'claim':'groups','value':'/lab/teleport-kube','roles':['keycloak-lab-kube']}]}}
        self.tctl('create',self.write('connector.json',connector))
        self.wait_http(self.proxy+'/v1/webapi/ping',30)
        with self.http.open(self.proxy+'/web',timeout=20) as response: body=response.read().decode()
        self.check('normal_web_assets_served',response.status==200 and '<script' in body and 'type="module"' in body)
    def tctl(self,*args):
        copied=[]
        for arg in args:
            if isinstance(arg,Path) and arg.is_relative_to(REPO):
                target=self.root/'inputs'/arg.name; target.parent.mkdir(mode=0o700,exist_ok=True); shutil.copyfile(arg,target); target.chmod(0o600); copied.append(target)
            else: copied.append(arg)
        return self.run([self.root/'bin/tctl','--config',self.config,*copied])
    def totp(self):
        counter=struct.pack('>Q',int(time.time())//30)
        key=base64.b32decode(self.otp_secret+'='*((-len(self.otp_secret))%8))
        digest=hmac.new(key,counter,hashlib.sha1).digest(); offset=digest[-1]&15
        return str((struct.unpack('>I',digest[offset:offset+4])[0]&0x7fffffff)%1000000).zfill(6)
    def login_form(self,browser,initial,username):
        page,final=super().login_form(browser,initial,username)
        if username=='disabled': return page,final
        self.check('mfa_prompt_'+username,page.action is not None and page.action.startswith(self.idp+'/'))
        if not self.result['checks'].get('incorrect_otp_denied'):
            bad='000000' if self.totp()!='000000' else '111111'
            req=urllib.request.Request(page.action,urllib.parse.urlencode(dict(page.fields,otp=bad)).encode(),headers={'Content-Type':'application/x-www-form-urlencoded'})
            with browser.open(req,timeout=30) as response: page=Page(response.read().decode()); final=response.geturl()
            self.check('incorrect_otp_denied',page.action is not None and final.startswith(self.idp+'/'))
        if self.last_otp_period.get(username)==int(time.time())//30 or time.time()%30>25:
            time.sleep(30-time.time()%30+.1)
        self.last_otp_period[username]=int(time.time())//30
        req=urllib.request.Request(page.action,urllib.parse.urlencode(dict(page.fields,otp=self.totp())).encode(),headers={'Content-Type':'application/x-www-form-urlencoded'})
        with browser.open(req,timeout=30) as response:
            body=response.read().decode()
            self.last_login_markers=[marker for marker in ('Invalid authenticator code','Invalid username or password','Account is disabled','invalid_code','error.login') if marker.lower() in body.lower()]
            self.last_login_path=urllib.parse.urlsplit(response.geturl()).path
            return Page(body),response.geturl()
    def local_redirect(self,url):
        # Only the short, per-login tsh loopback handler lives in the Linux
        # namespace. Forward its GET there without exposing URL/token output.
        code='''import sys,urllib.request,json
class Stop(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs): return None
try:
 r=urllib.request.build_opener(Stop()).open(sys.stdin.read(),timeout=20)
 print(json.dumps({"status":r.status}))
except urllib.error.HTTPError as e:
 print(json.dumps({"status":e.code,"location":e.headers.get("Location")}))
'''
        p=subprocess.run(['docker','exec','-i',self.runner,'python3','-c',code],input=url.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
        if p.returncode: raise Failure('Linux loopback ceremony forwarding failed')
        return json.loads(p.stdout)
    def cli_login(self,username='allowed',suffix='',ttl=5):
        self.stage='native tsh login with real MFA'
        profile=self.root/('profile-'+username+suffix); env=dict(self.env,TELEPORT_HOME=str(profile))
        p=self.start([self.root/'bin/tsh','login','--proxy',f'127.0.0.1:{self.proxyport}','--auth=keycloak-lab','--ttl='+str(ttl),'--browser=none','--add-keys-to-agent=no'],'tsh',env)
        until=time.monotonic()+45; initial=None
        while time.monotonic()<until:
            match=re.search(r'http://(?:127\.0\.0\.1|localhost):\d+/[a-zA-Z0-9-]+',bytes(self.outputs[p.pid]).decode(errors='replace'))
            if match: initial=match[0]; break
            if p.poll() is not None: raise Failure('tsh exited before login')
            time.sleep(.1)
        if initial is None: raise Failure('tsh ceremony timeout')
        location=self.local_redirect(initial).get('location')
        if not location or not location.startswith(self.idp+'/'): raise Failure('unexpected tsh redirect')
        browser,_=self.browser(); page,_=self.login_form(browser,location,username)
        if not page.redirect or not page.redirect.startswith('http://127.0.0.1:'):
            self.result['login_failure']={'fixture':username,'form_present':page.action is not None,'markers':self.last_login_markers,'path':self.last_login_path}
            raise Failure('encrypted CLI callback missing')
        self.local_redirect(page.redirect)
        self.check('native_tsh_login_'+username+suffix,p.wait(timeout=30)==0)
        status=json.loads(self.run([self.root/'bin/tsh','status','--format=json'],env=env).stdout)['active']
        roles=status['roles']; grants=[r for r in roles if not r.startswith(('keycloak-login-','keycloak-guard-'))]
        self.check('least_privilege_certificate_'+username+suffix,grants==(['keycloak-lab-kube'] if username=='kube-user' else ['keycloak-lab-ssh']) and (username=='kube-user' or status['logins']==['lab-user']) and len(roles)==3)
        self.profiles[username+suffix]=env
        return env
    def wait_denied(self,env,seconds=15):
        start=time.monotonic()
        while time.monotonic()-start<seconds:
            if self.run([self.root/'bin/tsh','ls','--format=json'],env=env,check=False).returncode: return round(time.monotonic()-start,3)
            time.sleep(.25)
        raise Failure('revocation deadline exceeded')
    def exercise_browser(self):
        self.stage='real browser full UI login MFA and logout'
        public=self.run(['openssl','x509','-in',self.root/'server.crt','-pubkey','-noout']).stdout
        der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=public,capture_output=True,check=True).stdout
        cfg={'proxy':self.proxy,'issuer':self.issuer,'password':self.password,
             'otp':base64.b64encode(base64.b32decode(self.otp_secret+'='*((-len(self.otp_secret))%8))).decode(),
             'spki':base64.b64encode(hashlib.sha256(der).digest()).decode(),'browser':str(self.args.browser) if self.args.browser else None}
        result=subprocess.run([self.args.node,REPO/'build.assets/cooplay/browser-smoke.mjs'],input=json.dumps(cfg).encode(),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,env=dict(self.env,NODE_EXTRA_CA_CERTS=str(self.root/'ca.crt')))
        try: data=json.loads(result.stdout)
        except ValueError: raise Failure('browser harness did not return a result')
        self.result['browser']=data
        self.check('real_browser_login_mfa_logout',result.returncode==0 and data['passed'])

    def exercise(self):
        self.exercise_browser()
        self.start_expiry_probe()
        one=self.cli_login('logout-user'); two=self.cli_login('logout-user','-second')
        copied=self.root/'copied-profile'; shutil.copytree(Path(one['TELEPORT_HOME']),copied)
        copied_env=dict(one,TELEPORT_HOME=str(copied))
        self.stage='current tsh logout isolation'
        self.run([self.root/'bin/tsh','logout'],env=one)
        self.result['current_logout_seconds']=self.wait_denied(copied_env)
        self.check('current_logout_invalidates_copied_credentials',True)
        self.check('independent_login_survives_current_logout',self.run([self.root/'bin/tsh','ls','--format=json'],env=two).returncode==0)
        active=self.cli_login('allowed')
        self.stage='real SSH least privilege'
        allowed=self.run([self.root/'bin/tsh','ssh','lab-user@keycloak-smoke','id','-u'],env=active)
        self.check('unprivileged_linux_ssh',allowed.stdout.strip().isdigit() and allowed.stdout.strip()!=b'0')
        self.check('root_ssh_denied',self.run([self.root/'bin/tsh','ssh','root@keycloak-smoke','true'],env=active,check=False).returncode!=0)
        process=self.start([self.root/'bin/tsh','ssh','--no-resume','-t','lab-user@keycloak-smoke','echo COOPLAY_SESSION_READY; sleep 120'],'ssh-session',active)
        until=time.monotonic()+20
        while b'COOPLAY_SESSION_READY' not in self.outputs[process.pid]:
            if process.poll() is not None or time.monotonic()>until: raise Failure('SSH recording session did not start')
            time.sleep(.1)
        self.stage='automatic disabled-user synchronization'
        user=self.admin('users?username=allowed&exact=true')[0]
        self.admin('users/'+user['id'],'PUT',{'enabled':False})
        self.result['disable_new_request_seconds']=self.wait_denied(active)
        self.check('disabled_user_active_ssh_disconnected',process.wait(timeout=15)!=0)
        self.admin('users/'+user['id'],'PUT',{'enabled':True})
        self.check('re_enable_does_not_erase_revocation',self.run([self.root/'bin/tsh','ls','--format=json'],env=active,check=False).returncode!=0)
        self.stage='automatic group removal synchronization'
        group_env=self.cli_login('group-user'); user=self.admin('users?username=group-user&exact=true')[0]
        groups=self.admin('users/'+user['id']+'/groups'); group=next(g for g in groups if g['path']=='/lab/teleport-ssh')
        self.admin('users/'+user['id']+'/groups/'+group['id'],'DELETE')
        self.result['group_removal_seconds']=self.wait_denied(group_env)
        self.check('group_removal_revokes_existing_credentials',True)
        self.stage='Keycloak signed back-channel logout'
        sso=self.cli_login('sso-user'); user=self.admin('users?username=sso-user&exact=true')[0]
        self.admin('users/'+user['id']+'/logout','POST')
        self.result['backchannel_logout_seconds']=self.wait_denied(sso)
        self.check('real_keycloak_backchannel_revokes_credentials',True)
        self.cli_login('sso-user','-fresh')
        self.check('idp_logout_allows_fresh_authentication',True)
        self.exercise_kubernetes()
        self.exercise_lifecycle()
        self.stage='native audit evidence'
        time.sleep(2); events=[]
        for path in (getattr(self,'audit_data',self.root/'data')/'log').rglob('*.log'):
            for line in path.read_text(errors='replace').splitlines():
                try:
                    value=json.loads(line)
                    if isinstance(value,dict): events.append(value)
                except ValueError: pass
        self.check('login_audit',any(e.get('event')=='user.login' and e.get('success') is True for e in events))
        self.check('revocation_audit',any(e.get('event')=='lock.created' for e in events))
        self.check('ssh_session_start_audit',any(e.get('event')=='session.start' for e in events))
        self.check('ssh_session_end_audit',any(e.get('event')=='session.end' for e in events))
        self.check('durable_revocation_journal',any(getattr(self,'active_journal',self.root/'revocations').glob('*.json')))
        self.check_recordings(events)
    def cleanup(self):
        for name in reversed(self.extra_containers): self.run(['docker','rm','--force',name],check=False)
        if self.runner_created:
            # Transfer only this disposable work directory back to the caller.
            self.run(['docker','exec',self.runner,'chown','-R',str(os.getuid())+':'+str(os.getgid()),str(self.root)],check=False)
            self.run(['docker','rm','--force',self.runner],check=False)
            self.runner_created=False
        super().cleanup()


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--binaries',type=Path,default=REPO/'build/cooplay-candidate/linux-arm64')
    p.add_argument('--node',default='node'); p.add_argument('--browser',type=Path,default=Path('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome') if sys.platform=='darwin' else None)
    p.add_argument('--result',type=Path,default=REPO/'build/cooplay-candidate/real-keycloak-result.json'); p.add_argument('--keep-private-workdir',action='store_true')
    args=p.parse_args(); os.umask(0o077); lab=CandidateLab(args); passed=False
    try: lab.setup(); lab.exercise(); passed=True
    except (Exception,KeyboardInterrupt) as error:
        lab.result.update(failed_step=lab.stage,error_type=type(error).__name__)
        frames=traceback.extract_tb(error.__traceback__)
        if frames: lab.result['failed_location']=Path(frames[-1].filename).name+':'+str(frames[-1].lineno)
        if isinstance(error,urllib.error.HTTPError): lab.result['http_status']=error.code
        if isinstance(error,Failure): lab.result['failure_reason']=str(error)
    finally:
        try: lab.cleanup()
        except Exception: lab.result['cleanup_failed']=True; passed=False
        lab.result.update(passed=passed,finished_at_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        args.result.parent.mkdir(parents=True,exist_ok=True); args.result.write_text(json.dumps(lab.result,indent=2)+'\n')
        # Asset manifests are intentionally kept in the result file, not dumped
        # into chat/CI output. Never print HTTP or subprocess response bodies.
        summary={k:v for k,v in lab.result.items() if k!='build_manifest'}; print(json.dumps(summary,indent=2))
    return 0 if passed else 1
if __name__=='__main__': sys.exit(main())

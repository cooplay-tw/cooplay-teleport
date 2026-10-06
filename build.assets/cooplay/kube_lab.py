# Copyright (C) 2026 Cooplay contributors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Disposable real Kubernetes authorization and active-exec revocation checks."""
import json
import subprocess
import time
from lab_common import Failure, port


class KubernetesLab:
    def kube_admin(self, *args, payload=None, check=True):
        process = subprocess.run(['docker', 'exec', '-i', self.kube_container, '/bin/kubectl', *args],
                                 input=None if payload is None else json.dumps(payload).encode(),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90)
        if check and process.returncode:
            raise Failure('isolated Kubernetes setup failed' + (': ' + process.stderr.decode(errors='replace')[:1200] if args and args[0]=='apply' else ''))
        return process

    def start_kubernetes(self, pins):
        self.stage = 'start isolated Kubernetes'
        self.kube_container = self.container + '-kubernetes'
        self.kubeport = port()
        self.run(['docker', 'run', '--detach', '--privileged', '--name', self.kube_container,
                  '--publish', f'127.0.0.1:{self.kubeport}:6443', pins['k3s'], 'server',
                  '--tls-san=host.docker.internal', '--disable=traefik,servicelb,metrics-server,local-storage',
                  '--write-kubeconfig-mode=600'], timeout=120)
        self.extra_containers.append(self.kube_container)
        until = time.monotonic() + 180
        while self.kube_admin('get', 'nodes', check=False).returncode:
            if time.monotonic() > until:
                raise Failure('Kubernetes API readiness timed out')
            time.sleep(1)
        def metadata(name, namespace=None):
            return dict(name=name, **({'namespace': namespace} if namespace else {}))
        items = [{'apiVersion':'v1', 'kind':'Namespace', 'metadata':metadata(n)} for n in ('lab-allowed','lab-denied','teleport-agent')]
        for ns in ('lab-allowed', 'lab-denied'):
            items.append({'apiVersion':'v1','kind':'ServiceAccount','metadata':metadata('fixture',ns),'automountServiceAccountToken':False})
            for name in ('demo', 'other'):
                items.append({'apiVersion':'v1','kind':'Pod','metadata':metadata(name,ns), 'spec':{
                    'automountServiceAccountToken':False,'serviceAccountName':'fixture',
                    'securityContext':{'runAsNonRoot':True,'runAsUser':10000,'runAsGroup':10000,'seccompProfile':{'type':'RuntimeDefault'}},
                    'containers':[{'name':'demo','image':pins['busybox'],'command':['sh','-c','echo fixture-ready; sleep 7200'],
                    'securityContext':{'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']}},
                    'resources':{'requests':{'cpu':'10m','memory':'8Mi'},'limits':{'cpu':'100m','memory':'32Mi'}}}]}})
        items += [{'apiVersion':'v1','kind':'Secret','metadata':metadata('denied-fixture','lab-allowed'),'stringData':{'test':'non-production-fixture'}},
          {'apiVersion':'v1','kind':'ServiceAccount','metadata':metadata('teleport','teleport-agent'),'automountServiceAccountToken':False}]
        reader_rules=[{'apiGroups':[''],'resources':['pods'],'verbs':['get','list','watch']},
                      {'apiGroups':[''],'resources':['pods/log','pods/exec'],'resourceNames':['demo'],'verbs':['get','create']}]
        impersonation=[{'apiGroups':[''],'resources':['users'],'resourceNames':['keycloak-lab'],'verbs':['impersonate']},
                       {'apiGroups':[''],'resources':['groups'],'resourceNames':['keycloak-lab-readers','system:authenticated'],'verbs':['impersonate']},
                       {'apiGroups':['authorization.k8s.io'],'resources':['selfsubjectaccessreviews','selfsubjectrulesreviews'],'verbs':['create']}]
        agent=[{'kind':'ServiceAccount','name':'teleport','namespace':'teleport-agent'}]
        def role(kind,name,rules,ns=None):
            return {'apiVersion':'rbac.authorization.k8s.io/v1','kind':kind,'metadata':metadata(name,ns),'rules':rules}
        def binding(kind,name,refkind,subjects,ns=None):
            return {'apiVersion':'rbac.authorization.k8s.io/v1','kind':kind,'metadata':metadata(name,ns),
                    'roleRef':{'apiGroup':'rbac.authorization.k8s.io','kind':refkind,'name':name},'subjects':subjects}
        items += [role('Role','readers',reader_rules,'lab-allowed'),
                  binding('RoleBinding','readers','Role',[{'kind':'Group','name':'keycloak-lab-readers','apiGroup':'rbac.authorization.k8s.io'}],'lab-allowed'),
                  role('ClusterRole','teleport-impersonator',impersonation),binding('ClusterRoleBinding','teleport-impersonator','ClusterRole',agent),
                  role('Role','pod-metadata',[{'apiGroups':[''],'resources':['pods'],'verbs':['get']}],'lab-allowed'),
                  binding('RoleBinding','pod-metadata','Role',agent,'lab-allowed')]
        self.kube_admin('apply','-f','-',payload={'apiVersion':'v1','kind':'List','items':items})
        self.kube_admin('wait','--for=condition=Ready','pod','--all','-n','lab-allowed','--timeout=150s')
        # Admin kubeconfig is used only in memory to obtain the public CA. The
        # Teleport service receives a bounded, narrowly authorized SA token.
        admin=json.loads(self.kube_admin('config','view','--raw','-o','json').stdout)
        cluster=admin['clusters'][0]['cluster']
        cluster['server']=f'https://host.docker.internal:{self.kubeport}'
        token=self.kube_admin('create','token','teleport','-n','teleport-agent','--duration=30m').stdout.decode().strip()
        self.agent_kubeconfig=self.write('kube-agent.json',{'apiVersion':'v1','kind':'Config','clusters':[{'name':'cooplay-kube','cluster':cluster}],
                'users':[{'name':'agent','user':{'token':token}}], 'contexts':[{'name':'cooplay-kube','context':{'cluster':'cooplay-kube','user':'agent'}}],'current-context':'cooplay-kube'})
        self.run(['docker','cp',self.kube_container+':/bin/k3s',self.root/'bin/kubectl'])
        (self.root/'bin/kubectl').chmod(0o755)
        self.result['kubernetes_version']=pins['k3s_version']
        self.result['kubernetes_image']=pins['k3s']

    def exercise_kubernetes(self):
        self.stage='Kubernetes least privilege through native Teleport'
        env=self.cli_login('kube-user')
        self.run([self.root/'bin/tsh','kube','login',getattr(self,'kube_cluster_name','cooplay-kube')],env=env)
        def kubectl(*args,check=True):
            return self.run([self.root/'bin/kubectl','--request-timeout=15s',*args],env=env,check=check)
        self.check('kube_allowed_namespace_list',kubectl('get','pods','-n','lab-allowed','-o','json').returncode==0)
        self.check('kube_allowed_named_exec',b'10000' in kubectl('exec','-n','lab-allowed','demo','--','id','-u').stdout)
        for name,args in (
            ('secrets', ['get','secrets','-n','lab-allowed']),
            ('other_namespace',['get','pods','-n','lab-denied']),
            ('cluster_wide_list',['get','pods','--all-namespaces']),
            ('delete',['delete','pod','demo','-n','lab-allowed']),
            ('other_pod_exec',['exec','-n','lab-allowed','other','--','true']),
            ('self_escalation',['auth','can-i','get','secrets','--as=system:admin','-n','lab-allowed'])):
            self.check('kube_denied_'+name,kubectl(*args,check=False).returncode!=0)
        process=self.start([self.root/'bin/kubectl','exec','-n','lab-allowed','demo','--','sh','-c','echo KUBE_SESSION_READY; sleep 120'],'kube-exec',env)
        until=time.monotonic()+30
        while b'KUBE_SESSION_READY' not in self.outputs[process.pid]:
            if process.poll() is not None or time.monotonic()>until: raise Failure('Kubernetes exec did not start')
            time.sleep(.1)
        user=self.admin('users?username=kube-user&exact=true')[0]
        self.admin('users/'+user['id'],'PUT',{'enabled':False})
        self.result['kube_disable_seconds']=self.wait_denied(env)
        self.check('kube_active_exec_disconnected',process.wait(timeout=15)!=0)
        self.check('kube_existing_credentials_denied',kubectl('get','pods','-n','lab-allowed',check=False).returncode!=0)

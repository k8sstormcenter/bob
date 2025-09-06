# Software Bill of Behaviour - Tooling `bobctl`

<img width="623" height="440" alt="PNG image" src="https://github.com/user-attachments/assets/a85b5168-ffff-4aef-a8f1-cd3f551d69e7" />



We introduce the “Bill of Behavior” (BoB): a vendor-supplied profile detailing known benign runtime behaviors for software, designed to be distributed directly within OCI artifacts. 
Generated using eBPF, a BoB codifies expected syscalls, file access patterns, network communications, and capabilities. 
This empowers powerful, signature-less anomaly detection, allowing end-users to infer malicious activity or tampering in third-party software without the current burden of authoring and maintaining complex, custom security rules.

Image a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ship it `with each update` 
<img width="3124" height="2638" alt="bobverticalvendor" src="https://github.com/user-attachments/assets/b66e1510-c4c6-41b8-8f45-11ce98faf947" />

That means the user receives a secure default runtime profile. They can customize it, or directly apply it for runtime detection. And which each update of the software,
get an uptodate runtimeprofile 🚨 New Design Kubescape 4.0 will support user-defined-profiles, here an example using the kubescape CRDs 🚨 
``` yaml
apiVersion: spdx.softwarecomposition.kubescape.io/v1beta1
kind: ApplicationProfile
metadata:
  name: bob-application123
  namespace: {{ .Release.Namespace }}                                                                                                                      
spec:
  architectures:
  - amd64
  containers:
  - capabilities:  # KNOWN CAPABILITIES
    - DAC_OVERRIDE
    - SETGID
    - SETUID
    endpoints:     # KNOWN NETWORK
    - direction: inbound
      endpoint: :8080/ping.php
      headers:
        Host: # User accessible Overrides
        - {{ include "mywebapp.fullname" . }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.service.port }}                          
      internal: false
      methods:
      - GET
    execs:       #KNOWN EXEC
    - args:
      - /usr/bin/dirname
      - /var/lock/apache2
      path: /usr/bin/dirname
    - args:
      - /bin/sh
      - -c
      - ping -c 4 172.16.0.2
      path: /bin/sh
    imageID: ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b  #IMAGE HASH
    opens:     #KNOWN FILE OPENS
    - flags:  
      - O_CLOEXEC
      - O_DIRECTORY
      - O_NONBLOCK
      - O_RDONLY
      path: /etc/apache2/* #globs that generalize UUIDs or well-known FS structures
    - flags:
      - O_CLOEXEC
      - O_RDONLY
      path: /etc/group
    - flags:
      - O_CLOEXEC
      - O_RDONLY
      path: /etc/ld.so.cache
    rulePolicies:  # SPECIFIC EXCEPTION RULES
      R0001:
        processAllowed:
        - ping
        - sh
      R0002: {}
      ...
    syscalls:    # KNOWN SYSCALLS
    - accept4
    - access
    - arch_prctl
    - getegid
    - geteuid
      ...
```



<img width="3133" height="2637" alt="bobverticalcustomer" src="https://github.com/user-attachments/assets/7e3b045c-8c63-4948-9748-21d62125823a" />

## FAQ
Q: Isnt this the same as SELINUX/APPARMOR profiles?   
A: Just like eBPF extends the Kernel, the above Profile are a superset of `seccomp` (Profiles incl FileAccess, Execs, ImageHashes, NetworkEndpoints and Capabilities) and can work real-time with user-space applications. In this example
it doesnt require loading anything into the LSM. LSMs have a totally different life-cycle and granularity than applications. 

**THE MOST IMPORTANT DIFFERENCE is UX, granularity and timeing** and this enables transferring it between systems and making it transparent to users

## Example comparison of seccomp with BoB (for redis)
For the KV-database `redis` in its most popular Helm-Chart, we traced out the superset of all syscalls across many k8s-versions/distros. In K8s, there is a [`RuntimeDefault` seccomp](https://github.com/moby/profiles/blob/main/seccomp/default.json) [profile](https://github.com/containerd/containerd/blob/main/contrib/seccomp/seccomp_default.go) depending on the containerruntime that disallows the most dangerous syscalls. Since, it is the best-known security feature, we
compare the 195 allowed syscalls from the default with the 128 from the BoB profile.
Generally speaking, a BoB profile will have a lower number of syscalls than a seccomp profile. There are many discussions on the internet on how [seccomp is difficult across architecture](https://github.com/opencontainers/runc/issues/2151)s and known [issues](https://lwn.net/Articles/738694/).

Profile	|Total Syscalls|	In BoB Not in RuntimeDefault|	In RuntimeDefault, Not in BoB|
--|--|--|--|
Redis Superset BoB|	128	|8	|N/A|
K8s RuntimeDefault|	363 |	N/A|	~195|

WIP: new and more detailed comparison for Redis is coming soon

## More elaborate Comparison of the shrinking attack surface if using NO| FULL | BAU profiles for CNCF Pixie
| Profile                     | Capabilities                                                                 | Network | Opens (#) | Execs (#) | Allowed Syscalls (#) |
|-----------------------------|------------------------------------------------------------------------------|---------|-----------|-----------|----------------------|
| Kubernetes Default (v1.33)  | unconfined                                                                   | CNI     | unconfined| unconfined| 363                  |
| FULL:catalogoperator        | CHOWN,<br>DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN,<br>SETGID,<br>SETPCAP,<br>SETUID,<br>SYS_ADMIN | 1       | 23        | 3         | 96                   |
| FULL:catalogsource          | CHOWN,<br>DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN,<br>SETGID,<br>SETPCAP,<br>SETUID,<br>SYS_ADMIN | 0       | 19        | 2         | 106                  |
| BAU :catalogsource          | CHOWN,<br>DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN,<br>SETGID,<br>SETPCAP,<br>SETUID,<br>SYS_ADMIN | 0       | 57        | 2         | 94                   |
| FULL:certman                | DAC_OVERRIDE,<br>DAC_READ_SEARCH                                             | 0       | 8         | 1         | 65                   |
| FULL:initjob                | DAC_OVERRIDE,<br>DAC_READ_SEARCH                                             | 0       | 10        | 1         | 100                  |
| FULL:kelvin                 | DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN                               | 0       | 97        | 1         | 76                   |
| BAU :kelvin                 | none                                                                         | 0       | 0         | 0         | 22                   |
| FULL:olmoperator            | DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN                               | 1       | 8         | 1         | 63                   |
| FULL:pem                    | BPF,<br>DAC_READ_SEARCH,<br>IPC_LOCK,<br>NET_ADMIN,<br>PERFMON,<br>SYS_ADMIN,<br>SYS_PTRACE,<br>SYSLOG | 0       | 390       | 1         | 122                  |
| BAU :pem                    | BPF,<br>DAC_READ_SEARCH,<br>IPC_LOCK,<br>NET_ADMIN,<br>PERFMON,<br>SYS_ADMIN,<br>SYS_PTRACE | 0       | 197       | 0         | 44                   |
| FULL:pletcd                 | NET_ADMIN,<br>NET_RAW,<br>SETGID,<br>SETPCAP,<br>SETUID,<br>SYS_ADMIN        | 0       | 39        | 10        | 92                   |
| BAU :pletcd                 | SETGID,<br>SETPCAP,<br>SETUID,<br>SYS_ADMIN                                  | 0       | 37        | 2         | 53                   |
| FULL:plnats                 | DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN                               | 3       | 11        | 1         | 57                   |
| BAU :plnats                 | none                                                                         | 1       | 1         | 0         | 19                   |
| FULL:querybroker            | DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>FOWNER,<br>NET_ADMIN                    | 0       | 20        | 1         | 107                  |
| BAU :querybroker            | DAC_OVERRIDE,<br>FOWNER                                                      | 0       | 0         | 0         | 22                   |
| FULL:viziercloudconnector   | DAC_OVERRIDE,<br>DAC_READ_SEARCH,<br>NET_ADMIN                               | 0       | 18        | 1         | 70                   |
| BAU :viziercloudconnector   | none                                                                         | 0       | 3         | 0         | 29                   |
| FULL:viziermeta             | NET_ADMIN                                                                    | 0       | 16        | 1         | 65                   |
| BAU :viziermeta             | none                                                                         | 0       | 3         | 0         | 24                   |
| FULL:vizieroperator         | NET_ADMIN                                                                    | 1       | 13        | 1         | 104                  |
| BAU :vizieroperator         | none                                                                         | 1       | 2         | 0         | 27                   |




Additionally to syscalls: a BoB contains fileopens, execs, capabilities and network endpoints/methods. This is reminiscent of Apparmour profiles and network-policies.
It is theoretically possible to convert a BoB into an Apparmour profile, a seccomp profile and a set of network-policies.

Which way the community will go in terms of using the information contained in a bob, such that it can be enforced at runtime, remains to be seen.

A BoB, is first of all a `vehicle` to transport the information of the runtime behavior. And only secondly, the runtime-anomaly generation method. The fact, that kubescape can rather straightforwardly do both, is a very lucky coincidence.

## Origin Story

.. over coffee at London KubeCon EU 2025


![animation](https://github.com/user-attachments/assets/51ccc381-b1c4-4889-9d68-8ef7518e74ff)


## Understanding the Use Cases

A Bill of Behaviour helps us detect unexpected or malicious activity. We'll focus on two primary scenarios:

### 1. Runtime Anomalies
This scenario covers situations where a CVE is present in the app, or it gets exploited.

### 2. Supply Chain Anomalies
This scenario covers threats originating from a compromised supply chain. For example:
*   The artefact is not the one from the vendor.
*   The vendor's supply chain got compromised.
*   A typosquatting attack has occurred.
*   The artefact contains a beacon, a backdoor, a cryptominer, or something else malicious.


# Try it out in a live lab 
[give us feedback ](https://labs.iximiuz.com/courses/bill-of-behaviour-c070da3a), report issues , raise PRs (contributing guidelines will follow)


https://labs.iximiuz.com/courses/bill-of-behaviour-c070da3a

License is Apache 2.0

## Demo: Deploy a Application
Using a well-known `demo`** app, we deploy a ping utility called `webapp` that has:

*   **a) Desired functionality:** it pings things.
*   **b) Undesired functionality:** it is vulnerable to injection (runtime is compromised).
    *   _This is to mimic a CVE in your app._
*   **c) Tampering with the artefact:** In module 2, we will additionally tamper with the artifact and make it create a backdoor (supply chain is compromised).
    *   _This is to mimic a SupplyChain corruption between vendor and you._

```sh
cd ~/bobctl
git checkout https://github.com/k8sstormcenter/bobctl
# maybe you need storage, then `make storage`
make kubescape
sleep 30 # TODO proper wait command goes here
make helm-install
```
##  Generate Traffic of Benign Behaviour

<div style="background-color: #f0f8ff; border: 1px solid #ccc; padding: 10px; border-radius: 5px;">

**Benign** (*adjective*) [bi-ˈnīn] 
*   **Benignity** (*noun*) [bi-ˈnig-nə-tē]
*   **Benignly** (*adverb*) [bi-ˈnīn-lē]

**Definitions/SYNONYMS:**

1.  Of a mild type or character that does not threaten health or life. *HARMLESS*.
2.  Of a gentle disposition: *GRACIOUS*.
3.  Showing kindness and gentleness. *FAVORABLE*, *WHOLESOME*.
</div>

In shell 1:
```sh
kubectl logs -n honey -l app=node-agent -c node-agent -f
```

In shell 2

```sh
make fwd
curl localhost:8080/ping.php?ip=172.16.0.2
```
This will be recorded into the above profile reflected by the stanza:
```
  endpoint:
    - direction: inbound
      endpoint: :8080/ping.php
      headers:
        Host:
        - localhost:8080  # vendor needs to template possible benign endpoints e.g via k8s-dns                         
      internal: false
      methods:
      - GET
  exec:
  ...
    - args:
      - /bin/sh
      - -c
      - ping -c 4 172.16.0.2 #vendor needs to template possible benign IP CIDR
      path: /bin/sh
```

## Create a repeatable Positive Test

**Vendor**
Encode the `benign` behavior into a test, like a helm hook

```yaml
apiVersion: v1
kind: Pod
metadata:
  labels:
    {{- include "mywebapp.labels" . | nindent 4 }}
    kubescape.io/ignore: "true"
  annotations:
    "helm.sh/hook": test
    "helm.sh/hook-delete-policy": hook-succeeded,hook-failed
spec:
  containers:
    - image: curlimages/curl:8.7.1
      command:
          URL="${SERVICE}.${NAMESPACE}.svc.cluster.local:${PORT}/ping.php?ip=${TARGET_IP}"
          RESPONSE=$(curl -s "$URL")
          echo "$RESPONSE"
          echo "$RESPONSE" | grep -q "Ping results for ${TARGET_IP}"
          echo "$RESPONSE" | grep -q "${TARGET_IP} ping statistics"
```

**User** 
If I now pull the helm-chart and execute helm test -> I can test that I do not see any anomalies.
```
make helm-test
```
```sh
kubectl logs -n honey -l app=node-agent -c node-agent -f | grep "Unexpected"  # You should not see anything 
```

*** Known exceptions: There are expected syscall deviations, those are small. Making those transparent to the user is WIP. Currently you need a superset Bob

## Generate Runtime Attack (normal attack that abuses CVE)
In shell 1:
```sh
kubectl logs -n honey -l app=node-agent -c node-agent -f
```

In shell 2
```sh
make attack
```

```json
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/bin/ls"],"exec":"/bin/ls","retval":0},"infectedPID":6972,"severity":5,"size":"4.1 kB","timestamp":"2025-05-14T09:41:34.973055288Z","trace":{}},"CloudMetadata":null,"RuleID":"R0001","RuntimeK8sDetails":{"clusterName":"honeycluster","containerName":"ping-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"default","containerID":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c","podName":"webapp-d87cdd796-4ltvq","podNamespace":"default","podLabels":{"app":"webapp","pod-template-hash":"d87cdd796"},"workloadName":"webapp","workloadNamespace":"default","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":6950,"cmdline":"/bin/sh -c ping -c 4 172.16.0.2;ls","comm":"sh","ppid":5180,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"ls␟6972":{"pid":6972,"cmdline":"/bin/ls ","comm":"ls","ppid":6950,"pcomm":"sh","hardlink":"/bin/ls","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/ls"}}},"containerID":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c"},"event":{"runtime":{"runtimeName":"containerd","containerId":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c","containerName":"ping-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"default","podName":"webapp-d87cdd796-4ltvq","podLabels":{"app":"webapp","pod-template-hash":"d87cdd796"},"containerName":"ping-app","owner":{}},"timestamp":1747215694973055288,"type":"normal"},"level":"error","message":"Unexpected process launched: /bin/ls","msg":"Unexpected process launched","time":"2025-05-14T09:41:34Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY","O_NONBLOCK","O_DIRECTORY","O_CLOEXEC"],"path":"/var/www/html"},"infectedPID":6972,"severity":1,"timestamp":"2025-05-14T09:41:34.975867565Z","trace":{}},"CloudMetadata":null,"RuleID":"R0002","RuntimeK8sDetails":{"clusterName":"honeycluster","containerName":"ping-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"default","containerID":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c","podName":"webapp-d87cdd796-4ltvq","podNamespace":"default","workloadName":"webapp","workloadNamespace":"default","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":6950,"cmdline":"/bin/sh -c ping -c 4 172.16.0.2;ls","comm":"sh","ppid":5180,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"ls␟6972":{"pid":6972,"cmdline":"/bin/ls ","comm":"ls","ppid":6950,"pcomm":"sh","hardlink":"/bin/ls","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/ls"}}},"containerID":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c"},"event":{"runtime":{"runtimeName":"containerd","containerId":"2b3c4de694b3e5668c920cea48db530892eda11c4984552a7457b7f5af701d9c","containerName":"ping-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"default","podName":"webapp-d87cdd796-4ltvq","podLabels":{"app":"webapp","pod-template-hash":"d87cdd796"},"containerName":"ping-app","owner":{}},"timestamp":1747215694975867565,"type":"normal"},"level":"error","message":"Unexpected file access: /var/www/html with flags O_RDONLY,O_NONBLOCK,O_DIRECTORY,O_CLOEXEC","msg":"Unexpected file access","time":"2025-05-14T09:41:34Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"sendmmsg"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960d3acaa776c62f03a55","severity":1,"size":"730 kB","timestamp":"2025-07-07T21:22:12.648682466Z","trace":{},"uniqueID":"b8ae38884cb701d21b2862f2cdbee24e","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0003","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":15899,"cmdline":"apache2 -DFOREGROUND","comm":"apache2","ppid":15845,"pcomm":"containerd-shim","uid":0,"gid":0,"startTime":"0001-01-01T00:00:00Z","cwd":"/var/www/html","path":"/usr/sbin/apache2"},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"k8s":{"node":"cplane-01","namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923332648682466,"type":"normal"},"level":"error","message":"Unexpected system call: sendmmsg","msg":"Unexpected system call","time":"2025-07-07T21:22:12Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"socketpair"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960d3acaa776c62f03a55","severity":1,"size":"730 kB","timestamp":"2025-07-07T21:22:12.655726956Z","trace":{},"uniqueID":"668c081933ba8b63ab41bf2f74ba5c69","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0003","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":15899,"cmdline":"apache2 -DFOREGROUND","comm":"apache2","ppid":15845,"pcomm":"containerd-shim","uid":0,"gid":0,"startTime":"0001-01-01T00:00:00Z","cwd":"/var/www/html","path":"/usr/sbin/apache2"},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"k8s":{"node":"cplane-01","namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923332655726956,"type":"normal"},"level":"error","message":"Unexpected system call: socketpair","msg":"Unexpected system call","time":"2025-07-07T21:22:12Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected domain request","arguments":{"addresses":["216.58.210.174"],"domain":"google.com.","port":50015,"protocol":"UDP"},"infectedPID":20611,"severity":5,"size":"4.1 kB","timestamp":"2025-07-07T21:22:10.417464343Z","trace":{},"uniqueID":"0b80141cea771029450509ea63514032","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":1}},"CloudMetadata":null,"RuleID":"R0005","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20589,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;curl google.com","comm":"sh","ppid":15922,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"curl␟20611":{"pid":20611,"cmdline":"/usr/bin/curl google.com","comm":"curl","ppid":20589,"pcomm":"sh","hardlink":"/usr/bin/curl","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/usr/bin/curl"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923330417464343,"type":"normal"},"level":"error","message":"Unexpected domain communication: google.com. from: mywebapp-app","msg":"Unexpected domain request","time":"2025-07-07T21:22:10Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"getpeername"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960d3acaa776c62f03a55","severity":1,"size":"730 kB","timestamp":"2025-07-07T21:22:12.639434336Z","trace":{},"uniqueID":"69bbdde26311ca1a112c3449cc03d209","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0003","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":15899,"cmdline":"apache2 -DFOREGROUND","comm":"apache2","ppid":15845,"pcomm":"containerd-shim","uid":0,"gid":0,"startTime":"0001-01-01T00:00:00Z","cwd":"/var/www/html","path":"/usr/sbin/apache2"},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"k8s":{"node":"cplane-01","namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923332639434336,"type":"normal"},"level":"error","message":"Unexpected system call: getpeername","msg":"Unexpected system call","time":"2025-07-07T21:22:12Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/usr/bin/curl","google.com"],"exec":"/usr/bin/curl","retval":0},"infectedPID":20611,"severity":5,"size":"4.1 kB","timestamp":"2025-07-07T21:22:10.396395121Z","trace":{},"uniqueID":"10eb3203d2094782c9a560b1207a9c66","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0001","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20589,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;curl google.com","comm":"sh","ppid":15922,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"curl␟20611":{"pid":20611,"cmdline":"/usr/bin/curl google.com","comm":"curl","ppid":20589,"pcomm":"sh","hardlink":"/usr/bin/curl","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/usr/bin/curl"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923330396395121,"type":"normal"},"level":"error","message":"Unexpected process launched: /usr/bin/curl","msg":"Unexpected process launched","time":"2025-07-07T21:22:10Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected Service Account Token Access","arguments":{"flags":["O_RDONLY"],"path":"/run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token"},"infectedPID":20588,"severity":8,"timestamp":"2025-07-07T21:22:07.355497979Z","trace":{},"uniqueID":"d077f244def8a70e5ea758bd8352fcd8","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0006","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20586,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;cat /run/secrets/kubernetes.io/serviceaccount/token","comm":"sh","ppid":16216,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"cat␟20588":{"pid":20588,"cmdline":"/bin/cat /run/secrets/kubernetes.io/serviceaccount/token","comm":"cat","ppid":20586,"pcomm":"sh","hardlink":"/bin/cat","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/cat"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923327355497979,"type":"normal"},"level":"error","message":"Unexpected access to service account token: /run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token with flags: O_RDONLY","msg":"Unexpected Service Account Token Access","time":"2025-07-07T21:22:07Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY"],"path":"/run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token"},"infectedPID":20588,"severity":1,"timestamp":"2025-07-07T21:22:07.355497979Z","trace":{},"uniqueID":"6fa0673cb27a4829df52779bb1d42923","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0002","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20586,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;cat /run/secrets/kubernetes.io/serviceaccount/token","comm":"sh","ppid":16216,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"cat␟20588":{"pid":20588,"cmdline":"/bin/cat /run/secrets/kubernetes.io/serviceaccount/token","comm":"cat","ppid":20586,"pcomm":"sh","hardlink":"/bin/cat","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/cat"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923327355497979,"type":"normal"},"level":"error","message":"Unexpected file access: /run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token with flags O_RDONLY","msg":"Unexpected file access","time":"2025-07-07T21:22:07Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"fadvise64"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960d3acaa776c62f03a55","severity":1,"size":"730 kB","timestamp":"2025-07-07T21:22:02.638550612Z","trace":{},"uniqueID":"840a89954c4149cca50949888cfdb6a6","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0003","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":15899,"cmdline":"apache2 -DFOREGROUND","comm":"apache2","ppid":15845,"pcomm":"containerd-shim","uid":0,"gid":0,"startTime":"0001-01-01T00:00:00Z","cwd":"/var/www/html","path":"/usr/sbin/apache2"},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"k8s":{"node":"cplane-01","namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923322638550612,"type":"normal"},"level":"error","message":"Unexpected system call: fadvise64","msg":"Unexpected system call","time":"2025-07-07T21:22:02Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY"],"path":"/var/www/html/index.html"},"infectedPID":20581,"severity":1,"timestamp":"2025-07-07T21:22:04.332009145Z","trace":{},"uniqueID":"df2808e2d1f9a406d267ce3037697a3f","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0002","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20543,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;cat index.html","comm":"sh","ppid":15926,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"cat␟20581":{"pid":20581,"cmdline":"/bin/cat index.html","comm":"cat","ppid":20543,"pcomm":"sh","hardlink":"/bin/cat","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/cat"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923324332009145,"type":"normal"},"level":"error","message":"Unexpected file access: /var/www/html/index.html with flags O_RDONLY","msg":"Unexpected file access","time":"2025-07-07T21:22:04Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY","O_NONBLOCK","O_DIRECTORY","O_CLOEXEC"],"path":"/var/www/html"},"infectedPID":20503,"severity":1,"timestamp":"2025-07-07T21:21:58.287348855Z","trace":{},"uniqueID":"6a62049e8c5629b76f4f2f6d32e17cb0","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0002","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20495,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;ls","comm":"sh","ppid":15924,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"ls␟20503":{"pid":20503,"cmdline":"/bin/ls ","comm":"ls","ppid":20495,"pcomm":"sh","hardlink":"/bin/ls","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/ls"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923318287348855,"type":"normal"},"level":"error","message":"Unexpected file access: /var/www/html with flags O_RDONLY,O_NONBLOCK,O_DIRECTORY,O_CLOEXEC","msg":"Unexpected file access","time":"2025-07-07T21:21:58Z"}
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/bin/cat","/proc/self/mounts"],"exec":"/bin/cat","retval":0},"infectedPID":20527,"severity":5,"size":"4.1 kB","timestamp":"2025-07-07T21:22:01.312624103Z","trace":{},"uniqueID":"86a130a79323f10e54cf35ed94f7df9a","profileMetadata":{"status":"completed","completion":"complete","name":"replicaset-webapp-mywebapp-67965968bb","failOnProfile":true,"type":0}},"CloudMetadata":null,"RuleID":"R0001","RuntimeK8sDetails":{"clusterName":"bobexample","containerName":"mywebapp-app","hostNetwork":false,"image":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","imageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb","namespace":"webapp","containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","podName":"webapp-mywebapp-67965968bb-76d6g","podNamespace":"webapp","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"workloadName":"webapp-mywebapp","workloadNamespace":"webapp","workloadKind":"Deployment"},"RuntimeProcessDetails":{"processTree":{"pid":20504,"cmdline":"/bin/sh -c ping -c 4 1.1.1.1;cat /proc/self/mounts","comm":"sh","ppid":15925,"pcomm":"apache2","hardlink":"/bin/dash","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/dash","childrenMap":{"cat␟20527":{"pid":20527,"cmdline":"/bin/cat /proc/self/mounts","comm":"cat","ppid":20504,"pcomm":"sh","hardlink":"/bin/cat","uid":33,"gid":33,"startTime":"0001-01-01T00:00:00Z","upperLayer":false,"cwd":"/var/www/html","path":"/bin/cat"}}},"containerID":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35"},"event":{"runtime":{"runtimeName":"containerd","containerId":"48ce40eaf1f1d19a1b2125ecefdffe5de5c28910a6c24739309322a6228dad35","containerName":"mywebapp-app","containerImageName":"ghcr.io/k8sstormcenter/webapp@sha256:e323014ec9befb76bc551f8cc3bf158120150e2e277bae11844c2da6c56c0a2b","containerImageDigest":"sha256:c622cf306b94e8a6e7cfd718f048015e033614170f19228d8beee23a0ccc57bb"},"k8s":{"namespace":"webapp","podName":"webapp-mywebapp-67965968bb-76d6g","podLabels":{"app.kubernetes.io/instance":"webapp","app.kubernetes.io/name":"mywebapp","pod-template-hash":"67965968bb"},"containerName":"mywebapp-app","owner":{}},"timestamp":1751923321312624103,"type":"normal"},"level":"error","message":"Unexpected process launched: /bin/cat","msg":"Unexpected process launched","time":"2025-07-07T21:22:01Z"}
```

## Generate Supply Chain Attack
WIP


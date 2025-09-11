# Software Bill of Behaviour - Tooling `bobctl`


<img width="623" height="440" alt="PNG image" src="https://github.com/user-attachments/assets/a85b5168-ffff-4aef-a8f1-cd3f551d69e7" />

We introduce the “Bill of Behavior” (BoB): a vendor-supplied profile detailing known benign runtime behaviors for software, designed to be distributed directly within OCI artifacts. 
Generated using eBPF, a BoB codifies expected syscalls, file access patterns, network communications, and capabilities. 
This empowers two things:
** for the supply chain at deploy-time (possibly in a staging env), we can use a detailed and highly specific such profile to verify an installer at client side to exclude tampering (see the npm incident from sept 8)
** for continuous anomaly detection at runtime, allowing end-users to infer malicious activity, to shrink their false positive noise and to have a vendor-supplied behavioural baseline, the generalized and more lightweight profile is used.
We foresee a benefit for the end-user in shifting authoring and maintaining custom security policies from the recipient, who does not have in-depth knowledge of the software to the vendor, who (should) have the knowledge.

Image a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ship it `with each update` 
<img width="3124" height="2638" alt="bobverticalvendor" src="https://github.com/user-attachments/assets/b66e1510-c4c6-41b8-8f45-11ce98faf947" />

That means the user receives a secure default runtime profile. They can customize it, or directly apply it for runtime detection. And which each update of the software,
get an uptodate runtimeprofile

---

## Table of Contents

1. [Introduction](#software-bill-of-behaviour---tooling-bobctl)
2. [Bill of Behavior (BoB) Overview](#software-bill-of-behaviour---tooling-bobctl)
3. [Vendor Example: ApplicationProfile CRD](#software-bill-of-behaviour---tooling-bobctl)
4. [FAQ](#faq)
5. [Example Comparison: Seccomp vs BoB](#example-comparison-of-seccomp-with-bob-for-redis)
    - [For redis (in standalone form)](#for-redis-in-standalone-form)
    - [For Tetragon (OpenSource CNCF Security eBPF tool)](#for-tetragon-an-opensource-cncf-security-ebpf-tool)
    - [Comparison for CNCF Pixie](#more-elaborate-comparison-of-the-shrinking-attack-surface-if-using-no-full-bau-profiles-for-cncf-pixie)
6. [BoB as a Transport and Enforcement Mechanism](#bob-as-a-transport-and-enforcement-mechanism)
7. [Origin Story](#origin-story)
8. [Understanding the Use Cases](#understanding-the-use-cases)
    - [Runtime Anomalies](#1-runtime-anomalies)
    - [Supply Chain Anomalies](#2-supply-chain-anomalies)
9. [Try it Out in a Live Lab](#try-it-out-in-a-live-lab)
10. [Demo: Deploy an Application](#demo-deploy-a-application)
11. [Generate Traffic of Benign Behaviour](#generate-traffic-of-benign-behaviour)
12. [Create a Repeatable Positive Test](#create-a-repeatable-positive-test)
13. [Generate Runtime Attack](#generate-runtime-attack-normal-attack-that-abuses-cve)
14. [Generate Supply Chain Attack (WIP)](#generate-supply-chain-attack)
15. [License](#license-is-apache-20)


> **DISCLAIMER:**  
> The scripts are currently for rapid prototyping to iterate on a design the community will accept.  
> The regex is **not stable**—do **not** rely on AI for these profiles.   If you want to use them for your software:  
> **Run the scripts, then use your eyes to fix what the regex messed up.**
> Once the code is stable, (and if there is expressed interest/acceptance/funding etc) I ll create proper tooling
---
### What it looks like (in Kubescape format)
🚨 New Design Kubescape 4.0 will support user-defined-profiles, here an example using the kubescape CRDs 🚨 
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

A: Just like eBPF extends the Kernel, the above Profile are a superset of `seccomp` (Profiles incl FileAccess, Execs, ImageHashes, NetworkEndpoints and Capabilities) and can work real-time with user-defined profiles, but it doesnt require loading anything into the LSM. LSMs have a totally different life-cycle and granularity than applications. 
<img width="1334" height="665" alt="Screenshot 2025-09-08 at 09 47 48" src="https://github.com/user-attachments/assets/e3389c14-1472-478e-93bd-96880312911f" />

**THE MOST IMPORTANT DIFFERENCE is UX, granularity and timeing** and this enables transferring it between systems and making it transparent to users

## Example comparison of seccomp with BoB (for redis)
Seccomp is a well-established sandboxing mechanism that filters which syscalls are allowed from an application to be made to the kernel. Kubernetes [uses it since version 1.19](https://kubernetes.io/docs/tutorials/security/seccomp/)

For the KV-database `redis` in its most popular Helm-Chart, we traced out the `superset` of benign behavior across many k8s-versions/distros. In K8s, there is a [`RuntimeDefault` seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) profile that is shipped by default, the SBoB allowlists 99 syscalls, meaning the resulting difference will be detected as anomaly.
Generally speaking, a BoB profile will have a lower number of syscalls than a seccomp profile. There are many discussions on the internet on how [seccomp is difficult across architecture](https://github.com/kubernetes/kubernetes/issues/104696)

### An SBoB is a generalized and customizable Application Profile that alerts on anything not allowlisted
(The following summaries are output by the github workflow script that summarizes what the profile allows if each of the workloads is annotated with said SBoB profile)  WARNING: those scripts may not be fully stable.

#### For redis (in standalone form)
using the bitnami chart: For a DB, the user will need to supply network-ranges that are allowed.

| Component                   | Container         | Type          | Capabilities                        | Net    | Opens  | Execs  | Syscalls |
|-----------------------------|------------------|--------------|-------------------------------------|--------|--------|--------|----------|
| rs-bob-redis-master         | redis            | container    | DAC_OVERRIDE<br>DAC_READ_SEARCH<br>NET_ADMIN | 0      | 17     | 5      | 99       |

Applications of type DB are security sensitive, as they often store juicy content. The most interesting thing to anomaly detect is which `outbound network` connections are happening (exfiltration attempts).

If you are interested in using eBPF to monitor querys, see this course how [our friends from pixie](https://labs.iximiuz.com/courses/discoverebpf-0d7c6c54/lesson-1#dbs) achieve such observability.

#### For Tetragon (an OpenSource CNCF Security eBPF tool)

| Component                   | Container         | Type          | Capabilities                        | Net    | Opens  | Execs  | Syscalls |
|-----------------------------|------------------|--------------|-------------------------------------|--------|--------|--------|----------|
| rs-tetragon-operator        | tetragon-operator | container    | NET_ADMIN                           | 10     | 8      | 1      | 92       |
| rs-tetragon                 | export-stdout    | container    | none                                | 0      | 5      | 2      | 84       |
| rs-tetragon                 | tetragon         | container    | BPF<br>DAC_OVERRIDE<br>DAC_READ_SEARCH<br>NET_ADMIN<br>PERFMON<br>SYSLOG<br>SYS_ADMIN<br>SYS_PTRACE | 0      | 49     | 1      | 131      |

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

A BoB, is first of all a `vehicle` to transport the information of the runtime behavior. And only secondly, the runtime-anomaly generation method. The fact, that kubescape can rather straightforwardly consume them is a huge plus.

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
          URL=\"${SERVICE}.${NAMESPACE}.svc.cluster.local:${PORT}/ping.php?ip=${TARGET_IP}\"
          RESPONSE=$(curl -s \"$URL\")
          echo \"$RESPONSE\"
          echo \"$RESPONSE\" | grep -q \"Ping results for ${TARGET_IP}\"
          echo \"$RESPONSE\" | grep -q \"${TARGET_IP} ping statistics\"
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
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/bin/ls"],"exec":"/bin/ls","retval":0},"infectedPID":6972,"severity":5,"size":"4.1 kB","timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY","O_NONBLOCK","O_DIRECTORY","O_CLOEXEC"],"path":"/var/www/html"},"infectedPID":6972,"severity":1,"timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"sendmmsg"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960dbb6e0f6f1d9b7ebf3b"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"socketpair"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960dbb6e0f6f1d9b7ebf3b"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected domain request","arguments":{"addresses":["216.58.210.174"],"domain":"google.com.","port":50015,"protocol":"UDP"},"infectedPID":20611,"severity":5,"size":"4.1 kB","timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"getpeername"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960dbb6e0f6f1d9b7ebf3b"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/usr/bin/curl","google.com"],"exec":"/usr/bin/curl","retval":0},"infectedPID":20611,"severity":5,"size":"4.1 kB","timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected Service Account Token Access","arguments":{"flags":["O_RDONLY"],"path":"/run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token"},"infectedPID":20611,"severity":5,"timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY"],"path":"/run/secrets/kubernetes.io/serviceaccount/..2025_07_07_21_05_56.676258237/token"},"infectedPID":20611,"severity":5,"timestamp":"2025-05-22T17:16:24Z"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected system call","arguments":{"syscall":"fadvise64"},"infectedPID":15899,"md5Hash":"4e79f11b07df8f72e945e0e3b3587177","sha1Hash":"b361a04dcb3086d0ecf960dbb6e0f6f1d9b7ebf3b"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY"],"path":"/var/www/html/index.html"},"infectedPID":20581,"severity":1,"timestamp":"2025-07-07T21:22:04"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected file access","arguments":{"flags":["O_RDONLY","O_NONBLOCK","O_DIRECTORY","O_CLOEXEC"],"path":"/var/www/html"},"infectedPID":20503,"severity":1,"timestamp":"2025-07-07T21:21:53"}}
{"BaseRuntimeMetadata":{"alertName":"Unexpected process launched","arguments":{"args":["/bin/cat","/proc/self/mounts"],"exec":"/bin/cat","retval":0},"infectedPID":20527,"severity":5,"size":"4.1 kB","timestamp":"2025-07-07T21:22:08"}}
```

## Generate Supply Chain Attack
WIP

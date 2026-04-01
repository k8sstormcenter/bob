# Software Bill of Behavior SBoB 

> 🚨 Updated life-lab with signatures (alpha) and the new wildcards here https://labs.iximiuz.com/courses/nodeagent-51fe7b80/dungeon#archive

![KCEU26ROEDIGBERTSCHYInstantK8sRuntimeAnomalyDetection](https://github.com/user-attachments/assets/3013d87c-198b-4aa5-90c7-affa80495ac1)


<img width="2775" height="1998" alt="BoBLogoRegistered" src="https://github.com/user-attachments/assets/f78cb80b-e419-44bd-a13b-809ce9cfd4cd" />

We introduce the “Bill of Behavior” (BoB): a vendor-supplied profile detailing known benign runtime behaviors for software, designed to be distributed directly within OCI artifacts. 
Generated using eBPF, a BoB codifies expected syscalls, file access patterns, network communications, and capabilities. 
This empowers two things:
- **for the supply chain at deploy-time** (possibly in a staging env): we can use a detailed and highly specific such profile to verify an installer at client side to exclude tampering (see the npm incident from sept 8)
- **for continuous anomaly detection at runtime**: allowing end-users to infer malicious activity, to shrink their false positive noise and to have a vendor-supplied behavioural baseline, the generalized and more lightweight profile is used.

  
We foresee a massive scale benefit for the end-user, who does not have in-depth knowledge of the software by shifting authoring and maintaining custom security policies to the vendor, who knows their own software, has the test cases and can judge what part of the policies should be generalized.

Imagine a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ship it `with each update` . Just like a `Container Beipackzettel` 🌡️📦📃🩻
<img 
<img width="3226" height="2744" alt="BoBverticalboth_registered" src="https://github.com/user-attachments/assets/4696c374-289b-4449-9a5d-81f3682c01a2" />


That means the user receives a secure default runtime profile. They can customize it, or directly apply it for runtime detection. And which each update of the software,
get an uptodate runtimeprofile


> **Trademark:** Bill of Behavior is a registered trademark by Constanze Roedig, all rights reserved  
---

## Table of Contents

1. [Introduction](#software-bill-of-behavior---tooling-bobctl)
2. [Bill of Behavior (BoB) Overview](#software-bill-of-behavior---tooling-bobctl)
3. [A generalized ApplicationProfile](#software-bill-of-behavior---tooling-bobctl)
4. [FAQ](#faq)
5. [Example Comparison: Seccomp vs BoB](#example-comparison-of-seccomp-with-bob-for-redis)
    - [For redis (in standalone form)](#for-redis-in-standalone-form)
    - [For Tetragon (OpenSource CNCF Security eBPF tool)](#for-tetragon-an-opensource-cncf-security-ebpf-tool)
    - [Comparison of Deploy- vs Run-time for Pixie (OpenSource CNCF Observability eBPF suite)](#more-elaborate-comparison-of-the-shrinking-attack-surface-if-using-no-full-bau-profiles-for-cncf-pixie)
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
      path: /etc/apache2/⋯ #globs that generalize UUIDs or well-known FS structures
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



## FAQ
Q: Isnt this the same as SELINUX/APPARMOR profiles?   

A: Just like eBPF extends the Kernel, the above Profile are a superset of (Lists of recorded activity like incl FileAccess, Execs, ImageHashes, NetworkEndpoints, SystemCalls and Capabilities) and can work real-time with user-defined profiles, but it doesnt require loading anything into the LSM. LSMs have a totally different life-cycle and granularity than applications. 
<img width="1334" height="665" alt="Screenshot 2025-09-08 at 09 47 48" src="https://github.com/user-attachments/assets/e3389c14-1472-478e-93bd-96880312911f" />

**THE MOST IMPORTANT DIFFERENCE is UX, granularity and timeing** and this enables transferring it between systems and making it transparent to users

## Example comparison of seccomp with BoB (for redis)
Seccomp is a well-established sandboxing mechanism that filters which syscalls are allowed from an application to be made to the kernel. Kubernetes [uses it since version 1.19](https://kubernetes.io/docs/tutorials/security/seccomp/)

For the KV-database `redis` in its most popular Helm-Chart, we traced out the `superset` of benign behavior across many k8s-versions/distros. In K8s, there is a [`RuntimeDefault` seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/) profile that is shipped by default, the SBoB allowlists 99 syscalls, meaning the resulting difference will be detected as anomaly.
Generally speaking, a BoB profile will have a lower number of syscalls than a seccomp profile. There are many discussions on the internet on how [seccomp is difficult across architecture](https://github.com/kubernetes/kubernetes/issues/104696)

### An SBoB is a generalized and customizable Application Profile that alerts on anything not allowlisted


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
[give us feedback ](https://labs.iximiuz.com/courses/nodeagent-51fe7b80/dungeon#archive), report issues , raise PRs (contributing guidelines will follow)




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



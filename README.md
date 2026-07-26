# Software Bill of Behavior SBOB 
Imagine a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ships it `with each update` . Just like a Container Package-Insert (Packungsbeilage) 📦📃🩻


An SBOB is a vendor-supplied profile that provides contrast between known benign and malicious runtime behaviors.

It's understood to be an abstraction of linux kernel level behavior to express `intent` across systems:

- **to explicitely test for false-negatives**: each attack type can be verified as 'blind' or 'detectable'
- **for continuous anomaly detection at runtime**: an updated SBOB with each release allows end-users to calibrate their Detection/Reponse 

  

<img width="3226" height="2744" alt="BoBverticalboth_registered" src="https://github.com/user-attachments/assets/4696c374-289b-4449-9a5d-81f3682c01a2" />
We foresee a massive scale benefit for the end-user, who does not have in-depth knowledge of the software by shifting authoring and maintaining custom security policies to the vendor, who knows their own software, has the test cases and can judge what part of the policies should be generalized.
**Trademark:** Bill of Behavior is a registered trademark by Constanze Roedig, all rights reserved  
## Example 

A minimal SBOB for redis (the `database` app type)

![redis kill-chain — kubescape rule coverage](example/redis-client/redis-killchain.gif)


```bash
bobctl contrast --profile example/redis-client/sbobs/ap-redis.yaml --type database --expect reads-host-files --strict
```



🚨GOAL for 2027: 90 percent of all CNCF projects (that run on linux-k8s) get an SBOB 

### Auto-Tuning (preview)
This repo is currently a demo while I m working on a bob-agent that your AI can talk to such that an SBOB can be created for any application. DM me if you are an early adopter (on CNCF slack, Linkedin, or [K8sstormcenter slack](https://join.slack.com/t/k8sstorm/signup) . You can obviously create your own SBOB by hand, too) 


 ![tune](https://github.com/user-attachments/assets/110e715a-97ac-4b4e-990e-0e93eb930903)


### Format/Spec
![billofbehavior.com](https://billofbehavior.com/spec)


## FAQ
Q: Isnt this the same as SELINUX/APPARMOR/seccomp profiles?   

A: This a real-time, user-friendly `addition` to the classical methods, not a contradiction. SBOBs are aimed at detection and contrast


---


```bash
bobctl contrast --profile example/redis-client/sbobs/ap-redis.yaml --type database --expect reads-host-files --strict


kubectl apply -f example/redis-client/sbobs/       
kubectl apply -f example/redis-client/redis.yaml   
kubectl apply -f example/redis-client/client.yaml  
```

## What's in the redis-example

| file | role |
|---|---|
| `example/redis-client/redis.yaml` | the redis server  |
| `example/redis-client/client.yaml` | the **one allowed client** for this database type|

An SBOB is a *narrow* envelope that captures system-independent behavior.

### What a detection MEANS is different for each application type, but generally mapped to TTPs

Constructing a good SBOB means modelling an attack type (ideally not limited to a particular CVE) and measuring if it is detectable should it ever occur in the wild.

| Rule | ATT&CK | Fires when redis… | What a detection implies |
|---|---|---|---|
| R0001 Unexpected process | T1059 | spawns a non-redis process | **RCE** — Lua `io.popen`, module exec, injected command |
| R0040 Unexpected args | T1059 | a known binary runs with new args | living-off-the-land variant of the above |
| R1001 Drifted process | T1554 | runs a binary not in the image | a **dropped/implanted** tool executed |
| R1004 Process from mount | T1059 | execs from a mounted volume | payload delivered via a writable mount |
| R1000 Process from /dev/shm | T1620 | execs from shared memory | staged fileless-style payload |
| R1005 Fileless execution | T1620 | runs code from an anon memfd | **in-memory malware**, nothing on disk |
| R0002 File access anomaly | T1005 | reads/writes outside baseline | data staging / config tamper / reading `/etc/shadow` |
| R0010 Sensitive file access | T1552.001 | reads keys/tokens/secrets | **credential access** |
| R0006 SA-token access | T1552.001 | reads the k8s serviceaccount token | theft to **pivot to the API server** |
| R0008 Env from procfs | T1552 | reads another process' `environ` | secret/cred harvesting |
| R0007 Uses k8s API | T1613 | talks to kube-apiserver | a DB has no reason to — **recon/lateral** |
| R0005 DNS anomaly | T1071 | resolves a new domain | **C2 beacon** or exfil target lookup |
| R0011 Unexpected egress | T1041 | opens ANY outbound connection | **exfiltration / reverse shell** (server egress = 0) |
| R1003 SSH unexpected dest | T1021.004 | initiates SSH | **lateral movement** |
| R1007/8/9 crypto-mine | T1496 | spawns miner / hits pool domain / port | **resource hijack** |
| R0004 Capabilities anomaly | T1611 | uses a new Linux capability | **privilege escalation / escape prep** |
| R1006 unshare | T1611 | creates a new namespace | **container-escape** primitive |
| R0009 eBPF load | T1611 | loads an eBPF program | kernel-level **rootkit/tamper** |
| R1002 Kernel module load | T1547.006 | loads a kmod | **rootkit** |
| R1015 ptrace | T1055.008 | ptraces another process | **code injection / credential dumping** |
| R1030 io_uring | T1620 | uses io_uring | stealthy I/O — **detection evasion** |
| R0003 Syscall anomaly | T1106 | new syscall vs baseline | exploit primitive (broad signal) |
| R1010/R1012 sym/hardlink | T1222 | links over a sensitive file | **persistence / priv-esc** |
| R1011 ld_preload | T1574.006 | sets `LD_PRELOAD` | library-injection **persistence** |
| R2000 Exec to pod | T1609 | someone `kubectl exec`s in | interactive intrusion (or admin — verify) |
| R2001 Port-forward to pod | T1609/T1090 | someone port-forwards in | access **tunnel** to the datastore |




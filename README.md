# Software Bill of Behavior SBOB 
Imagine a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ships it `with each update` . Just like a Container Package-Insert (Packungsbeilage) 📦📃🩻


An SBOB is a profile that provides contrast between intended benign and malicious runtime behaviors. It can be signed, bundled

It's understood to be an abstraction of linux kernel level behavior to express `intent` across systems:

- **to explicitely test for false-negatives**: each attack type can be verified as 'blind' or 'detectable'
- **for continuous anomaly detection at runtime**: allows end-users to calibrate their Detection/Reponse 

  

<img width="3226" height="2744" alt="BoBverticalboth_registered" src="https://github.com/user-attachments/assets/4696c374-289b-4449-9a5d-81f3682c01a2" />
We foresee a massive scale benefit for the end-user, who does not have in-depth knowledge of the software by shifting authoring and maintaining custom security policies to the vendor, who knows their own software, has the test cases and can judge what part of the policies should be generalized.

**Trademark:** Bill of Behavior is a registered trademark by Constanze Roedig, all rights reserved  

![redis kill-chain — kubescape rule coverage](example/redis-client/redis-killchain.gif)

[Specification](https://billofbehavior.com/bob/docs/spec/) · [Kubescape reference implementation](https://kubescape.io/docs/operator/bill-of-behavior/)

## TLDR — run bobctl (redis)

```bash
# bobctl (x86_64, pinned)
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.2/bobctl-linux-amd64
chmod +x bobctl && sudo mv bobctl /usr/local/bin/

# static contrast (no cluster)
bobctl contrast --profile example/redis-client/sbobs/cp-redis.yaml --type database --expect reads-host-files --strict

# cluster: rc4 kubescape stack
make kubescape
make alertmanager

# deploy redis + bind the SBoB
kubectl apply -f example/redis-client/sbobs/
kubectl apply -f example/redis-client/redis.yaml
kubectl apply -f example/redis-client/client.yaml

# run the attack kill-chain
bobctl attack --attack-suite example/redis-attacks.yaml -n redis-demo --service redis --service-port 6379 --format table

# auto-tune
bobctl tune --profile <learned-cp-name> --functional-tests example/redis-functional-tests.yaml \
  --attack-suite example/redis-attacks.yaml --service redis --service-port 6379 --ks-namespace honey -n redis
```




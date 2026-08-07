# Software Bill of Behavior SBOB 

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/k8sstormcenter/bob/badge)](https://scorecard.dev/viewer/?uri=github.com/k8sstormcenter/bob)

Imagine a software vendor distills all their knowledge of their own testing into a standard file and ships it `with each update` . Just like a Container Package-Insert (Packungsbeilage) 📦📃🩻


An SBOB is a profile that provides contrast between intended benign and malicious runtime behaviors. 

It's understood to be an abstraction of linux kernel level behavior to express `intent` across systems:

- **to explicitly test for false-negatives**: each attack type can be verified as 'blind' or 'detectable'
- **for continuous anomaly detection at runtime**: allows end-users to calibrate their Detection/Reponse 

 ![redis kill-chain — kubescape rule coverage](example/redis/redis-killchain.gif) 

 🚨GOAL for 2027: 90 percent of all CNCF projects (that run on linux-k8s) get an SBOB 

<img width="3226" height="2744" alt="BoBverticalboth_registered" src="https://github.com/user-attachments/assets/4696c374-289b-4449-9a5d-81f3682c01a2" />

`scale is hard in security` and thats the main reason why a solid runtime expectation `needs` to be distributed from the entity that has the knowledge of the implementation details AND the test cases AND the tooling AND the requirements.


**Trademark:** Bill of Behavior is a registered trademark by Constanze Roedig, all rights reserved  





### Stay informed when more applications get SBOBs
Subscribe to the newsletter [https://billofbehavior.com](https://fusioncore.kit.com/86141f7462), follow us on [Linkedin](https://www.linkedin.com/in/croedig/), or talk to us on [slack](https://join.slack.com/t/k8sstorm/signup) 

Next up release: Argo CD with all of its seven components:

![Argo CD kill-chain — all 7 containers](example/argocd/argocd-killchain.gif)





### Format/Spec
[Specification](https://billofbehavior.com/bob/docs/spec/) for the [Kubescape reference implementation](https://kubescape.io/docs/operator/bill-of-behavior/).






## TLDR — run bobctl
Here for the vulnerable redis example:

```bash
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.2/bobctl-linux-amd64
chmod +x bobctl && sudo mv bobctl /usr/local/bin/


make kubescape
make alertmanager


kubectl apply -f example/redis/sbobs/
kubectl apply -f example/redis/redis.yaml
kubectl apply -f example/redis/client.yaml


bobctl attack --attack-suite example/redis-attacks.yaml -n redis-demo --service redis --service-port 6379 --format table

kubectl logs -n honey -l app=node-agent -c node-agent
```

## Try it out in a lab with a k3s and a k8s
Public again on [Iximiuz Labs](https://labs.iximiuz.com/courses/bill-of-behaviour-c070da3a/1vendor/lesson-1) 




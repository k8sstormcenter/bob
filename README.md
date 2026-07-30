# Software Bill of Behavior — SBOB 📦📃🩻

Imagine a software vendor (like a pharmaceutical company) distills all their knowledge of their own testing into a standard file and ships it `with each update`. Just like a Container Package-Insert (Packungsbeilage).

An SBOB is a signed profile that provides **contrast** between intended benign and malicious runtime behavior. Like a contrast agent (Kontrastmittel), it makes the software's *side effects* visible: a connection to an endpoint that was never declared, a read of a key in a path that was never intended, a binary that was never meant to run.

It is an abstraction of Linux kernel-level behavior that expresses `intent` across systems:

- **to explicitely test for false-negatives**: each attack type can be verified as `blind` or `detectable`
- **for continuous anomaly detection at runtime**: end-users calibrate their Detection/Response against a baseline the vendor — not the operator — provides

> **Für iX-/Heise-Leser 🇩🇪 — willkommen!** Die SBOB ist die „Packungsbeilage" für Container: ein vom Hersteller signiertes, präskriptives Laufzeitprofil, das die Absicht der Software abbildet — statt sie am laufenden System zu erraten. Referenzimplementierung im CNCF-Projekt **Kubescape** (eBPF). Spezifikation, Demo und Quickstart weiter unten. Wenn es Sinn ergibt: ein ⭐ freut mich.

<img width="3226" height="2744" alt="BoBverticalboth_registered" src="https://github.com/user-attachments/assets/4696c374-289b-4449-9a5d-81f3682c01a2" />

We foresee a massive scale benefit for the end-user, who does not have in-depth knowledge of the software, by shifting authoring and maintaining custom security policies to the vendor, who knows their own software, has the test cases, and can judge what part of the policies should be generalized.

## See it — a Redis kill-chain against its SBOB

SBOB contrast is produced by application type. Redis is an example of `db`.

![redis kill-chain — kubescape rule coverage](example/redis-client/redis-killchain.gif)

```bash
bobctl contrast --profile example/redis-client/sbobs/ap-redis.yaml --type database --expect reads-host-files --strict
```

## Why this exists

Runtime security has existed for decades — seccomp, AppArmor, SELinux, and a shelf of CNCF tools on top. That was never the hard part. The hard part is *who writes and maintains the profile*: the quality of any runtime detection stands or falls with understanding the application well enough to predict its behavior — at every single release.

Today that knowledge sits with the vendor, but the profiles are written by the operator, who is decoupled from the release and estranged from its intent. So profiles get configured too loosely (real attacks stay invisible — **false negatives**) or too tightly (analysts drown in irrelevant alerts — **false positives**, and in enforcing mode the control breaks the app). And observation alone cannot fix it: a profile learned from a running system captures only *what happened*, not *what was allowed to happen* — so if an intruder is already inside, it learns the malicious behavior as "normal".

An SBOB moves the responsibility to where the knowledge lives. Because the profile abstracts over the *stable* Linux ABIs (paths, args, capabilities, endpoints) rather than chasing low-level detail, it is portable across heterogeneous systems and readable by humans. That deliberate imprecision is the feature, not a defect — it is what lets it scale. And false positives finally get a value: they now mean either a gap in the vendor's QA, or the operator running the software off-label. Either way, worth knowing.

## Does it help with CRA, NIS2, DORA?

To be clear: an **SBOB is not a CRA-mandated artifact**, and nothing here claims otherwise. It is a concrete technical means to *document expected runtime behavior*, make deviations detectable, and give operators of regulated environments (CRA Art. 13 evidence of a vendor's security QA, NIS2 incident detection, DORA "mechanisms to detect anomalous activity") something better than a per-release guessing game.

## TLDR — run bobctl (redis)

```bash
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.2/bobctl-linux-amd64
chmod +x bobctl && sudo mv bobctl /usr/local/bin/

make kubescape
make alertmanager

kubectl apply -f example/redis-client/sbobs/
kubectl apply -f example/redis-client/redis.yaml
kubectl apply -f example/redis-client/client.yaml

bobctl attack --attack-suite example/redis-attacks.yaml -n redis-demo --service redis --service-port 6379 --format table

kubectl logs -n honey -l app=node-agent -c node-agent
```

Each attack lands as `detectable` or `blind`, and DNS/typosquatting/exploit anomalies are raised in real time by the node-local agent.

## Reference implementation

SBOB is implemented as a reference in the CNCF Incubating project **Kubescape**, developed further under two research grants (FFG and Netidee). Only two components are needed: a per-node `node-agent` (eBPF sensing via Inspektor Gadget) and a `storage` API server for lifecycle, rules and alerting. Some parts (signature verification, tamper detection) are still experimental.

- **Specification:** [billofbehavior.com/bob/docs/spec](https://billofbehavior.com/bob/docs/spec/)
- **Kubescape reference:** [kubescape.io — Bill of Behavior](https://kubescape.io/docs/operator/bill-of-behavior/)

## Roadmap

Next up: **Argo CD**, with all of its seven components.

![Argo CD kill-chain — all 7 containers](example/argocd/argocd-killchain.gif)

🚨 **Goal for 2027:** 90 percent of all CNCF projects (that run on Linux/K8s) ship an SBOB — with validation tests — with every release. The SBOM proved that standardization works when the effort lands where the knowledge sits. SBOB does the same for runtime behavior.

## Stay informed / contribute

- ⭐ **Star this repo** — it helps others find it, and tells me which application type to profile next.
- Get a note when new SBOBs ship: [billofbehavior.com](https://billofbehavior.com)
- Talk to us on the [K8sStormCenter Slack](https://join.slack.com/t/k8sstorm/signup) or on [LinkedIn](https://www.linkedin.com/in/croedig/)
- Open an issue with the application type you'd like to see get an SBOB.

---

**Trademark:** Bill of Behavior is a registered trademark by Constanze Roedig, all rights reserved.
**License:** Apache-2.0

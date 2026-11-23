# An SBoB for an application nobody prepared: NATS

NATS is a CNCF project that this repository has no simulation, no path list and no traffic for. This walkthrough takes you from an empty cluster to a bound SBoB for it, with the public `bobctl` only. Plan for about 25 minutes, most of it waiting for the agent to learn.

What you get at the end:

- an SBoB for the `nats` container: what it executes, opens and connects to, generalized so that it survives a restart, plus a subtract list of what stays denied for a Go server (a shell-driven download, a credential read, cloud metadata, ...);
- usual traffic that stays silent under that SBoB;
- an alert when you do something in the container that the server never does.

What you do not get: the simulation of common CVE types and the D, N, P numbers. Those run only in this repository's `Contrast` workflow.

## 0. What you need

- A Kubernetes cluster you may break (k3s, kind, a playground), `kubectl`, `helm`, `make`, `python3`, `jq`.
- This repository checked out, and `docker login` done for the registry the node agent image comes from (`make kubescape` tells you if it is missing).

```bash
git clone https://github.com/k8sstormcenter/bob && cd bob
curl -fsSL -o bobctl https://github.com/k8sstormcenter/bob/releases/download/v0.1.30/bobctl-linux-amd64
chmod +x bobctl && sudo mv bobctl /usr/local/bin/
```

You need bobctl v0.1.30 or newer. Older releases cannot write the subtract list and do not have the `conditions` and `signatures` verbs.

## 1. Install the agent

```bash
make kubescape KUBESCAPE_CHART_VER=1.41.0-duckling193 KS_LEARN_PERIOD=8m
kubectl -n honey rollout status ds/node-agent --timeout=600s
kubectl -n honey rollout status deploy/storage --timeout=300s
kubectl -n honey get rules default-rules -o json | python3 scripts/enable-rules.py R0002 | kubectl replace -f -
```

The last line switches on the file access rule, which ships switched off.

## 2. Install NATS the way its project documents it, and start usual traffic

```bash
helm repo add nats https://nats-io.github.io/k8s/helm/charts/ && helm repo update nats
helm install nats nats/nats --version 2.15.3 -n nats --create-namespace
kubectl -n nats rollout status sts/nats --timeout=180s
kubectl apply -f example/nats/traffic.yaml
kubectl -n nats logs deploy/traffic -f      # wait for "workload-cycle-ok", then Ctrl-C
```

`traffic.yaml` is a client that publishes, subscribes, does request/reply, runs a small benchmark and reads the monitoring endpoint, in a loop. It stands for what your users do. The SBoB can only be as good as this traffic.

## 3. Do what an operator does, while the agent learns

The agent learns for 8 minutes from the start of the pod. Whatever you run in the container in that time becomes part of the profile, so run what you would run in production and nothing else:

```bash
for i in 1 2 3; do
  kubectl -n nats exec nats-0 -c nats -- nats-server --version
  kubectl -n nats exec nats-0 -c nats -- nats-server -t -c /etc/nats-config/nats.conf
  sleep 60
done
```

Then wait until the learned profile is complete:

```bash
until kubectl get containerprofiles -n nats -l kubescape.io/workload-name=nats,kubescape.io/workload-container-name=nats \
  -o jsonpath='{.items[*].metadata.annotations.kubescape\.io/status}' | grep -q completed; do sleep 20; done
```

## 4. Turn what was learned into an SBoB

```bash
mkdir -p nats-sbob/in
P=$(kubectl get containerprofiles -n nats -l kubescape.io/workload-name=nats,kubescape.io/workload-container-name=nats -o jsonpath='{.items[0].metadata.name}')
bobctl get "$P" -n nats -o yaml > nats-sbob/in/learned.yaml

TRAITS=$(bobctl conditions -n nats --pod nats-0 --container nats -o traits)
bobctl generalize -d nats-sbob/in --sbob nats-nats -n nats --exec-form regex \
  --signature-type queue --trait auto $(for t in $(echo "$TRAITS" | tr ',' ' '); do printf -- '--trait %s ' "$t"; done) \
  --ecosystem auto --entry-binary registry --open-tool-args --script-skeletons --keep-rule-syscalls --capped-exec regex --drop-endpoints \
  -o nats-sbob/sbob.yaml | tee nats-sbob/generalize.log
bobctl validate --file nats-sbob/sbob.yaml
```

- `--sbob nats-nats` is `<binding label>-<container>`.
- `--signature-type queue` is the only thing you tell bobctl about NATS. `bobctl signatures list` shows the types.
- Read `nats-sbob/generalize.log`: the line `signature traits:` says which language ecosystem bobctl recognised, and every `not subtracting` line names something it left out of the subtract list because NATS itself was seen doing it.
- Read `nats-sbob/sbob.yaml`. It is yours to review before it goes anywhere.
- `validate` prints one `WARN` line about `argv[0]=nats-server` and then `OK`. The warning is expected.

On the cluster this was written on, bobctl found `go,shared-pid,open-egress`, left nothing out of the subtract list, and the SBoB had 4 exec and 26 open entries.

## 5. Bind it

```bash
bobctl apply -f nats-sbob/sbob.yaml -n nats
helm upgrade nats nats/nats --version 2.15.3 -n nats --reuse-values --set-string 'podTemplate.merge.metadata.labels.kubescape\.io/user-defined-profile=nats'
kubectl -n nats rollout status sts/nats --timeout=180s
```

The label goes on the pod template through the chart, so that the chart does not remove it on the next upgrade. The pod restarts and is now checked against your SBoB.

## 6. Usual traffic must stay silent

Let the traffic run for five minutes, repeat the operator commands of step 3 once, then count the alerts for the bound pod:

```bash
UID_NOW=$(kubectl -n nats get pod nats-0 -o jsonpath='{.metadata.uid}')
kubectl -n honey logs ds/node-agent --since=10m | grep -a '"RuleID"' | sed 's/^[^{]*//' \
  | jq -r --arg u "$UID_NOW" 'select(.RuntimeK8sDetails.podUID==$u and .RuntimeK8sDetails.containerName=="nats") | [.RuleID, .RuntimeProcessDetails.processTree.comm, (.BaseRuntimeMetadata.arguments.message // "")] | @tsv' \
  | sort | uniq -c
```

Nothing printed means the SBoB fits. One failed traffic cycle right at the restart of step 5 is normal. A line here means the learn window missed something your traffic or your operators do: do it during step 3 next time, and repeat from step 2.

## 7. What the server never does must alert

These are things a NATS server has no reason to do. Each is harmless by itself:

```bash
kubectl -n nats exec nats-0 -c nats -- sh -c 'id; cat /etc/shadow > /dev/null; wget -qO- -T 3 http://169.254.169.254/latest/meta-data/ ; true'
```

Run the command of step 6 again. You should now see alerts: a process that was never learned, a credential file read, a connection to the cloud metadata address.

## 8. Clean up

```bash
helm uninstall nats -n nats && kubectl delete ns nats
```

## What to tell us

- Which step did not work as written.
- Whether `sbob.yaml` is something you would ship: too broad, too narrow, unreadable?
- Whether step 6 was silent and step 7 was not.

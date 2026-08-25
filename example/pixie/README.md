# Pixie (vizier) SBoBs

Generalised SBoBs for the Pixie in-cluster components — the vizier data/control plane that runs on
a PG. Pixie Cloud and the `px` CLI are out of scope.

## Where these came from

Recorded on a naked k3s rig with fork-kubescape (node-agent `rc-sofia-port0fix`, storage `v0.0.303`):

1. kubescape installed first, with `pl` / `px-operator` / `olm` **removed** from `excludeNamespaces`
   (bob's default excludes all three, i.e. all of pixie).
2. Capture started, then pixie deployed — so the vizier **cold boot** is inside the learning window.
3. Two rounds of perf load (~104 min total) inside a 2 h window: a web service + continuous client,
   plus exec/DNS/kubectl churn against `pl`, so PEM, kelvin and query-broker all did real work.
4. ContainerProfiles dumped **per object** (`kubectl get <cp> -o yaml`), never as a LIST — a LIST
   against the kubescape aggregated apiserver returns objects with the heavy spec fields stripped
   and every profile looks empty.

## How they were generalised

`tools/collapse_tuner.py` is a faithful offline port of the collapse analysis in
`bobctl v0.1.3-rc1` (`pkg/profile/pathanalysis.go` + `pkg/autotune/collapse.go`): same
`splitPath`, same every-depth prefix walk, same `looksGenerated` regexes
(uuid / hex{8,} / digits{3,} / `sess_|session_|tmp_|cache_`), same noisy test
(`uniqueChildren >= threshold || hasGenerated`) and the same `suggestThreshold` ladder.

Running it offline avoids needing a live cluster; `bobctl collapse --apply` does the same analysis
against a running cluster and writes a `CollapseConfiguration` CRD.

`tools/make_sbobs.py` then applies those collapse decisions and a portability pass:

| generalisation | why |
|---|---|
| children under noisy prefixes → `⋯` | unbounded cardinality (kernel headers, `/tmp`, cgroup slices) |
| `/lib/modules/<kver>/` → `/lib/modules/⋯/` | otherwise the SBoB pins to one kernel build |
| `/.build-id/<hh>/<hash>` → `⋯` | content-addressed, changes every rebuild |
| drop `statefulset.kubernetes.io/pod-name`, `apps.kubernetes.io/pod-index`, `pod-template-hash`, `controller-revision-hash` | pins the selector to a single pod |
| drop `app.kubernetes.io/version`, `helm.sh/chart` | breaks on chart upgrade |
| drop kube-apiserver ClusterIP (`10.43.0.1` / `10.96.0.1`) | distro-specific (k3s 10.43/16 vs kubeadm 10.96/12) |
| drop rig-local DNS suffix and the perf-load harness peers | environment-specific, not part of pixie |

## Result

| component / container | opens before | after |
|---|---|---|
| vizier-pem / pem | 568 | 324 |
| kelvin / app | 172 | 145 |
| vizier-metadata / app | 42 | 29 |
| vizier-query-broker / app | 41 | 36 |
| vizier-cloud-connector / app | 35 | 31 |
| pl-nats | 13 | 11 |
| every `*-wait` init container | 63 | 9 |

Network policy survives generalisation well because pixie's own egress is largely
**selector-based** (`podSelector` on `name: vizier-metadata`, `name: pl-nats`, `k8s-app: kube-dns`),
which is portable as-is; only the API-server ClusterIP needed removing.

## Namespaces

Pixie occupies **three** namespaces, and all three must be out of `excludeNamespaces` for
node-agent to profile them (bob's default excludes all three):

| namespace | contents | SBoBs |
|---|---|---|
| `pl` | vizier data/control plane — pem, kelvin, query-broker, metadata, cloud-connector, nats | `sbobs/` (14) |
| `px-operator` | `vizier-operator`, the CatalogSource pod, OLM bundle-unpack Jobs | `sbobs-operator/` (1) |
| `olm` | `olm-operator`, `catalog-operator` | `sbobs-operator/` (2) |

Two workloads in `px-operator` are deliberately **not** profiled:

- the **OLM bundle-unpack Jobs** (`23864b92…-pull/-extract/-util`) — their names carry the bundle
  digest and change on every install, so a user-defined profile can never bind to them;
- the **CatalogSource pod** (`pixie-operator-index-<random>`) — bare pod with a generated suffix.

Both are short-lived and their raw recordings are kept under `recorded/px-operator/` for reference.

## Raw recordings

`recorded/{pl,px-operator,olm}/` holds the **unmodified** ContainerProfiles these SBoBs were
generalised from — exactly as dumped by a per-object `kubectl get <cp> -o yaml`. Keep them: they are
the evidence behind every allowlist entry, and re-generalising with a different threshold only needs
`tools/`, not another recording run.

## Deploying

`distros.sh` installs **upstream** Pixie (OLM → px-operator → Vizier CR) and binds the SBoBs.
Pixie Cloud and the `px` CLI are not involved; without a `PX_DEPLOY_KEY` the vizier still comes
up and is profiled, it just does not register with the cloud.

```bash
./distros.sh deploy    # olm + px-operator + Vizier CR, wait for the mesh
./distros.sh sbob      # apply sbobs/ and label the workloads
./distros.sh all       # both, then status
./distros.sh status    # which pod is bound to which profile
```

Binding is per component. `Vizier.spec.pod.labels` applies **one shared** label map to every
vizier pod, which cannot express a different profile per component, so `distros.sh` patches each
workload's pod template with its own `kubescape.io/user-defined-profile` and then rolls it —
node-agent binds a user-defined profile at **container start**, so the label has to be present
before the pod is created.

| workload | kind | profile |
|---|---|---|
| `vizier-pem` | DaemonSet | `vizier-pem-pem` |
| `kelvin` | Deployment | `kelvin` |
| `vizier-query-broker` | Deployment | `vizier-query-broker` |
| `vizier-cloud-connector` | Deployment | `vizier-cloud-connector` |
| `vizier-metadata` | StatefulSet | `vizier-metadata` |
| `pl-nats` | StatefulSet | `pl-nats-pl-nats` |

px-operator reconciles the Vizier CR, so a vizier upgrade or operator resync can drop these
pod-template labels — re-run `./distros.sh sbob` afterwards and confirm with `status`.

## Regenerating

```bash
python3 tools/collapse_tuner.py <per-cp-dir> pl 10          # analysis report
python3 tools/make_sbobs.py     <per-cp-dir> sbobs pl 10     # emit SBoBs
```

## Caveats

- `vizier-pem` legitimately opens *other* components' binaries (kelvin, operator, catalog) and large
  parts of `/host` — it is a node-wide profiler, so its SBoB is broad by nature.
- These were learned on a **tailnet** rig, where CoreDNS forwards to Tailscale MagicDNS
  (`100.100.100.100`, RFC 6598). That peer is filtered out here, but re-check egress if you re-record
  somewhere else.
- Two `qb-wait` profiles exist for `vizier-pem` (one per node); they are identical after
  generalisation apart from recorded syscalls.

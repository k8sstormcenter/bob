# Injecting the kubescape overlay into a CNCF project via `.project`

**Status:** design note, unimplemented. Target demo: Pixie.

The idea: a CNCF project should be able to declare *"here is how my workloads behave"* the
same way it already declares its security policy and its licence — as canonical, machine-readable
metadata — so that anyone running the project can bind a behavioural baseline without the project
having to ship or endorse a security vendor.

This note works out whether `.project` can carry that, and concludes it can — but **not** in the
shape the phrase "inject the chart" suggests.

---

## 1. What `.project` actually is

`.project` is a CNCF automation convention: a **separate metadata repository per project**, holding
canonical project metadata, bootstrapped from the CNCF landscape, CLOMonitor and GitHub governance
files, and validated in CI.

- utility and schema: [`cncf/automation/utilities/dot-project`](https://github.com/cncf/automation/tree/main/utilities/dot-project)
- schema reference: `SCHEMA.md` in that directory, currently `schema_version: "1.0.0"`
- worked example: [`dapr/.project`](https://github.com/dapr/.project)

**Pixie already has one:** [`pixie-io/.project`](https://github.com/pixie-io/.project) — containing
`project.yaml`, `maintainers.yaml`, `CODEOWNERS`, and a `validate.yaml` workflow. So there is
nothing to bootstrap; the demo starts from a live repo.

Its `project.yaml` today carries `slug`, `name`, `description`, `repositories`, `website`,
`security` (policy + advisory contact), `governance`, `legal`, `documentation`, `landscape`, and a
`maturity_log`. Note the two commented-out `TODO` blocks for `package_managers` — Pixie has not
declared registry identifiers yet.

## 2. The constraint that decides the design

From `SCHEMA.md`:

> **Unknown fields are rejected** — any field not in this schema causes a validation error.

Two consequences, and they kill the obvious approaches:

- **You cannot put a Helm chart in `.project`.** It is a metadata repo with a fixed schema. There is
  no file-drop surface and no blob field.
- **You cannot add a custom key.** `x-kubescape:` or `runtime_profiles:` will fail `validate.yaml`
  and block the merge. There is no extension escape hatch in 1.0.0.

So "injection" here can only mean one thing: **`.project` becomes the discovery index, not the
delivery mechanism.** The chart and the profiles live where they already live; `.project` is how a
consumer finds them without us having to know anything about the project in advance.

That is a weaker claim than "ship kubescape with Pixie" — and it is the honest one. It is also
enough for the demo, because discovery is the part that does not currently exist.

## 3. Three routes, ranked by how soon they work

### Route A — use existing fields (works today, zero schema change)

Two fields in the current schema are semantically defensible carriers:

| field | type | what we would put there |
|---|---|---|
| `security.threat_model` | `PathRef` | URL of the project's recorded behaviour profile + the decisions it encodes |
| `audits[]` | `Audit[]` (`date`, `type`, `url`) | one entry per recorded profiling run; `type` is free text |

`security.threat_model` is the better fit. A set of tier profiles *is* a threat-model artifact: it
states what the workload is expected to do and therefore what would be anomalous. Pointing it at a
document that happens to also contain applyable YAML is not a stretch of the field's meaning.

```yaml
security:
  policy:
    path: "https://github.com/pixie-io/pixie/blob/main/SECURITY.md"
  threat_model:
    path: "https://github.com/k8sstormcenter/bob/blob/main/example/pixie/README.md"
  contact:
    advisory_url: "https://github.com/pixie-io/pixie/security/advisories/new"
```

**Honest limitation:** this is a human-readable pointer. Nothing machine-consumable is promised by
the schema — no version, no digest, no content type. A consumer has to know by convention that the
URL leads to profiles. It demonstrates the idea; it does not scale past a demo.

### Route B — propose a schema field (the actual mechanism)

The real answer is a PR to `cncf/automation`, not to Pixie:

```yaml
runtime_profiles:
  - format: "kubescape/containerprofile-v1beta1"
    path: "oci://ghcr.io/k8sstormcenter/pixie-profiles:<TAG>"
    covers: ["pl", "px-operator", "olm"]
```

Arguments that make this more than vendor-specific plumbing:

- it is **format-tagged**, so it is not a kubescape field — Falco, Tetragon or a NetworkPolicy
  bundle fit the same shape;
- it is a **pointer**, consistent with every other field in the schema (`policy`, `threat_model`,
  `adopters` are all `PathRef`);
- it answers a question CLOMonitor-style tooling already asks — *does this project describe its own
  runtime behaviour?* — which is closer to a maturity signal than to a product integration.

Cost: a schema version bump and TOC-adjacent review. This is the slow path and should be opened as
a discussion issue before any code.

### Route C — `package_managers` for distribution

Orthogonal to A and B, and independently useful. Pixie's `project.yaml` has the block commented out
with a `TODO`. If the profiles ship as an OCI artifact, they become addressable the same way images
are:

```yaml
package_managers:
  docker: "pixie-io/pixie"
  oci: "ghcr.io/k8sstormcenter/pixie-profiles"
```

Check `SCHEMA.md` for the accepted key set before assuming `oci` is allowed — `package_managers` is
`map[string](string|string[])`, but the validator may constrain the keys. **Unverified.**

## 4. The Pixie demo

Recommended shape: **Route A end to end, with Route B opened as a discussion in parallel.** Route A
is demonstrable in an afternoon and makes the argument for B concrete rather than hypothetical.

### 4.1 What we already have

Profiles were recorded against a live Pixie install earlier — the vizier PEM alone produced 568
opens across 26 ContainerProfiles. That is the raw material; it needs generalising into tier-shaped
SBoBs before it is publishable (raw recordings encode one cluster's addresses and paths).

### 4.2 Steps

1. **Publish the profiles.** Land `example/pixie/` in this repo: generalised SBoBs, a `README.md`
   that is the artifact `threat_model` will point at, and a `distros.sh` that deploys upstream Pixie
   and binds the labels. Follow the layout of `example/3tier-baseline/`.

2. **Install the overlay against real Pixie.**

   ```bash
   make kubescape          # chart kubescape-operator 1.40.3, ns honey, kubescape/values.yaml
   make alertmanager
   ```

   The kubescape `values.yaml` in this repo has historically **excluded the Pixie namespaces** —
   check and remove that exclusion before recording, or the run is empty.

   Pin the fork build:

   ```bash
   # TODO: fill in the rogue tag. Could not enumerate ghcr tags without read:packages;
   # do not guess it — take it from the build workflow run that produced it.
   IMAGE_TAG=<rogue-tag>
   ```

   The `-rogue` line carries the signing / benchmark work (`cmd/sign-object`,
   `benchmark/signing/`, `enable-signing.sh`). If the demo is meant to show *signed* profiles —
   which is the interesting story for a CNCF project consuming a third-party baseline — that is the
   build to use, and `set-signature-verification.sh` is already wired into `make kubescape`.

3. **Open the `.project` PR.** One field, against `pixie-io/.project`:

   ```yaml
   security:
     threat_model:
       path: "https://github.com/k8sstormcenter/bob/blob/main/example/pixie/README.md"
   ```

   Small, reversible, and reviewable by maintainers who do not have to care about kubescape. It
   should pass `validate.yaml` unchanged — `threat_model` is an existing `PathRef`. **Verify against
   the validator before opening**, do not assume.

4. **Close the loop.** A short script that reads `pixie-io/.project`, resolves `threat_model`,
   fetches the profiles and applies them. That script *is* the demo — it shows a consumer binding a
   baseline to a CNCF project knowing only the project's slug.

## 5. Risks and open questions

- **`threat_model` is a semantic stretch, and maintainers may say so.** It is defensible but it is
  not what the field was minted for. If Pixie pushes back, that rejection is itself the argument for
  Route B, and should be quoted in the `cncf/automation` discussion rather than argued around.
- **Nothing in `.project` is versioned or digest-pinned.** A URL can change under a consumer with no
  signal. Route B should carry a digest; Route A cannot.
- **Profiles are cluster-shaped.** Recorded SBoBs encode addresses, node names and volume paths from
  the cluster they were learned on. Publishing them raw would push one lab's topology into a CNCF
  project's metadata. They must be generalised first, and the generalisation reviewed.
- **`package_managers` key set is unverified** — see Route C.
- **The rogue tag is unfilled.** Deliberately left as a placeholder above.
- **Scope discipline.** This puts a third-party pointer in a CNCF project's canonical metadata.
  Whatever we point at has to be maintained at the standard that implies, or we should not open the
  PR at all.

## 6. What this is not

Not a proposal that Pixie depend on, vendor, or endorse kubescape. Nothing is added to the Pixie
repo, no chart is bundled, and no runtime component is introduced into the project's install path.
The single proposed change to anything Pixie owns is one URL in `project.yaml`, which a maintainer
can revert in one commit.

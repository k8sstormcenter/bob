NAME := bobctl
VERSION ?= 0.1.0
BUILD_DIR := bin

GO ?= go
GO_VERSION ?= 1.24
KUBESCAPE_CHART_VER ?= 1.40.3-sign-rc2

OUTPUT_PATH := $(BUILD_DIR)/$(NAME)
HELM := $(shell which helm)

#CURRENT_CONTEXT := $(shell kubectl config current-context)
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m | sed 's/x86_64/amd64/')

GO_LDFLAGS := -s -w -X main.version=$(VERSION)
REPO_ROOT := $(shell git rev-parse --show-toplevel)


.PHONY: all
all: build

.PHONY: build
build: $(OUTPUT_PATH)

$(OUTPUT_PATH): $(GO_FILES)
	@echo "Building $(NAME) for $(OS)/$(ARCH)..."
	@mkdir -p $(dir $(OUTPUT_PATH))
	cd pkg && CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)" -o ../$(OUTPUT_PATH) ./main.go
	@echo "Build complete: $(OUTPUT_PATH)"

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete."

.PHONY: docker-build
docker-build:
	@echo "Running docker build $(NAME)..."
	docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/k8sstormcenter/$(NAME):latest -f Dockerfile .

.PHONY: run
run: build
	@echo "Running $(NAME)..."
	@$(OUTPUT_PATH)

.PHONY: mac-prep
mac-prep:
	docker buildx create --name mybuilder --driver docker-container --use

.PHONY: tetragon
tetragon:
	-$(HELM) repo add cilium https://helm.cilium.io
	-$(HELM) repo update
	-$(HELM) upgrade --install tetragon cilium/tetragon -n bob --create-namespace --values honeycluster/honeystack/tetragon/values.yaml
	-kubectl wait --for=condition=Ready pod -l app.kubernetes.io/name=tetragon -n bob --timeout=5m 

# ── Unified deploy targets (used by CI and local-ci.sh) ─────────────────────
# Usage: make deploy-<app>
# Each target handles its own deploy method (manifest, helm, operator) and waits
# for readiness. Adding a new app = adding a new deploy-<app> target here.

.PHONY: deploy-webapp
deploy-webapp:
	@echo "=== Deploying webapp (manifest) ==="
	kubectl apply -f example/webapp-manifest.yaml
	kubectl wait --for=condition=available --timeout=120s deployment/webapp-mywebapp -n webapp

.PHONY: deploy-redis
deploy-redis:
	@echo "=== Deploying redis (manifest) ==="
	kubectl apply -f example/redis/redis-vulnerable.yaml
	kubectl wait --for=condition=available --timeout=120s deployment/redis -n redis

.PHONY: deploy-mariadb
deploy-mariadb:
	@echo "=== Deploying mariadb (manifest, intentionally insecure) ==="
	kubectl apply -f example/mariadb-vulnerable.yaml
	kubectl wait --for=condition=available --timeout=180s deployment/mariadb -n mariadb
	kubectl wait --for=condition=available --timeout=120s deployment/mariadb-client -n mariadb
	@echo "=== Pods in mariadb ==="
	kubectl get pods -n mariadb

# deploy-misp and deploy-elk removed: misp + elk are archived to the inner repo
# under pkg/nonmigrated/ and are no longer part of the contrast-tuning matrix.

# Argo CD — FULL upstream install (all subcomponents) + vulnerable overlay.
# ARGOCD_VERSION pins the CVE-carrying release (see example/argocd-vulnerable.yaml).
ARGOCD_VERSION ?= v2.9.3
.PHONY: deploy-argocd
deploy-argocd:
	@echo "=== Deploying Argo CD $(ARGOCD_VERSION) (full install: all subcomponents) ==="
	kubectl create namespace argocd 2>/dev/null || true
	# Full install.yaml (NOT core-install): server + repo-server + app-controller
	# + applicationset + notifications + dex + redis. Pinned + CVE-carrying.
	kubectl apply -n argocd -f \
		https://raw.githubusercontent.com/argoproj/argo-cd/$(ARGOCD_VERSION)/manifests/install.yaml
	@echo "=== Vulnerable overlay (permissive AppProject + exec-render surface) ==="
	kubectl apply -f example/argocd-vulnerable.yaml
	@echo "=== Wait for all Argo CD subcomponents ==="
	-kubectl rollout status -n argocd deploy/argocd-server                    --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-repo-server               --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-applicationset-controller --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-notifications-controller  --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-dex-server                --timeout=300s
	-kubectl rollout status -n argocd deploy/argocd-redis                     --timeout=300s
	-kubectl rollout status -n argocd statefulset/argocd-application-controller --timeout=300s
	@echo "=== Argo CD subcomponents ==="
	kubectl get pods -n argocd

.PHONY: deploy-postgres
deploy-postgres:
	@echo "=== Deploying postgres (CloudNativePG) ==="
	helm repo add cnpg https://cloudnative-pg.github.io/charts 2>/dev/null || true
	helm upgrade --install cnpg cnpg/cloudnative-pg \
		-n cnpg-system --create-namespace --wait --timeout 5m
	@# pg-client Service is declared headless (clusterIP: None) in
	@# example/postgres/cluster.yaml. Pre-existing clusterIP-typed Services from
	@# earlier deploys cannot be mutated in-place (K8s spec.clusterIP is
	@# immutable once set), so delete it before apply.
	-kubectl delete svc pg-client -n postgres --ignore-not-found
	kubectl apply -f example/postgres/cluster.yaml
	@echo "Waiting for CNPG cluster to be ready..."
	@TIMEOUT=300; ELAPSED=0; \
	while [ $$ELAPSED -lt $$TIMEOUT ]; do \
		PHASE=$$(kubectl get cluster pg -n postgres -o jsonpath='{.status.phase}' 2>/dev/null || echo ""); \
		echo "  Cluster phase: $$PHASE ($$ELAPSED/$${TIMEOUT}s)"; \
		if [ "$$PHASE" = "Cluster in healthy state" ]; then break; fi; \
		sleep 10; ELAPSED=$$((ELAPSED + 10)); \
	done
	@echo "Waiting for pg-client pod..."
	-kubectl wait --for=condition=ready pod -l app=pg-client -n postgres --timeout=120s
	kubectl get pods -n postgres

.PHONY: build-postgres-vuln
build-postgres-vuln:
	@echo "=== Building postgres-vuln image ==="
	@DOCKER_HOST=$${DOCKER_HOST:-unix:///var/run/docker.sock}; export DOCKER_HOST; \
	docker build -t postgres-vuln:latest example/postgres-vuln/

.PHONY: deploy-postgres-vuln
deploy-postgres-vuln: build-postgres-vuln
	@echo "=== Deploying postgres-vuln (CVE-2019-9193 superuser misconfiguration) ==="
	@# Load image into cluster (Kind, k3d, or k3s). The portability job's
	@# differential cluster B is k3d — without a k3d branch the locally-built
	@# postgres-vuln:latest never reaches its containerd, so imagePullPolicy:
	@# IfNotPresent falls back to pulling docker.io/postgres-vuln (nonexistent)
	@# → ImagePullBackOff → the deployment wait times out.
	@DOCKER_CMD="docker"; [ -S /var/run/docker.sock ] && DOCKER_CMD="env DOCKER_HOST=unix:///var/run/docker.sock docker"; \
	if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -q .; then \
		echo "Loading image into Kind..."; \
		env DOCKER_HOST=unix:///var/run/docker.sock kind load docker-image postgres-vuln:latest --name $$(kind get clusters | head -1) 2>/dev/null \
		  || kind load docker-image postgres-vuln:latest --name $$(kind get clusters | head -1); \
	elif command -v k3d >/dev/null 2>&1 && k3d cluster list 2>/dev/null | tail -n +2 | grep -q .; then \
		CLU=$$(k3d cluster list 2>/dev/null | awk 'NR>1{print $$1; exit}'); \
		echo "Importing image into k3d cluster $$CLU..."; \
		k3d image import postgres-vuln:latest -c $$CLU; \
	elif command -v k3s >/dev/null 2>&1; then \
		echo "Importing image into k3s..."; \
		$$DOCKER_CMD save postgres-vuln:latest | sudo k3s ctr images import -; \
	fi
	kubectl apply -f example/postgres-vuln/cluster.yaml
	@# pg-vuln Deployment uses imagePullPolicy: IfNotPresent and pg-vuln-client
	@# is a raw Pod with restartPolicy: Never. Without an explicit rollout +
	@# pod recreation, repeated runs silently use the previously-loaded image
	@# (rabbit on PR 119, Makefile:170). Force fresh containers here.
	@echo "Forcing rollout of pg-vuln after image reload..."
	-kubectl rollout restart deployment/pg-vuln -n postgres-vuln 2>/dev/null
	@echo "Recreating pg-vuln-client (raw Pod won't pick up new image otherwise)..."
	-kubectl delete pod pg-vuln-client -n postgres-vuln --ignore-not-found --grace-period=0 --force 2>/dev/null
	kubectl apply -f example/postgres-vuln/cluster.yaml
	@echo "Waiting for pg-vuln deployment..."
	kubectl wait --for=condition=available deployment/pg-vuln -n postgres-vuln --timeout=180s
	@echo "Waiting for pg-vuln-client pod..."
	-kubectl wait --for=condition=ready pod -l app=pg-vuln-client -n postgres-vuln --timeout=120s
	@echo "Verifying postgres accepts connections..."
	@TIMEOUT=60; ELAPSED=0; READY=0; \
	while [ $$ELAPSED -lt $$TIMEOUT ]; do \
		if kubectl exec pg-vuln-client -n postgres-vuln -- pg_isready -h pg-vuln -U postgres 2>/dev/null; then READY=1; break; fi; \
		sleep 5; ELAPSED=$$((ELAPSED + 5)); \
	done; \
	if [ $$READY -eq 0 ]; then echo "ERROR: postgres-vuln did not become ready within $${TIMEOUT}s"; exit 1; fi
	kubectl get pods -n postgres-vuln

# ── Legacy targets (kept for backward compat) ───────────────────────────────

.PHONY: helm-install-no-bob
helm-install-no-bob: 
	@echo "Installing webapp without BoB configuration..."
	helm pull oci://ghcr.io/k8sstormcenter/mywebapp 
	helm upgrade --install webapp oci://ghcr.io/k8sstormcenter/mywebapp --version 0.1.0 --namespace webapp --create-namespace --set bob.create=false
	rm -rf mywebapp-0.1.0.tgz
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp

.PHONY: helm-install
helm-install: 
	@echo "Installing webapp with BoB configuration ..."
	helm upgrade --install webapp example/mywebapp-chart --namespace webapp --create-namespace --values example/mywebapp-chart/values.yaml --set bob.create=false
	-kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=mywebapp -n webapp


.PHONY: helm-redis
helm-redis: 
	@echo "Installing redis..."
	helm dependency update example/myredis-umbrella-chart/redis-bob/
	helm upgrade --install bob -n bob --create-namespace ./example/myredis-umbrella-chart/redis-bob --values ./example/myredis-umbrella-chart/redis-bob/values.yaml
	-kubectl wait --for=condition=ready pod -n bob -l app.kubernetes.io/instance=bob


.PHONY: helm-redis-compromise #TODO this is a bit whimsical , come up with something better
helm-redis-compromise: 	
	@echo "Installing a compromised redis with original bob"
	#kubectl delete -n bob applicationprofile statefulset-bob-redis-master-$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-')
	helm upgrade --install bob -n bob --create-namespace ./example/myredis-umbrella-chart/redis-bob --values ./example/myredis-umbrella-chart/redis-bob/values_compromised.yaml
	-kubectl wait --for=condition=ready pod -n bob -l app.kubernetes.io/instance=bob


.PHONY: helm-redis-test
helm-redis-test:
	-helm test bob -n bob

.PHONY: helm-test
helm-test:
	kubectl wait --for=condition=available --timeout=120s deployment/webapp-mywebapp -n webapp
	@echo "Deployment is ready. Running Helm tests..."
	helm test webapp -n webapp

.PHONY: helm-uninstall
helm-uninstall:
	helm uninstall webapp -n webapp

.PHONY: fwd
fwd:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	kubectl --namespace webapp port-forward $$(kubectl get pods --namespace webapp -l "app.kubernetes.io/name=mywebapp,app.kubernetes.io/instance=webapp" -o jsonpath="{.items[0].metadata.name}") 8080:80 &

.PHONY: fileopenattack
fileopenattack:
	kubectl exec -n webapp $(WEBAPP_POD) -- cat /etc/apache2/apache2.conf
	kubectl exec -n webapp $(WEBAPP_POD) -- touch /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- echo hi > /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- cat /tmp/pwned
	kubectl exec -n webapp $(WEBAPP_POD) -- rm /tmp/pwned




.PHONY: attack # this is only for the webapp
attack:
	curl 127.0.0.1:8080/ping.php?ip=1.1.1.1\;ls
	curl  127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/proc/self/mounts
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20index.html"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcurl%20github.com"
	curl "127.0.0.1:8080/ping.php?ip=1.1.1.1%3Bcat%20/run/secrets/kubernetes.io/serviceaccount/token"
	sleep 10

.PHONY: kubescape-orig
kubescape-orig:
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	-$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER)  -n honey --create-namespace --values kubescape/deprecated/values_orig.yaml
	-kubectl apply  -f kubescape/default-rules.yaml


# NOTE: node-agent is NEVER restarted by any target here. It must come up once,
# on its own, with the right config already in place — hence the post-renderer
# below instead of a patch-then-bounce. Do not reintroduce `rollout restart ds
# node-agent`. Also do NOT pass --set nodeAgent.privileged=true: the chart
# default is false and privileged node-agent has crashed this host.
#
#
KS_POST_RENDER ?=
KS_POST_RENDERER := ./kubescape/post-render.sh
KS_POST_RENDER_FLAGS := $(if $(KS_POST_RENDER)$(KS_RUNC_MNT),--post-renderer $(KS_POST_RENDERER))

# node-agent finds NEWLY STARTED containers by fanotify-marking the runc binary
# (Inspektor Gadget's WithContainerFanotifyEbpf). IG only knows the stock paths
# — /usr/bin/runc and /var/lib/rancher/k3s/data/current/bin/runc — so a cluster
# whose runc lives anywhere else is silently blind: node-agent still enumerates
# whatever was running when IT started (via the CRI socket) and looks perfectly
# healthy, while every container created afterwards gets no ContainerProfile.
#
# Detect the runc actually in use from the live containerd shim. If it is a stock
# path (CI runners, ordinary k3s) these stay EMPTY and nothing is overridden. Only
# a non-standard data-dir — e.g. this laptop's `k3s --data-dir /mnt/dev-data/k3s`
# — sets RUNTIME_PATH, and only then do we hostPath-mount the filesystem holding
# it, because node-agent's `host` volume is a NON-recursive bind of "/" and so
# does not carry a separate partition.
#
# The path is passed BARE (no /host prefix): runtimefinder.Notify only resolves
# symlinks chrooted to HOST_ROOT when the value does not already start with /host,
# and `data/current` is an absolute symlink.
# node-agent finds NEWLY STARTED containers by fanotify-marking the runc binary
# (Inspektor Gadget's WithContainerFanotifyEbpf). IG only knows the stock paths —
# /usr/bin/runc and /var/lib/rancher/k3s/data/current/bin/runc — so a cluster
# whose runc lives anywhere else is silently blind: node-agent still enumerates
# whatever was running when IT started and looks healthy, while every container
# created afterwards gets no ContainerProfile.
#
# This is OPT-IN and must stay that way. It was briefly auto-detected from local
# `ps`, which is wrong on its face: this flag configures node-agent, which runs
# on the CLUSTER NODES, while `ps` reads the machine you happen to type `make`
# on. Those are the same host only on a single-node local cluster. On a
# multi-node or remote cluster the detection reads an unrelated process table —
# and on a client machine with no shim at all it produced a malformed value that
# went straight to helm (see #172). Auto-detection also ran three subshells on
# EVERY make target, including ones with nothing to do with helm.
#
# Find the value on a NODE, not here:
#   ps -eo args | grep -oE '[^ ]*/bin/containerd-shim-runc-v2'
# then pass the runc beside it, plus the filesystem holding it if that is a
# separate mount (node-agent's `host` volume is a NON-recursive bind of "/", so
# it does not carry one):
#   make kubescape KS_RUNC=/mnt/dev-data/k3s/data/current/bin/runc KS_RUNC_MNT=/mnt/dev-data
KS_RUNC ?=
KS_RUNC_MNT ?=

# Refuse anything that is not an absolute path rather than passing it to helm.
# The $(shell) lives INSIDE the guard so the default path (KS_RUNC unset, which
# is CI and every contributor who is not on a bespoke runtime layout) spawns no
# subshell at all.
ifneq ($(KS_RUNC),)
KS_RUNC_OK := $(shell printf '%s' "$(KS_RUNC)" | grep -q '^/' && echo yes || echo no)
ifneq ($(KS_RUNC_OK),yes)
$(error KS_RUNC must be an absolute path on the cluster NODE, got "$(KS_RUNC)")
endif
endif

# Only the env var goes through helm; the filesystem mount that KS_RUNC_MNT
# implies is applied by $(KS_POST_RENDERER), which reads it from the
# environment — hence the export.
export KS_RUNC_MNT
KS_RUNC_FLAGS := $(if $(KS_RUNC),--set global.overrideRuntimePath=$(KS_RUNC))

#
KS_LEARN_PERIOD ?=

ifneq ($(KS_LEARN_PERIOD),)
KS_LEARN_OK := $(shell printf '%s' "$(KS_LEARN_PERIOD)" | grep -qE '^[0-9]+(s|m|h)$$' && echo yes || echo no)
ifneq ($(KS_LEARN_OK),yes)
$(error KS_LEARN_PERIOD must be a Go duration like 15m or 900s, got "$(KS_LEARN_PERIOD)")
endif
endif

KS_LEARN_FLAGS := $(if $(KS_LEARN_PERIOD),--set nodeAgent.config.maxLearningPeriod=$(KS_LEARN_PERIOD))

# One rule-coverage card per contrast SBoB, defined in kubescape/rule-coverage.yaml.
# Every rule in the ruleset is accounted for as verified / probe / excluded / gap,
# so a rule that cannot fire on an app is never confused with one nobody covered.
#   make rule-coverage-gifs              # all apps
#   make rule-coverage-gifs APP=argocd   # one app
.PHONY: rule-coverage-gifs
rule-coverage-gifs:
	python3 scripts/render-rule-coverage-gif.py \
	  --config kubescape/rule-coverage.yaml \
	  --ruleset kubescape/default-rules.yaml \
	  $(if $(APP),$(foreach a,$(APP),--app $(a)),)

.PHONY: show-runc
show-runc:
	@echo "KS_RUNC:          $(if $(KS_RUNC),$(KS_RUNC),(unset - using IG's stock paths))"
	@echo "KS_RUNC_MNT:      $(if $(KS_RUNC_MNT),$(KS_RUNC_MNT),(unset - no extra hostPath mount))"
	@echo "KS_LEARN_PERIOD:  $(if $(KS_LEARN_PERIOD),$(KS_LEARN_PERIOD),(unset - chart default 2m))"
	@echo "extra helm flags: $(if $(KS_RUNC_FLAGS)$(KS_LEARN_FLAGS),$(KS_RUNC_FLAGS) $(KS_LEARN_FLAGS),(none))"

.PHONY: kubescape
# helm 4 applies server-side and refuses fields owned by the kubectl applies
# below (default-rules / rule-binding); --force-conflicts overrides that.
# --server-side=true is pinned with it because "auto" (the default) inherits
# client-side from a release previously upgraded by helm 3, and helm 4 rejects
# --force-conflicts without server-side apply. helm 3 has neither flag.
KS_HELM_V4_FLAGS := $(shell $(HELM) version --short 2>/dev/null | grep -q "^v4" && echo "--server-side=true --force-conflicts")

kubescape:
	$(HELM) upgrade --install kubescape https://github.com/k8sstormcenter/helm-charts/releases/download/kubescape-operator-$(KUBESCAPE_CHART_VER)/kubescape-operator-$(KUBESCAPE_CHART_VER).tgz -n honey --create-namespace --values kubescape/values.yaml $(KS_HELM_V4_FLAGS) $(KS_RUNC_FLAGS) $(KS_LEARN_FLAGS) $(KS_POST_RENDER_FLAGS)
	kubectl apply -f kubescape/default-rules.yaml
	kubectl apply -f kubescape/default-rule-binding.yaml

# Same install, but the trust policy comes from a ConfigMap YOU own instead of
# being inlined in values.yaml. The chart mounts it and renders none, so the
# policy can be rotated (kubectl apply on the ConfigMap) without a helm upgrade
# and without pasting the signed artifact into values.
SIGNED_BUNDLES_DIR ?= example/redis/distros/signed-bundles
KUBESCAPE_TRUST_CM ?= kubescape-trust-bundle

trust-bundle:
	kubectl create namespace honey --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n honey create configmap $(KUBESCAPE_TRUST_CM) \
	  --from-file=trust-policy.json=$(SIGNED_BUNDLES_DIR)/trust-policy.signed.json \
	  --dry-run=client -o yaml | kubectl apply -f -

kubescape-mounted: trust-bundle
	$(HELM) upgrade --install kubescape https://github.com/k8sstormcenter/helm-charts/releases/download/kubescape-operator-$(KUBESCAPE_CHART_VER)/kubescape-operator-$(KUBESCAPE_CHART_VER).tgz -n honey --create-namespace --values kubescape/values.yaml --set nodeAgent.bundleSigning.existingConfigMap=$(KUBESCAPE_TRUST_CM) $(KS_HELM_V4_FLAGS) $(KS_RUNC_FLAGS) $(KS_LEARN_FLAGS) $(KS_POST_RENDER_FLAGS)
	kubectl apply -f kubescape/default-rules.yaml
	kubectl apply -f kubescape/default-rule-binding.yaml

# Wait for node-agent to become Ready by itself. This is a WAIT, never a
# restart: node-agent binds user-supplied profiles and starts its learning
# window at pod start, so bouncing it throws that away.
.PHONY: wait-node-agent
wait-node-agent:
	@echo "Waiting for node-agent DaemonSet to become ready (no restart)..."
	kubectl rollout status -n honey ds node-agent --timeout=300s
	@echo "=== node-agent pods ==="
	kubectl get pods -n honey -l app.kubernetes.io/component=node-agent -o wide

.PHONY: alertmanager
alertmanager:
	@echo "Deploying alertmanager in honey namespace..."
	kubectl create namespace honey --dry-run=client -o yaml | kubectl apply -f -
	kubectl apply -n honey -f kubescape/alertmanager.yaml
	kubectl wait --for=condition=ready pod -l app=alertmanager -n honey --timeout=120s
	@echo "Alertmanager ready. Forward with: kubectl -n honey port-forward svc/alertmanager 9093:9093"

.PHONY: fwd-autotune
fwd-autotune:
	-sudo kill -9 $$(sudo lsof -t -i :8081) 2>/dev/null
	-sudo kill -9 $$(sudo lsof -t -i :9093) 2>/dev/null
	kubectl --namespace webapp port-forward svc/webapp-mywebapp 8081:80 &
	kubectl -n honey port-forward svc/alertmanager 9093:9093 &
	@sleep 2
	@echo "Port-forwards active: webapp=localhost:8081 alertmanager=localhost:9093"

.PHONY: kubescape-vendor
kubescape-vendor: 
	-$(HELM) repo add kubescape https://kubescape.github.io/helm-charts/
	-$(HELM) repo update
	$(HELM) upgrade --install kubescape kubescape/kubescape-operator --version $(KUBESCAPE_CHART_VER) -n honey --create-namespace --values kubescape/deprecated/values_vendor.yaml $(KS_RUNC_FLAGS) $(KS_LEARN_FLAGS) $(KS_POST_RENDER_FLAGS)
	-kubectl apply  -f kubescape/runtimerules.yaml
	-kubectl rollout status -n honey deploy/kubevuln --timeout=120s
	$(MAKE) wait-node-agent



.PHONY: wipe
wipe:
	-sudo kill -9 $$(sudo lsof -t -i :8080)
	-$(HELM) uninstall -n honey kubescape
	-$(HELM) uninstall -n webapp webapp
	-$(HELM) uninstall -n bob bob
	-kubectl delete namespace bob 
	-$(HELM) uninstall webapp -n webapp

.PHONY: helm
helm: ## Download helm if required
	curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \
		&& chmod +x get_helm.sh &&./get_helm.sh
HELM = $(shell which helm)


.PHONY: sample-app
sample-app:
	$(MAKE) --makefile=example/myharbor/Makefile install-helm install-harbor
	@kubectl wait --for=condition=ready pod -l app=harbor -n harbor --timeout=600s

.PHONY: nothing
nothing:
# for when we know the hash upfront:
#helm upgrade --install bob -n bob --create-namespace --set bob.create=true ./myredis-umbrella-chart/redis-bob
	#helm upgrade --install bob -n bob --create-namespace ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values.yaml
	#kubectl annotate applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob meta.helm.sh/release-name- 
	#kubectl annotate applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob meta.helm.sh/release-namespace-
	#kubectl annotate --overwrite applicationprofile statefulset-bob-redis-master-668c4559b4  -n bob kubescape.io/status='completed'
    #helm repo update 
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=false --set bob.ignore=true ./myredis-umbrella-chart/redis-bob
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=true --set bob.ignore=false --set bob.templateHash=$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-') ./myredis-umbrella-chart/redis-bob
	#helm dependency update myredis-umbrella-chart/redis-bob/
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=false --set bob.ignore=true ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values_compromised.yaml
	#helm upgrade --install bob -n bob --create-namespace --set bob.create=true --set bob.ignore=false  --set bob.templateHash=$$(kubectl get statefulset -n bob -o jsonpath='{.items[0].status.currentRevision}'|cut -f4 -d '-')  ./myredis-umbrella-chart/redis-bob --values ./myredis-umbrella-chart/redis-bob/values_compromised.yaml
